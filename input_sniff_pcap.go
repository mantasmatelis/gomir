package main

import (
	//"errors"
	"fmt"
	"github.com/miekg/pcap"
	"io"
	"os"
)

const (
	INPUT_SNIFF_PCAP_SNAPLEN     = (1 << 16) - 1
	INPUT_SNIFF_PCAP_PROMISCUOUS = true
	INPUT_SNIFF_PCAP_TIMEOUT_MS  = 200
)

type Connection struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
}

type InputSniffPcap struct {
	Input
	handlers map[Connection]chan *pcap.Packet
}

func (i *InputSniffPcap) Run(device string, ip string, port string) {
	i.handlers = make(map[Connection]chan *pcap.Packet)
	h, err := pcap.OpenLive(device, INPUT_SNIFF_PCAP_SNAPLEN, INPUT_SNIFF_PCAP_PROMISCUOUS, INPUT_SNIFF_PCAP_TIMEOUT_MS)
	defer h.Close()

	err = h.SetFilter(i.filterString(ip, port))
	if err != nil {
		fmt.Printf("InputSniffPcap: SetFilter failed: %s.\n", err.Error())
		os.Exit(3)
	}

	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r == 0 {
			//fmt.Printf("InputSniffPcap: No packets received in %dms.\n", INPUT_SNIFF_PCAP_TIMEOUT_MS)
			continue
		}
		pkt.Decode()
		err = i.processPacket(pkt)
		if err != nil {
			fmt.Printf("InputSniffPcap: Failed to decode packet: %s.\n", err)
		} else {
			//fmt.Printf("Decoded packet\n!")
		}
	}

}

func (i *InputSniffPcap) processPacket(pkt *pcap.Packet) error {
	conn := Connection{}

	if len(pkt.Headers) != 2 {
		return nil
	}

	//fmt.Printf(pkt.String())

	ipv6 := false
	ipv4Hdr, ok := pkt.Headers[0].(*pcap.Iphdr)

	var ipv6Hdr *pcap.Ip6hdr
	if !ok {
		ipv6 = true
		ipv6Hdr, ok = pkt.Headers[0].(*pcap.Ip6hdr)
		if !ok {
			return nil
			//return errors.New("Not an IP packet")
		}
	}
	if !ipv6 {
		copy(conn.srcAddr[:], ipv4Hdr.SrcIp)
		copy(conn.dstAddr[:], ipv4Hdr.DestIp)
	} else {
		copy(conn.srcAddr[:], ipv6Hdr.SrcIp)
		copy(conn.dstAddr[:], ipv6Hdr.DestIp)
	}
	tcpHdr, ok := pkt.Headers[1].(*pcap.Tcphdr)
	if !ok {
		return nil
		//return errors.New("Not a TCP packet")
	}
	conn.srcPort = tcpHdr.SrcPort
	conn.dstPort = tcpHdr.DestPort

	_, exists := i.handlers[conn]

	if !exists {
		i.handlers[conn] = make(chan *pcap.Packet)
		go i.handleConnection(conn)
	}
	i.handlers[conn] <- pkt
	return nil
}

func (i *InputSniffPcap) handleConnection(conn Connection) {
	//fmt.Println("Handling connection\n")
	//TODO: assume dead after 120 seconds, who waits that long to send half a request?
	var pkt *pcap.Packet
	var data []*pcap.Packet
	last_buffered_position := -1

	reader, writer := io.Pipe()
	go i.handleReader(reader)

	for {
		pkt = <-i.handlers[conn]
		data = append(data, pkt)
		for j := len(data) - 1; j > 0; j-- {
			if data[j].Headers[1].(*pcap.Tcphdr).Seq < data[j-1].Headers[1].(*pcap.Tcphdr).Seq {
				fmt.Println("Doing reordering\n")
				data[j], data[j-1] = data[j-1], data[j]
			} else {
				break
			}
		}

		for last_buffered_position == -1 || (len(data) > last_buffered_position+1 && data[last_buffered_position].Headers[1].(*pcap.Tcphdr).Seq+1 == data[last_buffered_position+1].Headers[1].(*pcap.Tcphdr).Seq) {
			_, err := writer.Write(data[last_buffered_position+1].Payload)
			if err != nil {
				fmt.Printf("InputSniffPcap: Error writing to pipe: %s.\n", err.Error())
				i.handlers[conn] = nil
				return
			}
			last_buffered_position += 1
		}
	}
}

func (i *InputSniffPcap) filterString(ip string, port string) string {
	filter := ""
	if port != "" {
		filter += "tcp port " + port
	}
	if port != "" && ip != "" {
		filter += " and "
	}
	if ip != "" {
		filter += "dst host " + ip
	}
	fmt.Printf("InputSniffPcap: Filter String: %s\n", filter)
	return filter
}
