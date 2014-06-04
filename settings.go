package main

import (
	"flag"
	"fmt"
	"github.com/miekg/pcap"
)

type MultiOption []string

func (o *MultiOption) Set(val string) error {
	*o = append(*o, val)
	return nil
}

func (o *MultiOption) String() string {
	return fmt.Sprintf("%s", []string(*o))
}

type Settings struct {
	help bool

	inputSniffPcap MultiOption
	outputHttp     MultiOption

	filterGroup MultiOption

	filterMethod        MultiOption
	filterHostRegex     MultiOption
	filterPathRegex     MultiOption
	filterHeaderRegex   MultiOption
	filterBodyRegex     MultiOption
	filterBodyJsonRegex MultiOption
	filterHeaderHash    MultiOption
	filterBodyHash      MultiOption
	filterBodyJsonHash  MultiOption
	filterLimit         MultiOption
}

var settings Settings

func settingsUsage() {
	fmt.Printf("Gomir mirrors requests to other servers, and discards the response, " +
		"filtering requests on headers, body parameters, JSON body, or frequency. " +
		"In addition, it can filter by the hash of a header, body paramater, " +
		"or JSON body parameter. This means that it can take requests from a " +
		"consistant percentage of users. A common use case is to send requests " +
		"from production to a testing server, making sure that requests " +
		"don't break on changed codebases.\n")

	ifs, err := pcap.FindAllDevs()

	if err != "" {
		fmt.Printf("\nCould not enumerate devices: %s.\n", err)
		fmt.Println("It is likely that sniffing through pcap will not work.")
	} else {
		fmt.Printf("\nNetworks:\n")
		for _, dev := range ifs {
			fmt.Printf("  %s: ", dev.Name)
			for i, addr := range dev.Addresses {
				fmt.Print(addr.IP)
				if i+1 != len(dev.Addresses) {
					fmt.Print(", ")
				}

			}
			fmt.Print("\n")
		}
	}
	fmt.Print("\n")
	fmt.Print("Options:\n")
	flag.PrintDefaults()
}

func settingsInit() {
	flag.Usage = settingsUsage

	flag.BoolVar(&settings.help, "help", false, "Displays this help information.")

	flag.Var(&settings.inputSniffPcap, "input-sniff-pcap", "") //    eth0/127.0.0.1/80, eth0/80, eth0/127:80:30:30/80

	flag.Var(&settings.outputHttp, "output-http", "")

	flag.Var(&settings.filterGroup, "filter-group", "")

	flag.Var(&settings.filterMethod, "filter-method", "")
	flag.Var(&settings.filterHostRegex, "filter-host-regex", "")
	flag.Var(&settings.filterPathRegex, "filter-path-regex", "")
	flag.Var(&settings.filterHeaderRegex, "filter-header-regex", "")
	flag.Var(&settings.filterBodyRegex, "filter-body-regex", "")
	flag.Var(&settings.filterBodyJsonRegex, "filter-body-json-regex", "")
	flag.Var(&settings.filterHeaderHash, "filter-header-hash", "")
	flag.Var(&settings.filterBodyHash, "filter-body-hash", "")
	flag.Var(&settings.filterBodyJsonHash, "filter-body-json-hash", "")
	flag.Var(&settings.filterLimit, "filter-hertz", "")

	flag.Parse()
}
