package main

import (
	//"github.com/miekg/pcap"
	"bufio"
	"fmt"
	"io"
	"net/http"
)

type Request struct {
	//Data     []byte
	Req      *http.Request
	JsonBody interface{}
}

type Put struct {
	Filters [][]*Filter
}

func (p *Put) AddFilterGroup(filters []*Filter) {
	p.Filters = append(p.Filters, filters)
}

func (p *Put) passesFilters(req *Request) bool {
	for _, fl := range p.Filters {
		passes := true
		for _, f := range fl {
			if !(*f).Passes(req) {
				passes = false
				break
			}
		}
		if passes {
			return true
		}
	}
	return false
}

type Input struct {
	Put
	Outputs []OutputInterface
}

type InputInterface interface {
	AddFilterGroup([]*Filter)
	AddOutput(OutputInterface)
	Run()
}

type OutputHandler func(*Request) error

type Output struct {
	Put
	c       chan *Request
	Handler OutputHandler
}

type OutputInterface interface {
	AddFilterGroup([]*Filter)
	HandleRequest(*Request)
}

func (i *Input) handleReader(ioReader io.Reader) {
	reader := bufio.NewReader(ioReader)
	for {
		if _, err := reader.Peek(1); err == io.EOF {
			return
		}
		req, err := http.ReadRequest(reader)
		if err != nil {
			fmt.Printf("Listener: Could not parse request: %s.\n", err.Error())
			return
		}
		i.handleRequest(&Request{Req: req})
	}
}

func (i *Input) handleRequest(req *Request) {
	fmt.Println("Sending request")
	if !i.passesFilters(req) {
		return
	}
	for _, o := range i.Outputs {
		o.HandleRequest(req)
	}
}

func (o *Output) HandleRequest(req *Request) {
	o.c <- req
}

func (o *Output) Run() {
	for i := 0; i < 10; i++ {
		go o.worker()
	}
}

func (o *Output) worker() {
	for {
		req := <-o.c
		if !o.passesFilters(req) {
			return
		}
		err := o.Handler(req)

		fmt.Printf("Output handler returned error: %s\n", err.Error())
	}
}
