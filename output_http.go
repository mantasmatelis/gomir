package main

import (
	//"net/http"
	"fmt"
)

type OutputHttp struct {
	Output
}

func (o *OutputHttp) Run() {
	o.Handler = o.Handle
}

func (o *OutputHttp) Handle(req *Request) error {
	fmt.Println("Handle request")
	return nil
}
