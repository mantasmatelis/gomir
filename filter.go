package main

import ()

type Filter interface {
	Passes(req *Request) bool
}

type RegexFilter struct {
}

type HashFilter struct {
}

type RateFilter struct {
}
