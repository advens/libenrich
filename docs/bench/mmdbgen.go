// mmdbgen <ip_nets.txt> <out.mmdb>: every network maps to {"c": 80}.
//
// Copyright 2026 Advens.
// Licensed under the Apache License, Version 2.0. See LICENSE.
package main

import (
	"bufio"
	"log"
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func main() {
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "bench",
		IPVersion:               4,
		RecordSize:              28,
		IncludeReservedNetworks: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	v := mmdbtype.Map{"c": mmdbtype.Uint32(80)}
	s := bufio.NewScanner(f)
	n := 0
	for s.Scan() {
		_, nw, err := net.ParseCIDR(s.Text())
		if err != nil {
			log.Fatal(err)
		}
		if err := w.Insert(nw, v); err != nil {
			log.Fatal(err)
		}
		n++
	}
	out, err := os.Create(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := w.WriteTo(out); err != nil {
		log.Fatal(err)
	}
	log.Printf("mmdb: %d networks", n)
}
