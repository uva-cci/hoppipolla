package main

import (
	"context"
	"log"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

var results []snet.Path

var scionDaemon *daemon.Service
var scionDaemonConn daemon.Connector

func main() {
	setup()
	clean()
	execute()
	clean()
	log.Println(results)
}

func execute() {
	src, err := scionDaemonConn.LocalIA(context.TODO())
	if err != nil {
		log.Fatalln(err)
	}

	dst, err := addr.ParseIA("16-ffaa:0:1002")
	if err != nil {
		log.Fatalln(err)
	}

	results, err = scionDaemonConn.Paths(context.TODO(), dst, src,
		daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatalln(err)
	}
}

func setup() {
	scionDaemon = &daemon.Service{Address: "127.0.0.1:30255"}
	conn, err := scionDaemon.Connect(context.TODO())
	if err != nil {
		log.Fatalln(err)
	}
	scionDaemonConn = conn
}

func clean() {
	if err := scionDaemonConn.Close(); err != nil {
		log.Println("ERROR: failed to close daemon connection:", err)
	}
}
