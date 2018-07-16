package main

import (
	"os"

	"github.com/hlandau/xlog"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/easyconfig.v1/cflag"

	"github.com/namecoin/ncdns/namecoin"
	"github.com/namecoin/ncdns/ncdumpzone"
)

var log, _ = xlog.New("ncdumpzone-main")

var (
	flagGroup   = cflag.NewGroup(nil, "ncdumpzone")
	rpchostFlag = cflag.String(flagGroup, "namecoinrpcaddress",
		"127.0.0.1:8336", "Namecoin RPC host:port")
	rpcuserFlag = cflag.String(flagGroup, "namecoinrpcusername", "",
		"Namecoin RPC username")
	rpcpassFlag = cflag.String(flagGroup, "namecoinrpcpassword", "",
		"Namecoin RPC password")
	formatFlag = cflag.String(flagGroup, "format", "zonefile", "Output "+
		"format.  \"zonefile\" = DNS zone file.  "+
		"\"firefox-override\" = Firefox cert_override.txt format.")
)

var conn namecoin.Conn

var config = easyconfig.Configurator{
	ProgramName: "ncdumpzone",
}

func main() {
	err := config.Parse(nil)
	if err != nil {
		log.Fatalf("Couldn't parse configuration: %s", err)
	}

	conn.Server = rpchostFlag.Value()
	conn.Username = rpcuserFlag.Value()
	conn.Password = rpcpassFlag.Value()

	err = ncdumpzone.Dump(conn, os.Stdout, formatFlag.Value())
	if err != nil {
		log.Fatalf("Couldn't dump zone: %s", err)
	}
}
