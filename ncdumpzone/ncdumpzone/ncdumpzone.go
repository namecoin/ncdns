package main

import (
	"os"

	"github.com/hlandau/xlog"
	"github.com/namecoin/btcd/rpcclient"
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
	rpccookiepathFlag = cflag.String(flagGroup, "namecoinrpccookiepath", "",
		"Namecoin RPC cookie path (used if password is unspecified)")
	formatFlag = cflag.String(flagGroup, "format", "zonefile", "Output "+
		"format.  \"zonefile\" = DNS zone file.  "+
		"\"firefox-override\" = Firefox cert_override.txt format.  "+
		"\"url-list\" = URL list.")
)

var conn *namecoin.Client

var config = easyconfig.Configurator{
	ProgramName: "ncdumpzone",
}

func main() {
	err := config.Parse(nil)
	if err != nil {
		log.Fatalf("Couldn't parse configuration: %s", err)
	}

	// Connect to local namecoin core RPC server using HTTP POST mode.
	connCfg := &rpcclient.ConnConfig{
		Host:         rpchostFlag.Value(),
		User:         rpcuserFlag.Value(),
		Pass:         rpcpassFlag.Value(),
		CookiePath:   rpccookiepathFlag.Value(),
		HTTPPostMode: true, // Namecoin core only supports HTTP POST mode
		DisableTLS:   true, // Namecoin core does not provide TLS by default
	}

	// Notice the notification parameter is nil since notifications are
	// not supported in HTTP POST mode.
	conn, err = namecoin.New(connCfg, nil)
	if err != nil {
		log.Fatalf("Couldn't create RPC client: %s", err)
	}
	defer conn.Shutdown()

	err = ncdumpzone.Dump(conn, os.Stdout, formatFlag.Value())
	if err != nil {
		log.Fatalf("Couldn't dump zone: %s", err)
	}
}
