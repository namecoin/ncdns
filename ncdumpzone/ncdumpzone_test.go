package ncdumpzone

import (
	"io"
	"testing"

	ncrpcclient "github.com/namecoin/minincrpcclient"

	"github.com/namecoin/ncdns/namecoin"
)

func BenchmarkDumpZone(b *testing.B) {
	// Connect to local namecoin core RPC server using HTTP POST mode.
	connCfg := &ncrpcclient.ConnConfig{
		Host:         "127.0.0.1:8336",
		User:         "",
		Pass:         "",
		CookiePath:   "./namecoin.cookie",
	}

	// Notice the notification parameter is nil since notifications are
	// not supported in HTTP POST mode.
	conn, err := namecoin.New(connCfg)
	if err != nil {
		panic(err)
	}

	for b.Loop() {
		err = Dump(conn, io.Discard, "zonefile")
		if err != nil {
			panic(err)
		}
	}
}
