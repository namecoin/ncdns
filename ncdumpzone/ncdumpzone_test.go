package ncdumpzone

import (
	"io"
	"testing"

	"github.com/btcsuite/btcd/rpcclient"

	"github.com/namecoin/ncdns/namecoin"
)

func BenchmarkDumpZone(b *testing.B) {
	// Connect to local namecoin core RPC server using HTTP POST mode.
	connCfg := &rpcclient.ConnConfig{
		Host:         "127.0.0.1:8336",
		User:         "",
		Pass:         "",
		CookiePath:   "./namecoin.cookie",
		HTTPPostMode: true, // Namecoin core only supports HTTP POST mode
		DisableTLS:   true, // Namecoin core does not provide TLS by default
	}

	// Notice the notification parameter is nil since notifications are
	// not supported in HTTP POST mode.
	conn, err := namecoin.New(connCfg, nil)
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
