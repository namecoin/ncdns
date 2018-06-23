package main

import "github.com/namecoin/ncdns/ncdomain"
import "github.com/namecoin/ncdns/namecoin"
import "github.com/namecoin/ncdns/tlsoverridefirefox"
import "github.com/namecoin/ncdns/util"
import "github.com/hlandau/xlog"
import "strings"
import "fmt"

import "gopkg.in/hlandau/easyconfig.v1"
import "gopkg.in/hlandau/easyconfig.v1/cflag"

var log, Log = xlog.New("ncdumpzone")

var (
	flagGroup   = cflag.NewGroup(nil, "ncdumpzone")
	rpchostFlag = cflag.String(flagGroup, "namecoinrpcaddress", "127.0.0.1:8336", "Namecoin RPC host:port")
	rpcuserFlag = cflag.String(flagGroup, "namecoinrpcusername", "", "Namecoin RPC username")
	rpcpassFlag = cflag.String(flagGroup, "namecoinrpcpassword", "", "Namecoin RPC password")
	formatFlag  = cflag.String(flagGroup, "format", "zonefile", "Output format.  \"zonefile\" = "+
		"DNS zone file.  \"firefox-override\" = Firefox "+
		"cert_override.txt format.")
)

var conn namecoin.Conn

var config = easyconfig.Configurator{
	ProgramName: "ncdumpzone",
}

const perCall = 1000

func main() {
	err := config.Parse(nil)
	if err != nil {
		log.Fatalf("Couldn't parse configuration: %s", err)
	}

	conn.Server = rpchostFlag.Value()
	conn.Username = rpcuserFlag.Value()
	conn.Password = rpcpassFlag.Value()

	if formatFlag.Value() != "zonefile" && formatFlag.Value() != "firefox-override" {
		log.Fatalf("Invalid \"format\" argument: %s", formatFlag.Value())
	}

	var errors []error
	errFunc := func(err error, isWarning bool) {
		errors = append(errors, err)
	}

	getNameFunc := func(k string) (string, error) {
		return conn.Query(k)
	}

	currentName := "d/"
	continuing := 0

	for {
		results, err := conn.Scan(currentName, perCall)
		log.Fatale(err, "scan")

		if len(results) <= continuing {
			log.Info("out of results, stopping")
			break
		}

		// scan is [x,y] not (x,y], so exclude the first result
		if continuing != 0 {
			results = results[1:]
		} else {
			continuing = 1
		}

		for i := range results {
			r := &results[i]

			// The order in which name_scan returns results is seemingly rather
			// random, so we can't stop when we see a non-d/ name, so just skip it.
			if !strings.HasPrefix(r.Name, "d/") {
				continue
			}

			suffix, err := util.NamecoinKeyToBasename(r.Name)
			if err != nil {
				continue
			}

			errors = errors[0:0]
			value := ncdomain.ParseValue(r.Name, r.Value, getNameFunc, errFunc)
			if len(errors) > 0 {
				continue
			}

			rrs, err := value.RRsRecursive(nil, suffix+".bit.", "bit.")
			log.Warne(err, "error generating RRs")

			for _, rr := range rrs {
				if formatFlag.Value() == "zonefile" {
					fmt.Print(rr.String(), "\n")
				} else if formatFlag.Value() == "firefox-override" {
					result, err := tlsoverridefirefox.OverrideFromRR(rr)
					if err != nil {
						panic(err)
					}
					fmt.Print(result)
				}
			}
		}

		currentName = results[len(results)-1].Name
	}
}
