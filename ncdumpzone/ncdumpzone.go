package main

import "gopkg.in/alecthomas/kingpin.v2"
import "github.com/namecoin/ncdns/ncdomain"
import "github.com/namecoin/ncdns/namecoin"
import "github.com/namecoin/ncdns/util"
import "github.com/hlandau/xlog"
import "strings"
import "fmt"

var log, Log = xlog.New("ncdumpzone")

var (
	rpchostFlag = kingpin.Flag("rpchost", "Namecoin RPC host:port").Default("127.0.0.1:8336").String()
	rpcuserFlag = kingpin.Flag("rpcuser", "Namecoin RPC username").String()
	rpcpassFlag = kingpin.Flag("rpcpass", "Namecoin RPC password").String()
)

var conn namecoin.Conn

const perCall = 1000

func main() {
	kingpin.Parse()

	conn.Server = *rpchostFlag
	conn.Username = *rpcuserFlag
	conn.Password = *rpcpassFlag

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
				fmt.Print(rr.String(), "\n")
			}
		}

		currentName = results[len(results)-1].Name
	}
}
