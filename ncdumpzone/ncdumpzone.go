package ncdumpzone

import (
	"fmt"
	"io"
	"strings"

	"github.com/hlandau/xlog"
	"github.com/miekg/dns"

	extratypes "github.com/hlandau/ncbtcjsontypes"
	"github.com/namecoin/ncdns/namecoin"
	"github.com/namecoin/ncdns/ncdomain"
	"github.com/namecoin/ncdns/tlsoverridefirefox"
	"github.com/namecoin/ncdns/util"
)

var log, Log = xlog.New("ncdumpzone")

const perCall = 1000

func dumpRR(rr dns.RR, dest io.Writer, format string) error {
	switch format {
	case "zonefile":
		fmt.Fprint(dest, rr.String(), "\n")
	case "firefox-override":
		result, err := tlsoverridefirefox.OverrideFromRR(rr)
		if err != nil {
			return err
		}
		fmt.Fprint(dest, result)
	}

	return nil
}

func dumpName(item *extratypes.NameFilterItem, conn namecoin.Conn,
	dest io.Writer, format string) error {
	// The order in which name_scan returns results is seemingly rather
	// random, so we can't stop when we see a non-d/ name, so just skip it.
	if !strings.HasPrefix(item.Name, "d/") {
		return nil
	}

	suffix, err := util.NamecoinKeyToBasename(item.Name)
	if err != nil {
		return nil
	}

	getNameFunc := func(k string) (string, error) {
		return conn.Query(k)
	}

	var errors []error
	errFunc := func(err error, isWarning bool) {
		errors = append(errors, err)
	}

	value := ncdomain.ParseValue(item.Name, item.Value, getNameFunc, errFunc)
	if len(errors) > 0 {
		return nil
	}

	rrs, err := value.RRsRecursive(nil, suffix+".bit.", "bit.")
	log.Warne(err, "error generating RRs")

	for _, rr := range rrs {
		err = dumpRR(rr, dest, format)
		if err != nil {
			return err
		}
	}

	return nil
}

// Dump extracts all domain names from conn, formats them according to the
// specified format, and writes the result to dest.
func Dump(conn namecoin.Conn, dest io.Writer, format string) error {
	if format != "zonefile" && format != "firefox-override" {
		return fmt.Errorf("Invalid \"format\" argument: %s", format)
	}

	currentName := "d/"
	continuing := 0

	for {
		results, err := conn.Scan(currentName, perCall)
		if err != nil {
			return fmt.Errorf("scan: %s", err)
		}

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

			err = dumpName(r, conn, dest, format)
			if err != nil {
				return err
			}
		}

		currentName = results[len(results)-1].Name
	}

	return nil
}
