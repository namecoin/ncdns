package ncdumpzone

import (
	"fmt"
	"io"
	"strings"

	"github.com/hlandau/xlog"
	"github.com/miekg/dns"

	"github.com/namecoin/ncbtcjson"
	"github.com/namecoin/ncdns/namecoin"
	"github.com/namecoin/ncdns/ncdomain"
	"github.com/namecoin/ncdns/rrtourl"
	"github.com/namecoin/ncdns/tlsoverridefirefox"
	"github.com/namecoin/ncdns/util"
)

var log, Log = xlog.New("ncdumpzone")

const defaultPerCall uint32 = 1000

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
	case "url-list":
		result, err := rrtourl.URLsFromRR(rr)
		if err != nil {
			return err
		}
		fmt.Fprint(dest, result)
	}

	return nil
}

func dumpName(item *ncbtcjson.NameShowResult, conn *namecoin.Client,
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
		return conn.NameQuery(k, "")
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
func Dump(conn *namecoin.Client, dest io.Writer, format string) error {
	if format != "zonefile" && format != "firefox-override" &&
		format != "url-list" {
		return fmt.Errorf("Invalid \"format\" argument: %s", format)
	}

	currentName := "d/"
	continuing := 0
	perCall := defaultPerCall

	for {
		results, err := conn.NameScan(currentName, perCall)
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

		// Temporary hack to fix
		// https://github.com/namecoin/ncdns/issues/105
		// TODO: Replace this hack with hex encoding after Namecoin
		// Core 0.18.0+ is ubiquitous.
		lenResults := len(results)
		for results[len(results)-1].NameError != "" {
			results = results[:len(results)-1]

			if len(results) == 0 {
				break
			}
		}
		// Edge case: if all of the results had a NameError,
		// then try to get more results at once.
		if len(results) == 0 {
			// All of the results had a nameError but we're
			// at the end of the results, so not a problem.
			if lenResults < int(perCall)-1 {
				log.Info("out of results, stopping")
				break
			}

			log.Warnf("All %d results (start point %s) had a NameError", lenResults, currentName)
			perCall *= 2
			continue
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
