package rrtourl

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/namecoin/ncdns/util"
)

// URLsFromRR returns a list of URL's derived from rr, which is suitable for
// passing to a search engine crawler like YaCy.  If no such list can be
// derived, returns an empty string.
func URLsFromRR(rr dns.RR) (string, error) {
	header := rr.Header()
	if header == nil {
		return "", fmt.Errorf("Nil RR header")
	}

	hostFQDN := header.Name

	// Remove things like "_443._tcp" in TLSA records
	for strings.HasPrefix(hostFQDN, "_") {
		_, hostFQDN = util.SplitDomainTail(hostFQDN)
	}

	// Remove the trailing period from FQDN's
	host := strings.TrimSuffix(hostFQDN, ".")

	// Remove wildcard subdomains (later we assume that they might be "www.")
	host = strings.TrimPrefix(host, "*.")

	return "http://" + host + "/" + "\n" +
		"http://www." + host + "/" + "\n" +
		"https://" + host + "/" + "\n" +
		"https://www." + host + "/" + "\n" +
		"ftp://" + host + "/" + "\n" +
		"ftp://www." + host + "/" + "\n" +
		"ftps://" + host + "/" + "\n" +
		"ftps://www." + host + "/" + "\n", nil
}
