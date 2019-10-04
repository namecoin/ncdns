// +build !no_namecoin_tls

package ncdomain

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/namecoin/ncdns/certdehydrate"
	"github.com/namecoin/ncdns/util"
	"github.com/namecoin/x509-signature-splice/x509"
)

type Value struct {
	valueWithoutTLSA
	TLSAGenerated []x509.Certificate // Certs can be dehydrated in the blockchain, they will be put here without SAN values.  SAN must be filled in before use.
}

func (v *Value) appendTLSA(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, tlsa := range v.TLSA {
		out = append(out, tlsa)
	}

	for _, cert := range v.TLSAGenerated {

		template := cert

		_, nameNoPort := util.SplitDomainTail(suffix)
		_, nameNoPortOrProtocol := util.SplitDomainTail(nameNoPort)

		if !strings.HasSuffix(nameNoPortOrProtocol, ".") {
			continue
		}
		nameNoPortOrProtocol = strings.TrimSuffix(nameNoPortOrProtocol, ".")

		derBytes, err := certdehydrate.FillRehydratedCertTemplate(template, nameNoPortOrProtocol)
		if err != nil {
			// TODO: add debug output here
			continue
		}

		derBytesHex := hex.EncodeToString(derBytes)

		out = append(out, &dns.TLSA{
			Hdr: dns.RR_Header{Name: "", Rrtype: dns.TypeTLSA, Class: dns.ClassINET,
				Ttl: defaultTTL},
			Usage:        uint8(3),
			Selector:     uint8(0),
			MatchingType: uint8(0),
			Certificate:  strings.ToUpper(derBytesHex),
		})

	}

	return out, nil
}

func parseTLSADehydrated(tlsa1dehydrated interface{}, v *Value) error {
	dehydrated, err := certdehydrate.ParseDehydratedCert(tlsa1dehydrated)
	if err != nil {
		return fmt.Errorf("Error parsing dehydrated certificate: %s", err)
	}

	template, err := certdehydrate.RehydrateCert(dehydrated)
	if err != nil {
		return fmt.Errorf("Error rehydrating certificate: %s", err)
	}

	v.TLSAGenerated = append(v.TLSAGenerated, *template)

	return nil
}

func parseTLSADANE(tlsa1dane interface{}, v *Value) error {
	if tlsa, ok := tlsa1dane.([]interface{}); ok {
		// Format: ["443", "tcp", 1, 2, 3, "base64 certificate data"]
		if len(tlsa) < 4 {
			return fmt.Errorf("TLSA item must have six items")
		}

		a1, ok := tlsa[0].(float64)
		if !ok {
			return fmt.Errorf("Third item in TLSA value must be an integer (usage)")
		}

		a2, ok := tlsa[1].(float64)
		if !ok {
			return fmt.Errorf("Fourth item in TLSA value must be an integer (selector)")
		}

		a3, ok := tlsa[2].(float64)
		if !ok {
			return fmt.Errorf("Fifth item in TLSA value must be an integer (match type)")
		}

		a4, ok := tlsa[3].(string)
		if !ok {
			return fmt.Errorf("Sixth item in TLSA value must be a string (certificate)")
		}

		a4b, err := base64.StdEncoding.DecodeString(a4)
		if err != nil {
			return fmt.Errorf("Fourth item in DS value must be valid base64: %v", err)
		}

		a4h := hex.EncodeToString(a4b)

		v.TLSA = append(v.TLSA, &dns.TLSA{
			Hdr: dns.RR_Header{Name: "", Rrtype: dns.TypeTLSA, Class: dns.ClassINET,
				Ttl: defaultTTL},
			Usage:        uint8(a1),
			Selector:     uint8(a2),
			MatchingType: uint8(a3),
			Certificate:  strings.ToUpper(a4h),
		})

		return nil
	} else {
		return fmt.Errorf("TLSA item must be an array")
	}
}

func parseTLSA(rv map[string]interface{}, v *Value, errFunc ErrorFunc) {
	tlsa, ok := rv["tls"]
	if !ok || tlsa == nil {
		return
	}

	v.TLSA = nil

	if tlsaa, ok := tlsa.([]interface{}); ok {
		for _, tlsa1 := range tlsaa {
			var tlsa1m map[string]interface{}

			if _, ok := tlsa1.([]interface{}); ok {
				tlsa1m = map[string]interface{}{
					"dane": tlsa1,
				}
			} else {
				tlsa1m = tlsa1.(map[string]interface{})
			}

			if tlsa1dehydrated, ok := tlsa1m["d8"]; ok {
				err := parseTLSADehydrated(tlsa1dehydrated, v)
				if err == nil {
					continue
				}
				errFunc.add(err)
			}

			if tlsa1dane, ok := tlsa1m["dane"]; ok {
				err := parseTLSADANE(tlsa1dane, v)
				if err == nil {
					continue
				}
				errFunc.add(err)
			}

			errFunc.add(fmt.Errorf("Unknown TLSA item format"))
		}
		return
	}

	errFunc.add(fmt.Errorf("Malformed TLSA field format"))
}
