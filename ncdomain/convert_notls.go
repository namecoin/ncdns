//go:build no_namecoin_tls
// +build no_namecoin_tls

package ncdomain

import (
	"github.com/miekg/dns"
)

func (v *Value) appendTLSA(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	return out, nil
}

func parseTLSA(rv map[string]interface{}, v *Value, errFunc ErrorFunc) {
	v.TLSA = nil
}
