package ncdomain_test

import "github.com/namecoin/ncdns/ncdomain"
import "github.com/namecoin/ncdns/testutil"
import _ "github.com/hlandau/nctestsuite"
import "testing"
import "fmt"
import "strings"
import "sort"

func TestSuite(t *testing.T) {
	items := testutil.SuiteReader(t)
	for ti := range items {
		// Don't test TLSA records if TLSA is disabled via build tag.
		if tlsaDisabled && strings.HasPrefix(ti.ID, "tlsa") {
			continue
		}

		resolve := func(name string) (string, error) {
			v, ok := ti.Names[name]
			if !ok {
				return "", fmt.Errorf("not found")
			}

			return v, nil
		}

		for k, jsonValue := range ti.Names {
			dnsName, err := convertName(k)
			if err != nil {
				continue
			}

			errCount := 0
			errFunc := func(err error, isWarning bool) {
				if !isWarning {
					errCount++
				}
				//fmt.Printf("Error:  %v\n", err)
			}

			v := ncdomain.ParseValue(k, jsonValue, resolve, errFunc)
			if v == nil {
				// TODO
				continue
			}

			rrstrs := []string{}
			rrs, _ := v.RRsRecursive(nil, dnsName+".bit.", dnsName+".bit.")
			for _, rr := range rrs {
				s := rr.String()
				s = strings.Replace(s, "\t600\t", "\t", -1) // XXX
				rrstrs = append(rrstrs, strings.Replace(s, "\t", " ", -1))
			}
			sort.Strings(rrstrs)
			rrstr := strings.Join(rrstrs, "\n")

			// CHECK MATCH
			if rrstr != ti.Records {
				t.Errorf("Didn't match: %s\n%+v\n    !=\n%+v\n\n%#v\n\n%#v", ti.ID, rrstr, ti.Records, v, rrs)
			}

			if errCount != ti.NumErrors {
				t.Errorf("Error count didn't match: %d != %d (%s)\n", errCount, ti.NumErrors, ti.ID)
			}
		}
	}
}

func convertName(n string) (string, error) {
	if len(n) < 3 || len(n) > 65 {
		return "", fmt.Errorf("invalid name")
	}
	if n[0:2] != "d/" {
		return "", fmt.Errorf("not a domain")
	}
	return n[2:], nil
}

/*
type item struct {
	jsonValue     string
	value         *ncdomain.Value
	expectedError error
	merges        map[string]string
	rrstr         string
}

var suite = []item{
	item{`{}`, &ncdomain.Value{}, nil, nil, ""},
	item{`{"ip":"1.2.3.4"}`, &ncdomain.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}, nil, nil, "bit. 600 IN A 1.2.3.4"},
	item{`{"ip":["1.2.3.4"]}`, &ncdomain.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}, nil, nil, "bit. 600 IN A 1.2.3.4"},
	item{`{"ip":["1.2.3.4","200.200.200.200"]}`, &ncdomain.Value{IP: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("200.200.200.200")}}, nil, nil, "bit. 600 IN A 1.2.3.4\nbit. 600 IN A 200.200.200.200"},
	item{`{"ip6":"dead:b33f::deca:fbad"}`, &ncdomain.Value{IP6: []net.IP{net.ParseIP("dead:b33f::deca:fbad")}}, nil, nil, "bit. 600 IN AAAA dead:b33f::deca:fbad"},
	item{`{"ip6":["dead:b33f::deca:fbad"]}`, &ncdomain.Value{IP6: []net.IP{net.ParseIP("dead:b33f::deca:fbad")}}, nil, nil, "bit. 600 IN AAAA dead:b33f::deca:fbad"},
	item{`{"ip6":["dead:b33f::deca:fbad","1234:abcd:5678:bcde:9876:fedc:5432:ba98"]}`, &ncdomain.Value{IP6: []net.IP{net.ParseIP("dead:b33f::deca:fbad"), net.ParseIP("1234:abcd:5678:bcde:9876:fedc:5432:ba98")}}, nil, nil, "bit. 600 IN AAAA dead:b33f::deca:fbad\nbit. 600 IN AAAA 1234:abcd:5678:bcde:9876:fedc:5432:ba98"},
	item{`{"ns":"alpha.beta.gamma.delta"}`, &ncdomain.Value{NS: []string{"alpha.beta.gamma.delta"}}, nil, nil, "bit. 600 IN NS alpha.beta.gamma.delta."},
	item{`{"ns":["alpha.beta.gamma.delta"]}`, &ncdomain.Value{NS: []string{"alpha.beta.gamma.delta"}}, nil, nil, "bit. 600 IN NS alpha.beta.gamma.delta."},
	item{`{"ns":["alpha.beta.gamma.delta","delta.gamma.beta.alpha"]}`, &ncdomain.Value{NS: []string{"alpha.beta.gamma.delta", "delta.gamma.beta.alpha"}}, nil, nil, "bit. 600 IN NS alpha.beta.gamma.delta.\nbit. 600 IN NS delta.gamma.beta.alpha."},
	item{`{"mx":[[10,"alpha.beta.gamma.delta"]]}`, &ncdomain.Value{MX: []*dns.MX{&dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 600}, Preference: 10, Mx: "alpha.beta.gamma.delta"}}}, nil, nil, "bit. 600 IN MX 10 alpha.beta.gamma.delta."},
	item{`{"mx":[[10,"alpha.beta.gamma.delta"],[20,"epsilon.example"]]}`, &ncdomain.Value{MX: []*dns.MX{&dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 600}, Preference: 10, Mx: "alpha.beta.gamma.delta"}, &dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 600}, Preference: 20, Mx: "epsilon.example"}}}, nil, nil, "bit. 600 IN MX 10 alpha.beta.gamma.delta.\nbit. 600 IN MX 20 epsilon.example."},
	item{`{"alias":"alpha.beta.gamma.delta"}`, &ncdomain.Value{Alias: "alpha.beta.gamma.delta"}, nil, nil, "bit. 600 IN CNAME alpha.beta.gamma.delta."},
	item{`{"translate":"alpha.beta.gamma.delta"}`, &ncdomain.Value{Translate: "alpha.beta.gamma.delta"}, nil, nil, "bit. 600 IN DNAME alpha.beta.gamma.delta."},
	item{`{"txt":"text record"}`, &ncdomain.Value{TXT: [][]string{[]string{"text record"}}}, nil, nil, "bit. 600 IN TXT \"text record\""},
	item{`{"txt":"[text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record]"}`, &ncdomain.Value{TXT: [][]string{[]string{"[text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record]", "[text ... record]"}}}, nil, nil, ""},
	item{`{"txt":["text record"]}`, &ncdomain.Value{TXT: [][]string{[]string{"text record"}}}, nil, nil, "bit. 600 IN TXT \"text record\""},
	item{`{"txt":["text record","text record 2"]}`, &ncdomain.Value{TXT: [][]string{[]string{"text record"}, []string{"text record 2"}}}, nil, nil, "bit. 600 IN TXT \"text record\"\nbit. 600 IN TXT \"text record 2\""},
	item{`{"txt":[["text", "record"]]}`, &ncdomain.Value{TXT: [][]string{[]string{"text", "record"}}}, nil, nil, "bit. 600 IN TXT \"text\" \"record\""},
	item{`{"txt":[["text", "record"],["text", "record", "2"]]}`, &ncdomain.Value{TXT: [][]string{[]string{"text", "record"}, []string{"text", "record", "2"}}}, nil, nil, "bit. 600 IN TXT \"text\" \"record\"\nbit. 600 IN TXT \"text\" \"record\" \"2\""},
	item{`{"service":[ ["http","tcp",1,2,80,"alpha.beta.gamma.delta"] ]}`, &ncdomain.Value{Service: []*dns.SRV{&dns.SRV{Hdr: dns.RR_Header{Name: "_http._tcp", Ttl: 600, Rrtype: dns.TypeSRV, Class: dns.ClassINET}, Priority: 1, Weight: 2, Port: 80, Target: "alpha.beta.gamma.delta"}}}, nil, nil, "_http._tcp.bit. IN SRV 1 2 80 alpha.beta.gamma.delta."},
	item{`{"service":[ ["http","tcp",1,2,80,"alpha.beta.gamma.delta"], ["https","tcp",1,2,443,"alpha.beta.gamma.delta"] ]}`, &ncdomain.Value{Service: []*dns.SRV{&dns.SRV{Hdr: dns.RR_Header{Name: "_http._tcp", Ttl: 600, Rrtype: dns.TypeSRV, Class: dns.ClassINET}, Priority: 1, Weight: 2, Port: 80, Target: "alpha.beta.gamma.delta"}, &dns.SRV{Hdr: dns.RR_Header{Name: "_https._tcp", Ttl: 600, Rrtype: dns.TypeSRV, Class: dns.ClassINET}, Priority: 1, Weight: 2, Port: 443, Target: "alpha.beta.gamma.delta"}}}, nil, nil, "_http._tcp.bit. 600 IN SRV 1 2 80 alpha.beta.gamma.delta.\n_https._tcp.bit. 600 IN SRV 1 2 443 alpha.beta.gamma.delta."},
	item{`{"map":{ "": {  } }}`, &ncdomain.Value{}, nil, nil, ""},
	item{`{"map":{ "": { "ip": "1.2.3.4" } }}`, &ncdomain.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}, nil, nil, "bit. 600 IN A 1.2.3.4"},
	item{`{"map":{ "www": { "ip": "1.2.3.4" } }}`, &ncdomain.Value{Map: map[string]*ncdomain.Value{"www": &ncdomain.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}}}, nil, nil, "www.bit. 600 IN A 1.2.3.4"},
	item{`{"map":{ "": "1.2.3.4" }}`, &ncdomain.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}, nil, nil, "bit. 600 IN A 1.2.3.4"},
	item{`{"map":{ "www": "1.2.3.4" }}`, &ncdomain.Value{Map: map[string]*ncdomain.Value{"www": &ncdomain.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}}}, nil, nil, "www.bit. 600 IN A 1.2.3.4"},
	item{`{"ds":[[12345,8,2,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]]}`, &ncdomain.Value{DS: []*dns.DS{&dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600}, KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766"}}}, nil, nil, "bit. 600 IN DS 12345 8 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766"},
	item{`{"ds":[[54321,8,1,"5sFxbPtr3IToTOGrVRDaxpFztbI="],[12345,8,2,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]]}`, &ncdomain.Value{DS: []*dns.DS{&dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600}, KeyTag: 54321, Algorithm: 8, DigestType: 1, Digest: "e6c1716cfb6bdc84e84ce1ab5510dac69173b5b2"}, &dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600}, KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766"}}}, nil, nil, "bit. 600 IN DS 54321 8 1 E6C1716CFB6BDC84E84CE1AB5510DAC69173B5B2\nbit. 600 IN DS 12345 8 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766"},
	item{`{"email":"hostmaster@example.com"}`, &ncdomain.Value{Hostmaster: "hostmaster@example.com"}, nil, nil, ""},
	item{`{"ip":["1.2.3.4"],"import":"d/example"}`, &ncdomain.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}, IP6: []net.IP{net.ParseIP("::beef")}}, nil, map[string]string{"d/example": `{"ip6":["::beef"]}`}, "bit. 600 IN A 1.2.3.4\nbit. 600 IN AAAA ::beef"},
	item{`{"ip":["1.2.3.4"],"import":"d/example"}`, &ncdomain.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}, IP6: []net.IP{net.ParseIP("::beef")}}, nil, map[string]string{"d/example": `{"ip":["2.3.4.5"],"ip6":["::beef"]}`}, "bit. 600 IN A 1.2.3.4\nbit. 600 IN AAAA ::beef"},
	item{`{"ns":["alpha.beta"],"import":"d/example"}`, &ncdomain.Value{NS: []string{"alpha.beta"}, IP6: []net.IP{net.ParseIP("::beef")}}, nil, map[string]string{"d/example": `{"ns":["gamma.delta"],"ip6":["::beef"]}`}, "bit. 600 IN NS alpha.beta."},
	item{`{"ds":[[12345,8,2,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]],"import":"d/example"}`, &ncdomain.Value{DS: []*dns.DS{&dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600}, KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766"}}}, nil, map[string]string{"d/example": `{"ds":[ [54321,8,1,"5sFxbPtr3IToTOGrVRDaxpFztbI="] ]}`}, "bit. 600 IN DS 12345 8 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766"},
	item{`{"import":"d/example"}`, &ncdomain.Value{DS: []*dns.DS{&dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600}, KeyTag: 54321, Algorithm: 8, DigestType: 1, Digest: "e6c1716cfb6bdc84e84ce1ab5510dac69173b5b2"}}}, nil, map[string]string{"d/example": `{"ds":[ [54321,8,1,"5sFxbPtr3IToTOGrVRDaxpFztbI="] ]}`}, "bit. 600 IN DS 54321 8 1 E6C1716CFB6BDC84E84CE1AB5510DAC69173B5B2"},
	item{`{"ip":["1.2.3.4"],"delegate":"d/example"}`, &ncdomain.Value{IP6: []net.IP{net.ParseIP("::beef")}}, nil, map[string]string{"d/example": `{"ip6":["::beef"]}`}, "bit. 600 IN AAAA ::beef"},
}

func TestConversion(t *testing.T) {
	for i, item := range suite {
		resolve := func(name string) (string, error) {
			if item.merges == nil {
				return "", fmt.Errorf("not found")
			}

			if s, ok := item.merges[name]; ok {
				return s, nil
			} else {
				return "", fmt.Errorf("not found")
			}
		}
		v, err := ncdomain.ParseValue(item.jsonValue, resolve)
		if err != item.expectedError {
			t.Errorf("Item %d did not match expected error: got %+v but expected %+v", i, err, item.expectedError)
		}
		if !equals(v, item.value) {
			t.Errorf("Item %d value did not match expected value: got %+v but expected %+v", i, v, item.value)
		}
		if item.rrstr != "" {
			rrstr := ""
			rrs, _ := v.RRsRecursive(nil, "bit.")
			for _, rr := range rrs {
				rrstr += strings.Replace(rr.String(), "\t", " ", -1)
				rrstr += "\n"
			}
			rrstr = strings.Trim(rrstr, "\n")
			if item.rrstr != rrstr {
				t.Errorf("Item %d rrstr did not match the expected value: got %+v but expected %+v", i, rrstr, item.rrstr)
			}
		}
	}
}

// utility functions for testing equality

func equals(v1 *ncdomain.Value, v2 *ncdomain.Value) bool {
	return (v1 != nil) == (v2 != nil) &&
		eqIPArray(v1.IP, v2.IP) &&
		eqIPArray(v1.IP6, v2.IP6) &&
		eqStringArray(v1.NS, v2.NS) &&
		v1.Alias == v2.Alias &&
		v1.Translate == v2.Translate &&
		eqDSArray(v1.DS, v2.DS) &&
		eqStringArrayArray(v1.TXT, v2.TXT) &&
		eqServiceArray(v1.Service, v2.Service) &&
		eqValueMap(v1, v2) &&
		v1.Hostmaster == v2.Hostmaster
}

func eqIPArray(a []net.IP, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func eqStringArray(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func eqDSArray(a []*dns.DS, b []*dns.DS) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !eqDS(a[i], b[i]) {
			return false
		}
	}
	return true
}

func eqDS(a *dns.DS, b *dns.DS) bool {
	return a.KeyTag == b.KeyTag && a.Algorithm == b.Algorithm &&
		a.DigestType == b.DigestType && a.Digest == b.Digest && eqHdr(a.Hdr, b.Hdr)
}

func eqHdr(a dns.RR_Header, b dns.RR_Header) bool {
	return a.Name == b.Name && a.Rrtype == b.Rrtype && a.Class == b.Class && a.Ttl == b.Ttl
}

func eqStringArrayArray(a [][]string, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !eqStringArray(a[i], b[i]) {
			return false
		}
	}
	return true
}

func eqServiceArray(a []*dns.SRV, b []*dns.SRV) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !eqService(a[i], b[i]) {
			return false
		}
	}
	return true
}

func eqService(a *dns.SRV, b *dns.SRV) bool {
	return a.Priority == b.Priority && a.Weight == b.Weight &&
		a.Port == b.Port && a.Target == b.Target && eqHdr(a.Hdr, b.Hdr)
}

func eqValueMap(a *ncdomain.Value, b *ncdomain.Value) bool {
	if len(a.Map) != len(b.Map) {
		return false
	}

	for k, v1 := range a.Map {
		v2, ok := b.Map[k]
		if !ok {
			return false
		}
		if !equals(v1, v2) {
			return false
		}
	}

	return true
}*/
