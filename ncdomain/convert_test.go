package ncdomain_test

import "github.com/hlandau/ncdns/convert"
import "github.com/miekg/dns"
import "testing"
import "net"
import "fmt"

type item struct {
	jsonValue     string
	value         *convert.Value
	expectedError error
	merges        map[string]string
}

var suite = []item{
	item{`{}`, &convert.Value{}, nil, nil},
	item{`{"ip":"1.2.3.4"}`, &convert.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}, nil, nil},
	item{`{"ip":["1.2.3.4"]}`, &convert.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}, nil, nil},
	item{`{"ip":["1.2.3.4","200.200.200.200"]}`, &convert.Value{IP: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("200.200.200.200")}}, nil, nil},
	item{`{"ip6":"dead:b33f::deca:fbad"}`, &convert.Value{IP6: []net.IP{net.ParseIP("dead:b33f::deca:fbad")}}, nil, nil},
	item{`{"ip6":["dead:b33f::deca:fbad"]}`, &convert.Value{IP6: []net.IP{net.ParseIP("dead:b33f::deca:fbad")}}, nil, nil},
	item{`{"ip6":["dead:b33f::deca:fbad","1234:abcd:5678:bcde:9876:fedc:5432:ba98"]}`, &convert.Value{IP6: []net.IP{net.ParseIP("dead:b33f::deca:fbad"), net.ParseIP("1234:abcd:5678:bcde:9876:fedc:5432:ba98")}}, nil, nil},
	item{`{"ns":"alpha.beta.gamma.delta"}`, &convert.Value{NS: []string{"alpha.beta.gamma.delta"}}, nil, nil},
	item{`{"ns":["alpha.beta.gamma.delta"]}`, &convert.Value{NS: []string{"alpha.beta.gamma.delta"}}, nil, nil},
	item{`{"ns":["alpha.beta.gamma.delta","delta.gamma.beta.alpha"]}`, &convert.Value{NS: []string{"alpha.beta.gamma.delta", "delta.gamma.beta.alpha"}}, nil, nil},
	item{`{"mx":[[10,"alpha.beta.gamma.delta"]]}`, &convert.Value{MX: []dns.MX{dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 600}, Preference: 10, Mx: "alpha.beta.gamma.delta"}}}, nil, nil},
	item{`{"mx":[[10,"alpha.beta.gamma.delta"],[20,"epsilon.example"]]}`, &convert.Value{MX: []dns.MX{dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 600}, Preference: 10, Mx: "alpha.beta.gamma.delta"}, dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 600}, Preference: 20, Mx: "epsilon.example"}}}, nil, nil},
	item{`{"alias":"alpha.beta.gamma.delta"}`, &convert.Value{Alias: "alpha.beta.gamma.delta"}, nil, nil},
	item{`{"translate":"alpha.beta.gamma.delta"}`, &convert.Value{Translate: "alpha.beta.gamma.delta"}, nil, nil},
	item{`{"txt":"text record"}`, &convert.Value{TXT: [][]string{[]string{"text record"}}}, nil, nil},
	item{`{"txt":"[text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record]"}`, &convert.Value{TXT: [][]string{[]string{"[text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record][text ... record]", "[text ... record]"}}}, nil, nil},
	item{`{"txt":["text record"]}`, &convert.Value{TXT: [][]string{[]string{"text record"}}}, nil, nil},
	item{`{"txt":["text record","text record 2"]}`, &convert.Value{TXT: [][]string{[]string{"text record"}, []string{"text record 2"}}}, nil, nil},
	item{`{"txt":[["text", "record"]]}`, &convert.Value{TXT: [][]string{[]string{"text", "record"}}}, nil, nil},
	item{`{"txt":[["text", "record"],["text", "record", "2"]]}`, &convert.Value{TXT: [][]string{[]string{"text", "record"}, []string{"text", "record", "2"}}}, nil, nil},
	item{`{"service":[ ["http","tcp",1,2,80,"alpha.beta.gamma.delta"] ]}`, &convert.Value{Service: []dns.SRV{dns.SRV{Hdr: dns.RR_Header{Name: "_http._tcp", Ttl: 600, Rrtype: dns.TypeSRV, Class: dns.ClassINET}, Priority: 1, Weight: 2, Port: 80, Target: "alpha.beta.gamma.delta"}}}, nil, nil},
	item{`{"service":[ ["http","tcp",1,2,80,"alpha.beta.gamma.delta"], ["https","tcp",1,2,443,"alpha.beta.gamma.delta"] ]}`, &convert.Value{Service: []dns.SRV{dns.SRV{Hdr: dns.RR_Header{Name: "_http._tcp", Ttl: 600, Rrtype: dns.TypeSRV, Class: dns.ClassINET}, Priority: 1, Weight: 2, Port: 80, Target: "alpha.beta.gamma.delta"}, dns.SRV{Hdr: dns.RR_Header{Name: "_https._tcp", Ttl: 600, Rrtype: dns.TypeSRV, Class: dns.ClassINET}, Priority: 1, Weight: 2, Port: 443, Target: "alpha.beta.gamma.delta"}}}, nil, nil},
	item{`{"map":{ "": {  } }}`, &convert.Value{}, nil, nil},
	item{`{"map":{ "": { "ip": "1.2.3.4" } }}`, &convert.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}, nil, nil},
	item{`{"map":{ "www": { "ip": "1.2.3.4" } }}`, &convert.Value{Map: map[string]*convert.Value{"www": &convert.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}}}, nil, nil},
	item{`{"map":{ "": "1.2.3.4" }}`, &convert.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}, nil, nil},
	item{`{"map":{ "www": "1.2.3.4" }}`, &convert.Value{Map: map[string]*convert.Value{"www": &convert.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}}}}, nil, nil},
	item{`{"ds":[[12345,8,2,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]]}`, &convert.Value{DS: []dns.DS{dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600}, KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766"}}}, nil, nil},
	item{`{"ds":[[54321,8,1,"5sFxbPtr3IToTOGrVRDaxpFztbI="],[12345,8,2,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]]}`, &convert.Value{DS: []dns.DS{dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600}, KeyTag: 54321, Algorithm: 8, DigestType: 1, Digest: "e6c1716cfb6bdc84e84ce1ab5510dac69173b5b2"}, dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600}, KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766"}}}, nil, nil},
	item{`{"email":"hostmaster@example.com"}`, &convert.Value{Hostmaster: "hostmaster@example.com"}, nil, nil},
	item{`{"ip":["1.2.3.4"],"import":"d/example"}`, &convert.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}, IP6: []net.IP{net.ParseIP("::beef")}}, nil, map[string]string{"d/example": `{"ip6":["::beef"]}`}},
	item{`{"ip":["1.2.3.4"],"import":"d/example"}`, &convert.Value{IP: []net.IP{net.ParseIP("1.2.3.4")}, IP6: []net.IP{net.ParseIP("::beef")}}, nil, map[string]string{"d/example": `{"ip":["2.3.4.5"],"ip6":["::beef"]}`}},
	item{`{"ns":["alpha.beta"],"import":"d/example"}`, &convert.Value{NS: []string{"alpha.beta"}, IP6: []net.IP{net.ParseIP("::beef")}}, nil, map[string]string{"d/example": `{"ns":["gamma.delta"],"ip6":["::beef"]}`}},
	item{`{"ds":[[12345,8,2,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]],"import":"d/example"}`, &convert.Value{DS: []dns.DS{dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600}, KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766"}}}, nil, map[string]string{"d/example": `{"ds":[ [54321,8,1,"5sFxbPtr3IToTOGrVRDaxpFztbI="] ]}`}},
	item{`{"import":"d/example"}`, &convert.Value{DS: []dns.DS{dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600}, KeyTag: 54321, Algorithm: 8, DigestType: 1, Digest: "e6c1716cfb6bdc84e84ce1ab5510dac69173b5b2"}}}, nil, map[string]string{"d/example": `{"ds":[ [54321,8,1,"5sFxbPtr3IToTOGrVRDaxpFztbI="] ]}`}},
	item{`{"ip":["1.2.3.4"],"delegate":"d/example"}`, &convert.Value{IP6: []net.IP{net.ParseIP("::beef")}}, nil, map[string]string{"d/example": `{"ip6":["::beef"]}`}},
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
		v, err := convert.ParseValue(item.jsonValue, resolve)
		if err != item.expectedError {
			t.Errorf("Item %d did not match expected error: got %+v but expected %+v", i, err, item.expectedError)
		}
		if !equals(v, item.value) {
			t.Errorf("Item %d value did not match expected value: got %+v but expected %+v", i, v, item.value)
		}
	}
}

// utility functions for testing equality

func equals(v1 *convert.Value, v2 *convert.Value) bool {
	return (v1 != nil) == (v2 != nil) &&
		eqIPArray(v1.IP, v2.IP) &&
		eqIPArray(v1.IP6, v2.IP6) &&
		eqStringArray(v1.NS, v2.NS) &&
		v1.Alias == v2.Alias &&
		eqDSArray(v1.DS, v2.DS) &&
		eqStringArrayArray(v1.TXT, v2.TXT) &&
		eqServiceArray(v1.Service, v2.Service) &&
		eqValueMap(v1, v2)
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

func eqDSArray(a []dns.DS, b []dns.DS) bool {
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

func eqDS(a dns.DS, b dns.DS) bool {
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

func eqServiceArray(a []dns.SRV, b []dns.SRV) bool {
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

func eqService(a dns.SRV, b dns.SRV) bool {
	return a.Priority == b.Priority && a.Weight == b.Weight &&
		a.Port == b.Port && a.Target == b.Target && eqHdr(a.Hdr, b.Hdr)
}

func eqValueMap(a *convert.Value, b *convert.Value) bool {
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
}
