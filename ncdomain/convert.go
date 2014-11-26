package ncdomain

import "encoding/json"
import "net"
import "fmt"
import "github.com/miekg/dns"
import "encoding/base64"
import "encoding/hex"
import "regexp"
import "net/mail"

const depthLimit = 16
const mergeDepthLimit = 4

type Value struct {
	IP         []net.IP
	IP6        []net.IP
	NS         []string
	Alias      string
	Translate  string
	DS         []*dns.DS
	TXT        [][]string
	Service    []*dns.SRV        // header name contains e.g. "_http._tcp"
	Hostmaster string            // "hostmaster@example.com"
	MX         []*dns.MX         // header name is left blank
	Map        map[string]*Value // may contain and "*", will not contain ""
}

func (v *Value) RRs(out []dns.RR, suffix string) ([]dns.RR, error) {
	il := len(out)
	suffix = dns.Fqdn(suffix)

	out, _ = v.appendIPs(out, suffix)
	out, _ = v.appendIP6s(out, suffix)
	out, _ = v.appendNSs(out, suffix)
	out, _ = v.appendTXTs(out, suffix)
	out, _ = v.appendDSs(out, suffix)
	out, _ = v.appendServices(out, suffix)
	out, _ = v.appendMXs(out, suffix)
	out, _ = v.appendAlias(out, suffix)
	out, _ = v.appendTranslate(out, suffix)

	xout := out[il:]
	for i := range xout {
		xout[i].Header().Name = suffix
	}

	return out, nil
}

func (v *Value) appendIPs(out []dns.RR, suffix string) ([]dns.RR, error) {
	for _, ip := range v.IP {
		out = append(out, &dns.A{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			A: ip,
		})
	}

	return out, nil
}

func (v *Value) appendIP6s(out []dns.RR, suffix string) ([]dns.RR, error) {
	for _, ip := range v.IP6 {
		out = append(out, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			AAAA: ip,
		})
	}

	return out, nil
}

func (v *Value) appendNSs(out []dns.RR, suffix string) ([]dns.RR, error) {
	for _, ns := range v.NS {
		out = append(out, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			Ns: ns,
		})
	}

	return out, nil
}

func (v *Value) appendTXTs(out []dns.RR, suffix string) ([]dns.RR, error) {
	for _, txt := range v.TXT {
		out = append(out, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			Txt: txt,
		})
	}

	return out, nil
}

func (v *Value) appendDSs(out []dns.RR, suffix string) ([]dns.RR, error) {
	for _, ds := range v.DS {
		out = append(out, ds)
	}

	return out, nil
}

func (v *Value) appendMXs(out []dns.RR, suffix string) ([]dns.RR, error) {
	for _, mx := range v.MX {
		out = append(out, mx)
	}

	return out, nil
}

func (v *Value) appendServices(out []dns.RR, suffix string) ([]dns.RR, error) {
	for _, svc := range v.Service {
		out = append(out, svc)
	}

	return out, nil
}

func (v *Value) appendAlias(out []dns.RR, suffix string) ([]dns.RR, error) {
	if v.Alias != "" {
		out = append(out, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			Target: v.Alias,
		})
	}

	return out, nil
}

func (v *Value) appendTranslate(out []dns.RR, suffix string) ([]dns.RR, error) {
	if v.Translate != "" {
		out = append(out, &dns.DNAME{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeDNAME,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			Target: v.Translate,
		})
	}

	return out, nil
}

func (v *Value) RRsRecursive(out []dns.RR, suffix string) ([]dns.RR, error) {
	out, err := v.RRs(out, suffix)
	if err != nil {
		return nil, err
	}

	for mk, mv := range v.Map {
		out, err = mv.RRsRecursive(out, mk+"."+suffix)
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

type rawValue struct {
	IP         interface{} `json:"ip"`
	IP6        interface{} `json:"ip6"`
	NS         interface{} `json:"ns"`
	DNS        interface{} `json:"dns"` // actually an alias for NS
	Alias      interface{} `json:"alias"`
	Translate  interface{} `json:"translate"`
	DS         interface{} `json:"ds"`
	TXT        interface{} `json:"txt"`
	Hostmaster interface{} `json:"email"` // Hostmaster
	MX         interface{} `json:"mx"`

	Map json.RawMessage `json:"map"`

	Service  interface{} `json:"service"`
	Import   interface{} `json:"import"`
	Delegate interface{} `json:"delegate"`
}

type ResolveFunc func(name string) (string, error)

// Call to convert a given JSON value to a parsed Namecoin domain value.
//
// If ResolveFunc is given, it will be called to obtain the values for domains
// referenced by "import" and "delegate" statements. The name passed is in
// Namecoin form (e.g. "d/example"). The JSON value or an error should be
// returned. If no ResolveFunc is passed, "import" and "delegate" statements
// always fail.
func ParseValue(jsonValue string, resolve ResolveFunc) (value *Value, err error) {
	rv := &rawValue{}
	v := &Value{}

	err = json.Unmarshal([]byte(jsonValue), rv)
	if err != nil {
		return
	}

	if resolve == nil {
		resolve = func(name string) (string, error) {
			return "", fmt.Errorf("not supported")
		}
	}

	rv.parse(v, resolve, 0, 0)

	value = v
	return
}

func (rv *rawValue) parse(v *Value, resolve ResolveFunc, depth, mergeDepth int) error {
	if depth > depthLimit {
		return fmt.Errorf("depth limit exceeded")
	}

	ok, _ := rv.parseDelegate(v, resolve, depth, mergeDepth)
	if ok {
		return nil
	}

	rv.parseImport(v, resolve, depth, mergeDepth)
	rv.parseIP(v, rv.IP, false)
	rv.parseIP(v, rv.IP6, true)
	rv.parseNS(v)
	rv.parseAlias(v)
	rv.parseTranslate(v)
	rv.parseHostmaster(v)
	rv.parseDS(v)
	rv.parseTXT(v)
	rv.parseService(v)
	rv.parseMX(v)
	rv.parseMap(v, resolve, depth, mergeDepth)
	v.moveEmptyMapItems()

	return nil
}

func (rv *rawValue) parseMerge(mergeValue string, v *Value, resolve ResolveFunc, depth, mergeDepth int) error {
	rv2 := &rawValue{}

	if mergeDepth > mergeDepthLimit {
		return fmt.Errorf("merge depth limit exceeded")
	}

	err := json.Unmarshal([]byte(mergeValue), rv2)
	if err != nil {
		return err
	}

	return rv2.parse(v, resolve, depth, mergeDepth)
}

func (rv *rawValue) parseIP(v *Value, ipi interface{}, ipv6 bool) {
	if ipi != nil {
		if ipv6 {
			v.IP6 = nil
		} else {
			v.IP = nil
		}
	}

	if ipa, ok := ipi.([]interface{}); ok {
		for _, ip := range ipa {
			if ips, ok := ip.(string); ok {
				rv.addIP(v, ips, ipv6)
			}
		}

		return
	}

	if ip, ok := ipi.(string); ok {
		rv.addIP(v, ip, ipv6)
	}
}

func (rv *rawValue) addIP(v *Value, ips string, ipv6 bool) error {
	pip := net.ParseIP(ips)
	if pip == nil || (pip.To4() == nil) != ipv6 {
		return fmt.Errorf("malformed IP")
	}

	if ipv6 {
		v.IP6 = append(v.IP6, pip)
	} else {
		v.IP = append(v.IP, pip)
	}

	return nil
}

func (rv *rawValue) parseNS(v *Value) error {
	// "dns" takes precedence
	if rv.DNS != nil {
		rv.NS = rv.DNS
	}

	if rv.NS == nil {
		return nil
	}

	v.NS = nil

	switch rv.NS.(type) {
	case []interface{}:
		for _, si := range rv.NS.([]interface{}) {
			s, ok := si.(string)
			if !ok || !validateHostName(s) {
				continue
			}

			v.NS = append(v.NS, s)
		}
		return nil
	case string:
		s := rv.NS.(string)
		if !validateHostName(s) {
			return fmt.Errorf("malformed NS hostname")
		}

		v.NS = append(v.NS, s)
		return nil
	default:
		return fmt.Errorf("unknown NS field format")
	}
}

func (rv *rawValue) parseAlias(v *Value) error {
	if rv.Alias == nil {
		return nil
	}

	if s, ok := rv.Alias.(string); ok {
		if !validateHostName(s) {
			return fmt.Errorf("malformed hostname in alias field")
		}

		v.Alias = s
		return nil
	}

	return fmt.Errorf("unknown alias field format")
}

func (rv *rawValue) parseTranslate(v *Value) error {
	if rv.Translate == nil {
		return nil
	}

	if s, ok := rv.Translate.(string); ok {
		if !validateHostName(s) {
			return fmt.Errorf("malformed hostname in translate field")
		}

		v.Translate = s
		return nil
	}

	return fmt.Errorf("unknown translate field format")
}

func (rv *rawValue) parseImport(v *Value, resolve ResolveFunc, depth, mergeDepth int) error {
	if rv.Import == nil {
		return nil
	}

	if s, ok := rv.Import.(string); ok {
		dv, err := resolve(s)
		if err == nil {
			err = rv.parseMerge(dv, v, resolve, depth, mergeDepth+1)
		}
		return err
	}

	return fmt.Errorf("unknown import field format")
}

func (rv *rawValue) parseDelegate(v *Value, resolve ResolveFunc, depth, mergeDepth int) (bool, error) {
	if rv.Delegate == nil {
		return false, nil
	}

	if s, ok := rv.Delegate.(string); ok {
		dv, err := resolve(s)
		if err == nil {
			err = rv.parseMerge(dv, v, resolve, depth, mergeDepth+1)
		}
		return true, err
	}

	return false, fmt.Errorf("unknown delegate field format")
}

func (rv *rawValue) parseHostmaster(v *Value) error {
	if rv.Translate == nil {
		return nil
	}

	if s, ok := rv.Hostmaster.(string); ok {
		if !validateEmail(s) {
			return fmt.Errorf("malformed e. mail address in email field")
		}

		v.Hostmaster = s
		return nil
	}

	return fmt.Errorf("unknown email field format")
}

func (rv *rawValue) parseDS(v *Value) error {
	if rv.DS == nil {
		return nil
	}

	v.DS = nil

	if dsa, ok := rv.DS.([]interface{}); ok {
		for _, ds1 := range dsa {
			if ds, ok := ds1.([]interface{}); ok {
				if len(ds) != 4 {
					continue
				}

				a1, ok := ds[0].(float64)
				if !ok {
					continue
				}

				a2, ok := ds[1].(float64)
				if !ok {
					continue
				}

				a3, ok := ds[2].(float64)
				if !ok {
					continue
				}

				a4, ok := ds[3].(string)
				if !ok {
					continue
				}

				a4b, err := base64.StdEncoding.DecodeString(a4)
				if err != nil {
					continue
				}

				a4h := hex.EncodeToString(a4b)
				v.DS = append(v.DS, &dns.DS{
					Hdr:        dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 600},
					KeyTag:     uint16(a1),
					Algorithm:  uint8(a2),
					DigestType: uint8(a3),
					Digest:     a4h,
				})
			}
		}
	}
	return fmt.Errorf("malformed DS field format")
}

func (rv *rawValue) parseTXT(v *Value) error {
	if rv.TXT == nil {
		return nil
	}

	if txta, ok := rv.TXT.([]interface{}); ok {
		// ["...", "..."] or [["...", "..."], ["...", "..."]]
		for _, vv := range txta {
			if sa, ok := vv.([]interface{}); ok {
				// [["...", "..."], ["...", "..."]]
				a := []string{}
				for _, x := range sa {
					if xs, ok := x.(string); ok {
						a = append(a, xs)
					}
				}
				v.TXT = append(v.TXT, a)
			} else if s, ok := vv.(string); ok {
				v.TXT = append(v.TXT, segmentizeTXT(s))
			} else {
				return fmt.Errorf("malformed TXT value")
			}
		}
	} else {
		// "..."
		if s, ok := rv.TXT.(string); ok {
			v.TXT = append(v.TXT, segmentizeTXT(s))
		} else {
			return fmt.Errorf("malformed TXT value")
		}
	}

	return nil
}

func segmentizeTXT(txt string) (a []string) {
	for len(txt) > 255 {
		a = append(a, txt[0:255])
		txt = txt[255:]
	}
	a = append(a, txt)
	return
}

func (rv *rawValue) parseMX(v *Value) error {
	if rv.MX == nil {
		return nil
	}

	if sa, ok := rv.MX.([]interface{}); ok {
		for _, s := range sa {
			rv.parseSingleMX(s, v)
		}
	}

	return fmt.Errorf("malformed MX value")
}

func (rv *rawValue) parseSingleMX(s interface{}, v *Value) error {
	sa, ok := s.([]interface{})
	if !ok {
		return fmt.Errorf("malformed MX value")
	}

	if len(sa) < 2 {
		return fmt.Errorf("malformed MX value")
	}

	prio, ok := sa[0].(float64)
	if !ok || prio < 0 {
		return fmt.Errorf("malformed MX value")
	}

	hostname, ok := sa[1].(string)
	if !ok || !validateHostName(hostname) {
		return fmt.Errorf("malformed MX value")
	}

	v.MX = append(v.MX, &dns.MX{
		Hdr:        dns.RR_Header{Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 600},
		Preference: uint16(prio),
		Mx:         hostname,
	})

	return nil
}

func (rv *rawValue) parseService(v *Value) error {
	if rv.Service == nil {
		return nil
	}

	if sa, ok := rv.Service.([]interface{}); ok {
		for _, s := range sa {
			rv.parseSingleService(s, v)
		}
	}

	return fmt.Errorf("malformed service value")
}

func (rv *rawValue) parseSingleService(svc interface{}, v *Value) error {
	svca, ok := svc.([]interface{})
	if !ok {
		return fmt.Errorf("malformed service value")
	}

	if len(svca) < 6 {
		return fmt.Errorf("malformed service value")
	}

	appProtoName, ok := svca[0].(string)
	if !ok || !validateServiceName(appProtoName) {
		return fmt.Errorf("malformed service value")
	}

	transportProtoName, ok := svca[1].(string)
	if !ok || !validateServiceName(transportProtoName) {
		return fmt.Errorf("malformed service value")
	}

	priority, ok := svca[2].(float64)
	if !ok {
		return fmt.Errorf("malformed service value")
	}

	weight, ok := svca[3].(float64)
	if !ok {
		return fmt.Errorf("malformed service value")
	}

	port, ok := svca[4].(float64)
	if !ok {
		return fmt.Errorf("malformed service value")
	}

	hostname, ok := svca[5].(string)
	if !ok || !validateHostName(hostname) {
		return fmt.Errorf("malformed service value")
	}

	v.Service = append(v.Service, &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   "_" + appProtoName + "._" + transportProtoName,
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    600,
		},
		Priority: uint16(priority),
		Weight:   uint16(weight),
		Port:     uint16(port),
		Target:   hostname,
	})

	return nil
}

func (rv *rawValue) parseMap(v *Value, resolve ResolveFunc, depth, mergeDepth int) error {
	m := map[string]json.RawMessage{}

	err := json.Unmarshal(rv.Map, &m)
	if err != nil {
		return err
	}

	for mk, mv := range m {
		rv2 := &rawValue{}
		v2 := &Value{}

		var s string
		err := json.Unmarshal(mv, &s)
		if err == nil {
			// deprecated case: "map": { "": "127.0.0.1" }
			rv2.IP = s
			rv2.IP6 = s
		} else {
			// normal case: "map": { "": { ... } }
			err = json.Unmarshal(mv, rv2)
			if err != nil {
				continue
			}
		}

		rv2.parse(v2, resolve, depth+1, mergeDepth)

		if v.Map == nil {
			v.Map = make(map[string]*Value)
		}

		v.Map[mk] = v2
	}

	return nil
}

// Moves items in {"map": {"": ...}} to the object itself, then deletes the ""
// entry in the map object.
func (v *Value) moveEmptyMapItems() error {
	if ev, ok := v.Map[""]; ok {
		if len(v.IP) == 0 {
			v.IP = ev.IP
		}
		if len(v.IP6) == 0 {
			v.IP6 = ev.IP6
		}
		if len(v.NS) == 0 {
			v.NS = ev.NS
		}
		if len(v.DS) == 0 {
			v.DS = ev.DS
		}
		if len(v.TXT) == 0 {
			v.TXT = ev.TXT
		}
		if len(v.Service) == 0 {
			v.Service = ev.Service
		}
		if len(v.MX) == 0 {
			v.MX = ev.MX
		}
		if len(v.Alias) == 0 {
			v.Alias = ev.Alias
		}
		if len(v.Translate) == 0 {
			v.Translate = ev.Translate
		}
		if len(v.Hostmaster) == 0 {
			v.Hostmaster = ev.Hostmaster
		}
		delete(v.Map, "")
		if len(v.Map) == 0 {
			v.Map = ev.Map
		}
	}
	return nil
}

// Validation functions

var re_hostName = regexp.MustCompilePOSIX(`^([a-z0-9_-]+\.)*[a-z0-9_-]+\.?$`)
var re_serviceName = regexp.MustCompilePOSIX(`^[a-z_][a-z0-9_-]*$`)

func validateHostName(name string) bool {
	name = dns.Fqdn(name)
	return len(name) <= 255 && re_hostName.MatchString(name)
}

func validateServiceName(name string) bool {
	return len(name) < 63 && re_serviceName.MatchString(name)
}

func validateEmail(email string) bool {
	addr, err := mail.ParseAddress(email)
	if addr == nil || err != nil {
		return false
	}
	return addr.Name == ""
}
