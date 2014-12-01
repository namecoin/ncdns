package ncdomain

import "encoding/json"
import "net"
import "fmt"
import "github.com/miekg/dns"
import "encoding/base64"
import "encoding/hex"
import "regexp"
import "net/mail"
import "github.com/hlandau/ncdns/util"
import "strings"

const depthLimit = 16
const mergeDepthLimit = 4

// Note: Name values in Value (e.g. those in Alias and Target, Services, MXs,
// etc.) are not necessarily fully qualified and must be fully qualified before
// being used. Non-fully-qualified names are relative to the name apex, and
// should be qualified as such based on whatever the corresponding name for the
// Value is and the zone apex you are using for .bit. These assumptions are not
// built-in for you to give flexibility in where the .bit zone is mounted,
// DNS namespace-wise. If you just call RRs() or RRsRecursive() you don't have
// to worry about any of this.
//
// Because empty values are used to indicate the non-presence of an option
// in some cases, namely for Alias and Translate, the empty string is represented as "=".
// Therefore when qualifying names in a Value yourself you must check if the
// input string is "=" and if so, replace it with "" first.
type Value struct {
	IP           []net.IP
	IP6          []net.IP
	NS           []string
	Alias        string
	HasAlias     bool // True if Alias was specified. Necessary as "" is a valid relative alias.
	Translate    string
	HasTranslate bool // True if Translate was specified. Necessary as "" is a valid relative value for Translate.
	DS           []*dns.DS
	TXT          [][]string
	Service      []*dns.SRV        // header name contains e.g. "_http._tcp"
	Hostmaster   string            // "hostmaster@example.com"
	MX           []*dns.MX         // header name is left blank
	TLSA         []*dns.TLSA       // header name contains e.g. "_443._tcp"
	Map          map[string]*Value // may contain and "*", will not contain ""

	// set if the value is at the top level (alas necessary for relname interpretation)
	IsTopLevel bool
}

func (v *Value) RRs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	il := len(out)
	suffix = dns.Fqdn(suffix)
	apexSuffix = dns.Fqdn(apexSuffix)

	out, _ = v.appendNSs(out, suffix, apexSuffix)
	if len(v.NS) == 0 {
		out, _ = v.appendTranslate(out, suffix, apexSuffix)
		if !v.HasTranslate {
			out, _ = v.appendAlias(out, suffix, apexSuffix)
			if !v.HasAlias {
				out, _ = v.appendIPs(out, suffix, apexSuffix)
				out, _ = v.appendIP6s(out, suffix, apexSuffix)
				out, _ = v.appendTXTs(out, suffix, apexSuffix)
				out, _ = v.appendMXs(out, suffix, apexSuffix)
			}
			// SRV and TLSA records are assigned to a subdomain, but CNAMEs are not recursive so CNAME must not inhibit them
			out, _ = v.appendServices(out, suffix, apexSuffix)
			out, _ = v.appendTLSA(out, suffix, apexSuffix)
		}
	}
	out, _ = v.appendDSs(out, suffix, apexSuffix)

	xout := out[il:]
	for i := range xout {
		h := xout[i].Header()
		if rrtypeHasPrefix(h.Rrtype) {
			h.Name += "." + suffix
		} else {
			h.Name = suffix
		}
	}

	return out, nil
}

func rrtypeHasPrefix(t uint16) bool {
	return t == dns.TypeSRV || t == dns.TypeTLSA
}

func (v *Value) appendIPs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
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

func (v *Value) appendIP6s(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
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

func (v *Value) appendNSs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, ns := range v.NS {
		qn, ok := v.qualify(ns, suffix, apexSuffix)
		if !ok {
			continue
		}

		out = append(out, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			Ns: qn,
		})
	}

	return out, nil
}

func (v *Value) appendTXTs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
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

func (v *Value) appendDSs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, ds := range v.DS {
		out = append(out, ds)
	}

	return out, nil
}

func (v *Value) appendMXs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, mx := range v.MX {
		out = append(out, mx)
	}

	return out, nil
}

func (v *Value) appendServices(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, svc := range v.Service {
		out = append(out, svc)
	}

	return out, nil
}

func (v *Value) appendTLSA(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, tlsa := range v.TLSA {
		out = append(out, tlsa)
	}

	return out, nil
}

func (v *Value) appendAlias(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	if v.HasAlias {
		qn, ok := v.qualify(v.Alias, suffix, apexSuffix)
		if !ok {
			return out, fmt.Errorf("bad alias")
		}
		out = append(out, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			Target: qn,
		})
	}

	return out, nil
}

func (v *Value) appendTranslate(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	if v.HasTranslate {
		qn, ok := v.qualify(v.Translate, suffix, apexSuffix)
		if !ok {
			return out, fmt.Errorf("bad translate")
		}
		out = append(out, &dns.DNAME{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeDNAME,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			Target: qn,
		})
	}

	return out, nil
}

func (v *Value) RRsRecursive(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	out, err := v.RRs(out, suffix, apexSuffix)
	if err != nil {
		return nil, err
	}

	for mk, mv := range v.Map {
		if !validateLabel(mk) && mk != "" && mk != "*" {
			continue
		}

		out, err = mv.RRsRecursive(out, mk+"."+suffix, apexSuffix)
		//if err != nil {
		//	return nil, err
		//}
	}

	return out, nil
}

func (v *Value) findSubdomainByName(subdomain string) (*Value, error) {
	if subdomain == "" {
		return v, nil
	}

	if strings.HasSuffix(subdomain, ".") {
		return nil, fmt.Errorf("a subdomain name should not be fully qualified")
	}

	head, rest := util.SplitDomainHead(subdomain)

	if sub, ok := v.Map[head]; ok {
		return sub.findSubdomainByName(rest)
	}

	return nil, fmt.Errorf("subdomain part not found: %s", head)
}

type rawValue struct {
	IP         interface{} `json:"ip"`
	IP6        interface{} `json:"ip6"`
	NS         interface{} `json:"ns"`
	nsSet      map[string]struct{}
	DNS        interface{} `json:"dns"` // actually an alias for NS
	Alias      interface{} `json:"alias"`
	Translate  interface{} `json:"translate"`
	DS         interface{} `json:"ds"`
	TXT        interface{} `json:"txt"`
	Hostmaster interface{} `json:"email"` // Hostmaster
	MX         interface{} `json:"mx"`
	TLSA       interface{} `json:"tlsa"`

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
func ParseValue(name, jsonValue string, resolve ResolveFunc) (value *Value, err error) {
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

	mergedNames := map[string]struct{}{}
	mergedNames[name] = struct{}{}

	rv.parse(v, resolve, 0, 0, "", "", mergedNames)
	v.IsTopLevel = true

	value = v
	return
}

func (rv *rawValue) parse(v *Value, resolve ResolveFunc, depth, mergeDepth int, subdomain, relname string, mergedNames map[string]struct{}) error {
	if depth > depthLimit {
		return fmt.Errorf("depth limit exceeded")
	}

	realv := v
	if subdomain != "" {
		// substitute a dummy value. We will then parse everything into this, find the appropriate level and copy
		// the value to the argument value.
		v = &Value{}
	}

	ok, _ := rv.parseDelegate(v, resolve, depth, mergeDepth, relname, mergedNames)
	if ok {
		return nil
	}

	rv.parseImport(v, resolve, depth, mergeDepth, relname, mergedNames)
	rv.parseIP(v, rv.IP, false)
	rv.parseIP(v, rv.IP6, true)
	rv.parseNS(v, relname)
	rv.parseAlias(v, relname)
	rv.parseTranslate(v, relname)
	rv.parseHostmaster(v)
	rv.parseDS(v)
	rv.parseTXT(v)
	rv.parseService(v, relname)
	rv.parseMX(v, relname)
	rv.parseTLSA(v)
	rv.parseMap(v, resolve, depth, mergeDepth, relname)
	v.moveEmptyMapItems()

	if subdomain != "" {
		subv, err := v.findSubdomainByName(subdomain)
		if err != nil {
			return err
		}
		*realv = *subv
	}

	return nil
}

func (v *Value) qualifyIntl(name, suffix, apexSuffix string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}

	if !v.IsTopLevel {
		_, suffix = util.SplitDomainTail(suffix)
	}

	if name == "" {
		return suffix
	}

	if name == "@" {
		return apexSuffix
	}

	if strings.HasSuffix(name, ".@") {
		return name[0:len(name)-2] + "." + apexSuffix
	}

	return name + "." + suffix
}

func (v *Value) qualify(name, suffix, apexSuffix string) (string, bool) {
	s := v.qualifyIntl(name, suffix, apexSuffix)
	if !validateHostName(s) {
		return "", false
	}

	return s, true
}

func (rv *rawValue) parseMerge(mergeValue string, v *Value, resolve ResolveFunc, depth, mergeDepth int, subdomain, relname string, mergedNames map[string]struct{}) error {
	rv2 := &rawValue{}

	if mergeDepth > mergeDepthLimit {
		return fmt.Errorf("merge depth limit exceeded")
	}

	err := json.Unmarshal([]byte(mergeValue), rv2)
	if err != nil {
		return err
	}

	return rv2.parse(v, resolve, depth, mergeDepth, subdomain, relname, mergedNames)
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

func (rv *rawValue) parseNS(v *Value, relname string) error {
	// "dns" takes precedence
	if rv.DNS != nil {
		rv.NS = rv.DNS
	}

	if rv.NS == nil {
		return nil
	}

	v.NS = nil

	if rv.nsSet == nil {
		rv.nsSet = map[string]struct{}{}
	}

	switch rv.NS.(type) {
	case []interface{}:
		for _, si := range rv.NS.([]interface{}) {
			s, ok := si.(string)
			if !ok {
				continue
			}
			rv.addNS(v, s, relname)
		}
		return nil
	case string:
		s := rv.NS.(string)
		rv.addNS(v, s, relname)
		return nil
	default:
		return fmt.Errorf("unknown NS field format")
	}
}

func (rv *rawValue) addNS(v *Value, s, relname string) error {
	if _, ok := rv.nsSet[s]; !ok {
		v.NS = append(v.NS, s)
		rv.nsSet[s] = struct{}{}
	}

	return nil
}

func (rv *rawValue) parseAlias(v *Value, relname string) error {
	if rv.Alias == nil {
		return nil
	}

	if s, ok := rv.Alias.(string); ok {
		v.Alias = s
		v.HasAlias = true
		return nil
	}

	return fmt.Errorf("unknown alias field format")
}

func (rv *rawValue) parseTranslate(v *Value, relname string) error {
	if rv.Translate == nil {
		return nil
	}

	if s, ok := rv.Translate.(string); ok {
		v.Translate = s
		v.HasTranslate = true
		return nil
	}

	return fmt.Errorf("unknown translate field format")
}

func isAllArray(x []interface{}) bool {
	for _, v := range x {
		if _, ok := v.([]interface{}); !ok {
			return false
		}
	}
	return true
}

func isAllString(x []interface{}) bool {
	for _, v := range x {
		if _, ok := v.(string); !ok {
			return false
		}
	}
	return true
}

func (rv *rawValue) parseImportImpl(val *Value, resolve ResolveFunc, depth, mergeDepth int, relname string, mergedNames map[string]struct{}, delegate bool) (bool, error) {
	var err error
	succeeded := false
	src := rv.Import
	if delegate {
		src = rv.Delegate
	}

	if src == nil {
		return false, nil
	}

	if s, ok := src.(string); ok {
		src = []interface{}{s}
	}

	if a, ok := src.([]interface{}); ok {
		// [..., ..., ...]

		if isAllString(a) {
			// ["s/somedomain"]
			// ["s/somedomain", "sub.domain"]
			a = []interface{}{a}
		}

		if isAllArray(a) {
			// [ ["s/somedomain", "sub.domain"], ["s/somedomain", "sub.domain"] ]
			for _, vx := range a {
				v := vx.([]interface{})
				if len(v) != 1 && len(v) != 2 {
					continue
				}

				subs := ""
				if k, ok := v[0].(string); ok {
					if len(v) > 1 {
						if sub, ok := v[1].(string); ok {
							subs = sub
						}
					}

					// ok
					var dv string
					dv, err = resolve(k)
					if err != nil {
						continue
					}

					if _, ok := mergedNames[k]; ok {
						// already merged
						continue
					}

					mergedNames[k] = struct{}{}

					err = rv.parseMerge(dv, val, resolve, depth, mergeDepth+1, subs, relname, mergedNames)
					if err != nil {
						continue
					}

					succeeded = true
				}
			}
		}
		// malformed
	}

	if err == nil {
		err = fmt.Errorf("unknown import/delegate field format")
	}

	return succeeded, err
}

func (rv *rawValue) parseImport(v *Value, resolve ResolveFunc, depth, mergeDepth int, relname string, mergedNames map[string]struct{}) error {
	_, err := rv.parseImportImpl(v, resolve, depth, mergeDepth, relname, mergedNames, false)
	return err
}

func (rv *rawValue) parseDelegate(v *Value, resolve ResolveFunc, depth, mergeDepth int, relname string, mergedNames map[string]struct{}) (bool, error) {
	return rv.parseImportImpl(v, resolve, depth, mergeDepth, relname, mergedNames, true)
}

func (rv *rawValue) parseHostmaster(v *Value) error {
	if rv.Hostmaster == nil {
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

func (rv *rawValue) parseTLSA(v *Value) error {
	if rv.TLSA == nil {
		return nil
	}

	v.TLSA = nil

	if tlsaa, ok := rv.TLSA.([]interface{}); ok {
		for _, tlsa1 := range tlsaa {
			if tlsa, ok := tlsa1.([]interface{}); ok {
				// Format: ["443", "tcp", 1, 2, 3, "base64 certificate data"]
				if len(tlsa) < 6 {
					continue
				}

				ports, ok := tlsa[0].(string)
				if !ok {
					porti, ok := tlsa[0].(float64)
					if !ok {
						continue
					}
					ports = fmt.Sprintf("%d", int(porti))
				}

				transport, ok := tlsa[1].(string)
				if !ok {
					continue
				}

				a1, ok := tlsa[2].(float64)
				if !ok {
					continue
				}

				a2, ok := tlsa[3].(float64)
				if !ok {
					continue
				}

				a3, ok := tlsa[4].(float64)
				if !ok {
					continue
				}

				a4, ok := tlsa[5].(string)
				if !ok {
					continue
				}

				a4b, err := base64.StdEncoding.DecodeString(a4)
				if err != nil {
					continue
				}

				a4h := hex.EncodeToString(a4b)
				name := "_" + ports + "._" + transport

				v.TLSA = append(v.TLSA, &dns.TLSA{
					Hdr:          dns.RR_Header{Name: name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 600},
					Usage:        uint8(a1),
					Selector:     uint8(a2),
					MatchingType: uint8(a3),
					Certificate:  strings.ToUpper(a4h),
				})
			}
		}
	}

	return fmt.Errorf("malformed TLSA field format")
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
					if xs, ok := x.(string); ok && len(xs) <= 255 {
						a = append(a, xs)
					}
				}
				if len(a) > 0 {
					v.TXT = append(v.TXT, a)
				}
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

	// Make sure the content of each TXT record does not exceed 65535 bytes.
	for i := range v.TXT {
		for {
			L := 0

			for j := range v.TXT[i] {
				L += len(v.TXT[i][j]) + 1
			}

			if L <= 65535 {
				break
			}

			// Pop segments until under the limit.
			v.TXT[i] = v.TXT[i][0 : len(v.TXT[i])-1]
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

func (rv *rawValue) parseMX(v *Value, relname string) error {
	if rv.MX == nil {
		return nil
	}

	if sa, ok := rv.MX.([]interface{}); ok {
		for _, s := range sa {
			rv.parseSingleMX(s, v, relname)
		}
	}

	return fmt.Errorf("malformed MX value")
}

func (rv *rawValue) parseSingleMX(s interface{}, v *Value, relname string) error {
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
	if !ok {
		return fmt.Errorf("malformed MX value")
	}

	v.MX = append(v.MX, &dns.MX{
		Hdr:        dns.RR_Header{Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 600},
		Preference: uint16(prio),
		Mx:         hostname,
	})

	return nil
}

func (rv *rawValue) parseService(v *Value, relname string) error {
	if rv.Service == nil {
		return nil
	}

	// We have to merge the services specified and those imported using an
	// import statement.
	servicesUsed := map[string]struct{}{}
	oldServices := v.Service
	v.Service = nil

	if sa, ok := rv.Service.([]interface{}); ok {
		for _, s := range sa {
			rv.parseSingleService(s, v, relname, servicesUsed)
		}
	}

	for _, svc := range oldServices {
		if _, ok := servicesUsed[svc.Header().Name]; !ok {
			v.Service = append(v.Service, svc)
		}
	}

	return fmt.Errorf("malformed service value")
}

func (rv *rawValue) parseSingleService(svc interface{}, v *Value, relname string, servicesUsed map[string]struct{}) error {
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
	if !ok {
		return fmt.Errorf("malformed service value")
	}

	sname := "_" + appProtoName + "._" + transportProtoName
	servicesUsed[sname] = struct{}{}

	v.Service = append(v.Service, &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   sname,
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

func (rv *rawValue) parseMap(v *Value, resolve ResolveFunc, depth, mergeDepth int, relname string) error {
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

		mergedNames := map[string]struct{}{}
		rv2.parse(v2, resolve, depth+1, mergeDepth, "", relname, mergedNames)

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

// This is used to validate NS records, targets in SRV records, etc. In these cases
// an IP address is not allowed. Therefore this regex must exclude all-numeric domain names.
// This is done by requiring the final part to start with an alphabetic character.
var re_hostName = regexp.MustCompilePOSIX(`^(([a-z0-9_][a-z0-9_-]{0,62}\.)*[a-z_][a-z0-9_-]{0,62}\.?|\.)$`)
var re_serviceName = regexp.MustCompilePOSIX(`^[a-z_][a-z0-9_-]*$`)
var re_label = regexp.MustCompilePOSIX(`^[a-z0-9_][a-z0-9_-]*$`)

func validateHostName(name string) bool {
	name = dns.Fqdn(name)
	return len(name) <= 255 && re_hostName.MatchString(name)
}

func validateServiceName(name string) bool {
	return len(name) < 63 && re_serviceName.MatchString(name)
}

func validateLabel(name string) bool {
	return len(name) <= 63 && re_label.MatchString(name)
}

func validateEmail(email string) bool {
	addr, err := mail.ParseAddress(email)
	if addr == nil || err != nil {
		return false
	}
	return addr.Name == ""
}
