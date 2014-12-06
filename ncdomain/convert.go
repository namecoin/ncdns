package ncdomain

import "encoding/json"
import "net"
import "fmt"
import "github.com/miekg/dns"
import "encoding/base64"
import "encoding/hex"
import "github.com/hlandau/ncdns/util"
import "strings"

const depthLimit = 16
const mergeDepthLimit = 4
const defaultTTL = 600

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

func (v *Value) mkString(i string) string {
	s := i[1:] + "Value:"
	i += "  "
	if v.HasAlias {
		s += i + "CNAME: \"" + v.Alias + "\""
	}
	if v.HasTranslate {
		s += i + "DNAME: \"" + v.Translate + "\""
	}
	if v.Hostmaster != "" {
		s += i + "Hostmaster: " + v.Hostmaster
	}
	for _, ip := range v.IP {
		s += i + "IPv4 Address: " + ip.String()
	}
	for _, ip := range v.IP6 {
		s += i + "IPv6 Address: " + ip.String()
	}
	for _, ns := range v.NS {
		s += i + "Nameserver: " + ns
	}
	for _, ds := range v.DS {
		s += i + "DS Record: " + ds.String()
	}
	for _, txt := range v.TXT {
		s += i + "TXT Record:"
		for _, txtc := range txt {
			s += i + "  " + txtc
		}
	}
	for _, srv := range v.Service {
		s += i + "SRV Record: " + srv.String()
	}
	for _, tlsa := range v.TLSA {
		s += i + "TLSA Record: " + tlsa.String()
	}
	if len(v.Map) > 0 {
		s += i + "Subdomains:"
		for k, v := range v.Map {
			s += i + "  " + k + ":"
			s += v.mkString(i + "    ")
		}
	}
	return s
}

func (v *Value) String() string {
	return v.mkString("\n")
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
				Ttl:    defaultTTL,
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
				Ttl:    defaultTTL,
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
				Ttl:    defaultTTL,
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
				Ttl:    defaultTTL,
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
				Ttl:    defaultTTL,
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
				Ttl:    defaultTTL,
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
		if !util.ValidateLabel(mk) && mk != "" && mk != "*" {
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
type ErrorFunc func(err error, isWarning bool)

func (ef ErrorFunc) add(err error) {
	if ef != nil && err != nil {
		ef(err, false)
	}
}

func (ef ErrorFunc) addWarning(err error) {
	if ef != nil && err != nil {
		ef(err, true)
	}
}

// Call to convert a given JSON value to a parsed Namecoin domain value.
//
// If ResolveFunc is given, it will be called to obtain the values for domains
// referenced by "import" and "delegate" statements. The name passed is in
// Namecoin form (e.g. "d/example"). The JSON value or an error should be
// returned. If no ResolveFunc is passed, "import" and "delegate" statements
// always fail.
//
// Returns nil if the JSON could not be parsed. For all other errors processing
// continues and recovers as much as possible; errFunc is called for all errors
// and warnings if specified.
func ParseValue(name, jsonValue string, resolve ResolveFunc, errFunc ErrorFunc) (value *Value) {
	rv := &rawValue{}
	v := &Value{}

	err := json.Unmarshal([]byte(jsonValue), rv)
	if err != nil {
		errFunc.add(err)
		return
	}

	if resolve == nil {
		resolve = func(name string) (string, error) {
			return "", fmt.Errorf("not supported")
		}
	}

	mergedNames := map[string]struct{}{}
	mergedNames[name] = struct{}{}

	rv.parse(v, resolve, errFunc, 0, 0, "", "", mergedNames)
	v.IsTopLevel = true

	value = v
	return
}

func (rv *rawValue) parse(v *Value, resolve ResolveFunc, errFunc ErrorFunc, depth, mergeDepth int, subdomain, relname string, mergedNames map[string]struct{}) {
	if depth > depthLimit {
		errFunc.add(fmt.Errorf("depth limit exceeded"))
		return
	}

	realv := v
	if subdomain != "" {
		// substitute a dummy value. We will then parse everything into this, find the appropriate level and copy
		// the value to the argument value.
		v = &Value{}
	}

	ok, _ := rv.parseDelegate(v, resolve, errFunc, depth, mergeDepth, relname, mergedNames)
	if ok {
		return
	}

	rv.parseImport(v, resolve, errFunc, depth, mergeDepth, relname, mergedNames)
	rv.parseIP(v, errFunc, rv.IP, false)
	rv.parseIP(v, errFunc, rv.IP6, true)
	rv.parseNS(v, errFunc, relname)
	rv.parseAlias(v, errFunc, relname)
	rv.parseTranslate(v, errFunc, relname)
	rv.parseHostmaster(v, errFunc)
	rv.parseDS(v, errFunc)
	rv.parseTXT(v, errFunc)
	rv.parseService(v, errFunc, relname)
	rv.parseMX(v, errFunc, relname)
	rv.parseTLSA(v, errFunc)
	rv.parseMap(v, resolve, errFunc, depth, mergeDepth, relname)
	v.moveEmptyMapItems()

	if subdomain != "" {
		subv, err := v.findSubdomainByName(subdomain)
		if err != nil {
			errFunc.add(fmt.Errorf("couldn't find subdomain by name in import or delegate item: %v", err))
			return
		}
		*realv = *subv
	}
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
	if !util.ValidateHostName(s) {
		return "", false
	}

	return s, true
}

func (rv *rawValue) parseMerge(mergeValue string, v *Value, resolve ResolveFunc, errFunc ErrorFunc, depth, mergeDepth int, subdomain, relname string, mergedNames map[string]struct{}) error {
	rv2 := &rawValue{}

	if mergeDepth > mergeDepthLimit {
		err := fmt.Errorf("merge depth limit exceeded")
		errFunc.add(err)
		return err
	}

	err := json.Unmarshal([]byte(mergeValue), rv2)
	if err != nil {
		err = fmt.Errorf("couldn't parse JSON to be merged: %v", err)
		errFunc.add(err)
		return err
	}

	rv2.parse(v, resolve, errFunc, depth, mergeDepth, subdomain, relname, mergedNames)
	return nil
}

func (rv *rawValue) parseIP(v *Value, errFunc ErrorFunc, ipi interface{}, ipv6 bool) {
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
				rv.addIP(v, errFunc, ips, ipv6)
			}
		}

		return
	}

	if ip, ok := ipi.(string); ok {
		rv.addIP(v, errFunc, ip, ipv6)
	}
}

func (rv *rawValue) addIP(v *Value, errFunc ErrorFunc, ips string, ipv6 bool) {
	pip := net.ParseIP(ips)
	if pip == nil || (pip.To4() == nil) != ipv6 {
		errFunc.add(fmt.Errorf("malformed IP: %s", ips))
		return
	}

	if ipv6 {
		v.IP6 = append(v.IP6, pip)
	} else {
		v.IP = append(v.IP, pip)
	}
}

func (rv *rawValue) parseNS(v *Value, errFunc ErrorFunc, relname string) {
	// "dns" takes precedence
	if rv.DNS != nil {
		rv.NS = rv.DNS
	}

	if rv.NS == nil {
		return
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
		return
	case string:
		s := rv.NS.(string)
		rv.addNS(v, s, relname)
		return
	default:
		errFunc.add(fmt.Errorf("unknown NS field format"))
	}
}

func (rv *rawValue) addNS(v *Value, s, relname string) {
	if _, ok := rv.nsSet[s]; !ok {
		v.NS = append(v.NS, s)
		rv.nsSet[s] = struct{}{}
	}
}

func (rv *rawValue) parseAlias(v *Value, errFunc ErrorFunc, relname string) {
	if rv.Alias == nil {
		return
	}

	if s, ok := rv.Alias.(string); ok {
		v.Alias = s
		v.HasAlias = true
		return
	}

	errFunc.add(fmt.Errorf("unknown alias field format"))
}

func (rv *rawValue) parseTranslate(v *Value, errFunc ErrorFunc, relname string) {
	if rv.Translate == nil {
		return
	}

	if s, ok := rv.Translate.(string); ok {
		v.Translate = s
		v.HasTranslate = true
		return
	}

	errFunc.add(fmt.Errorf("unknown translate field format"))
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

func (rv *rawValue) parseImportImpl(val *Value, resolve ResolveFunc, errFunc ErrorFunc, depth, mergeDepth int, relname string, mergedNames map[string]struct{}, delegate bool) (bool, error) {
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

					err = rv.parseMerge(dv, val, resolve, errFunc, depth, mergeDepth+1, subs, relname, mergedNames)
					if err != nil {
						errFunc.add(err)
						continue
					}

					succeeded = true
				}
			}

			// ...
			return succeeded, nil
		}
		// malformed
	}

	if err == nil {
		err = fmt.Errorf("unknown import/delegate field format")
	}

	errFunc.add(err)

	return succeeded, err
}

func (rv *rawValue) parseImport(v *Value, resolve ResolveFunc, errFunc ErrorFunc, depth, mergeDepth int, relname string, mergedNames map[string]struct{}) error {
	_, err := rv.parseImportImpl(v, resolve, errFunc, depth, mergeDepth, relname, mergedNames, false)
	return err
}

func (rv *rawValue) parseDelegate(v *Value, resolve ResolveFunc, errFunc ErrorFunc, depth, mergeDepth int, relname string, mergedNames map[string]struct{}) (bool, error) {
	return rv.parseImportImpl(v, resolve, errFunc, depth, mergeDepth, relname, mergedNames, true)
}

func (rv *rawValue) parseHostmaster(v *Value, errFunc ErrorFunc) {
	if rv.Hostmaster == nil {
		return
	}

	if s, ok := rv.Hostmaster.(string); ok {
		if !util.ValidateEmail(s) {
			errFunc.add(fmt.Errorf("malformed e. mail address in email field"))
			return
		}

		v.Hostmaster = s
		return
	}

	errFunc.add(fmt.Errorf("unknown email field format"))
}

func (rv *rawValue) parseDS(v *Value, errFunc ErrorFunc) {
	if rv.DS == nil {
		return
	}

	v.DS = nil

	if dsa, ok := rv.DS.([]interface{}); ok {
		for _, ds1 := range dsa {
			if ds, ok := ds1.([]interface{}); ok {
				if len(ds) < 4 {
					errFunc.add(fmt.Errorf("DS item must have four items"))
					continue
				}

				a1, ok := ds[0].(float64)
				if !ok {
					errFunc.add(fmt.Errorf("First item in DS value must be an integer (key tag)"))
					continue
				}

				a2, ok := ds[1].(float64)
				if !ok {
					errFunc.add(fmt.Errorf("Second item in DS value must be an integer (algorithm)"))
					continue
				}

				a3, ok := ds[2].(float64)
				if !ok {
					errFunc.add(fmt.Errorf("Third item in DS value must be an integer (digest type)"))
					continue
				}

				a4, ok := ds[3].(string)
				if !ok {
					errFunc.add(fmt.Errorf("Fourth item in DS value must be a string (digest)"))
					continue
				}

				a4b, err := base64.StdEncoding.DecodeString(a4)
				if err != nil {
					errFunc.add(fmt.Errorf("Fourth item in DS value must be valid base64: %v", err))
					continue
				}

				a4h := hex.EncodeToString(a4b)
				v.DS = append(v.DS, &dns.DS{
					Hdr:        dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: defaultTTL},
					KeyTag:     uint16(a1),
					Algorithm:  uint8(a2),
					DigestType: uint8(a3),
					Digest:     a4h,
				})
			} else {
				errFunc.add(fmt.Errorf("DS item must be an array"))
			}
		}
		return
	}

	errFunc.add(fmt.Errorf("malformed DS field format"))
}

func (rv *rawValue) parseTLSA(v *Value, errFunc ErrorFunc) {
	if rv.TLSA == nil {
		return
	}

	v.TLSA = nil

	if tlsaa, ok := rv.TLSA.([]interface{}); ok {
		for _, tlsa1 := range tlsaa {
			if tlsa, ok := tlsa1.([]interface{}); ok {
				// Format: ["443", "tcp", 1, 2, 3, "base64 certificate data"]
				if len(tlsa) < 6 {
					errFunc.add(fmt.Errorf("TLSA item must have six items"))
					continue
				}

				ports, ok := tlsa[0].(string)
				if !ok {
					porti, ok := tlsa[0].(float64)
					if !ok {
						errFunc.add(fmt.Errorf("First item in TLSA value must be an integer or string (port number)"))
						continue
					}
					ports = fmt.Sprintf("%d", int(porti))
				}

				transport, ok := tlsa[1].(string)
				if !ok {
					errFunc.add(fmt.Errorf("Second item in TLSA value must be a string (transport protocol name)"))
					continue
				}

				a1, ok := tlsa[2].(float64)
				if !ok {
					errFunc.add(fmt.Errorf("Third item in TLSA value must be an integer (usage)"))
					continue
				}

				a2, ok := tlsa[3].(float64)
				if !ok {
					errFunc.add(fmt.Errorf("Fourth item in TLSA value must be an integer (selector)"))
					continue
				}

				a3, ok := tlsa[4].(float64)
				if !ok {
					errFunc.add(fmt.Errorf("Fifth item in TLSA value must be an integer (match type)"))
					continue
				}

				a4, ok := tlsa[5].(string)
				if !ok {
					errFunc.add(fmt.Errorf("Sixth item in TLSA value must be a string (certificate)"))
					continue
				}

				a4b, err := base64.StdEncoding.DecodeString(a4)
				if err != nil {
					errFunc.add(fmt.Errorf("Fourth item in DS value must be valid base64: %v", err))
					continue
				}

				if len(ports) > 62 || len(transport) > 62 {
					errFunc.add(fmt.Errorf("Application and transport names must not exceed 62 characters"))
					continue
				}

				a4h := hex.EncodeToString(a4b)
				name := "_" + ports + "._" + transport

				v.TLSA = append(v.TLSA, &dns.TLSA{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET,
						Ttl: defaultTTL},
					Usage:        uint8(a1),
					Selector:     uint8(a2),
					MatchingType: uint8(a3),
					Certificate:  strings.ToUpper(a4h),
				})
			} else {
				errFunc.add(fmt.Errorf("TLSA item must be an array"))
			}
		}
		return
	}

	errFunc.add(fmt.Errorf("Malformed TLSA field format"))
}

func (rv *rawValue) parseTXT(v *Value, errFunc ErrorFunc) {
	if rv.TXT == nil {
		return
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
				errFunc.add(fmt.Errorf("malformed TXT value"))
				return
			}
		}
	} else {
		// "..."
		if s, ok := rv.TXT.(string); ok {
			v.TXT = append(v.TXT, segmentizeTXT(s))
		} else {
			errFunc.add(fmt.Errorf("malformed TXT value"))
			return
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

	return
}

func segmentizeTXT(txt string) (a []string) {
	for len(txt) > 255 {
		a = append(a, txt[0:255])
		txt = txt[255:]
	}
	a = append(a, txt)
	return
}

func (rv *rawValue) parseMX(v *Value, errFunc ErrorFunc, relname string) {
	if rv.MX == nil {
		return
	}

	if sa, ok := rv.MX.([]interface{}); ok {
		for _, s := range sa {
			rv.parseSingleMX(s, v, errFunc, relname)
		}
		return
	}

	errFunc.add(fmt.Errorf("malformed MX value"))
}

func (rv *rawValue) parseSingleMX(s interface{}, v *Value, errFunc ErrorFunc, relname string) {
	sa, ok := s.([]interface{})
	if !ok {
		errFunc.add(fmt.Errorf("malformed MX value"))
		return
	}

	if len(sa) < 2 {
		errFunc.add(fmt.Errorf("malformed MX value"))
		return
	}

	prio, ok := sa[0].(float64)
	if !ok || prio < 0 {
		errFunc.add(fmt.Errorf("malformed MX value"))
		return
	}

	hostname, ok := sa[1].(string)
	if !ok {
		errFunc.add(fmt.Errorf("malformed MX value"))
		return
	}

	v.MX = append(v.MX, &dns.MX{
		Hdr:        dns.RR_Header{Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: defaultTTL},
		Preference: uint16(prio),
		Mx:         hostname,
	})

	return
}

func (rv *rawValue) parseService(v *Value, errFunc ErrorFunc, relname string) {
	if rv.Service == nil {
		return
	}

	// We have to merge the services specified and those imported using an
	// import statement.
	servicesUsed := map[string]struct{}{}
	oldServices := v.Service
	v.Service = nil

	if sa, ok := rv.Service.([]interface{}); ok {
		for _, s := range sa {
			rv.parseSingleService(s, v, errFunc, relname, servicesUsed)
		}
	} else {
		errFunc.add(fmt.Errorf("malformed service value"))
	}

	for _, svc := range oldServices {
		if _, ok := servicesUsed[svc.Header().Name]; !ok {
			v.Service = append(v.Service, svc)
		}
	}
}

func (rv *rawValue) parseSingleService(svc interface{}, v *Value, errFunc ErrorFunc, relname string, servicesUsed map[string]struct{}) {
	svca, ok := svc.([]interface{})
	if !ok {
		errFunc.add(fmt.Errorf("malformed service value"))
		return
	}

	if len(svca) < 6 {
		errFunc.add(fmt.Errorf("malformed service value: must have six items"))
		return
	}

	appProtoName, ok := svca[0].(string)
	if !ok || !util.ValidateServiceName(appProtoName) {
		errFunc.add(fmt.Errorf("malformed service value: first item must be a string (application protocol)"))
		return
	}

	transportProtoName, ok := svca[1].(string)
	if !ok || !util.ValidateServiceName(transportProtoName) {
		errFunc.add(fmt.Errorf("malformed service value: second item must be a string (transport protocol)"))
		return
	}

	priority, ok := svca[2].(float64)
	if !ok {
		errFunc.add(fmt.Errorf("malformed service value: third item must be an integer (priority)"))
		return
	}

	weight, ok := svca[3].(float64)
	if !ok {
		errFunc.add(fmt.Errorf("malformed service value: fourth item must be an integer (weight)"))
		return
	}

	port, ok := svca[4].(float64)
	if !ok {
		errFunc.add(fmt.Errorf("malformed service value: fifth item must be an integer (port number)"))
		return
	}

	hostname, ok := svca[5].(string)
	if !ok {
		errFunc.add(fmt.Errorf("malformed service value: sixth item must be a string (target)"))
		return
	}

	sname := "_" + appProtoName + "._" + transportProtoName
	servicesUsed[sname] = struct{}{}

	v.Service = append(v.Service, &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   sname,
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    defaultTTL,
		},
		Priority: uint16(priority),
		Weight:   uint16(weight),
		Port:     uint16(port),
		Target:   hostname,
	})

	return
}

func (rv *rawValue) parseMap(v *Value, resolve ResolveFunc, errFunc ErrorFunc, depth, mergeDepth int, relname string) {
	if rv.Map == nil {
		return
	}

	m := map[string]json.RawMessage{}

	err := json.Unmarshal(rv.Map, &m)
	if err != nil {
		errFunc.add(fmt.Errorf("Couldn't unmarshal map: %v", err))
		return
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
				errFunc.add(fmt.Errorf("Couldn't unmarshal map: %v", err))
				continue
			}
		}

		mergedNames := map[string]struct{}{}
		rv2.parse(v2, resolve, errFunc, depth+1, mergeDepth, "", relname, mergedNames)

		if v.Map == nil {
			v.Map = make(map[string]*Value)
		}

		v.Map[mk] = v2
	}
}

// Moves items in {"map": {"": ...}} to the object itself, then deletes the ""
// entry in the map object.
func (v *Value) moveEmptyMapItems() {
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
}
