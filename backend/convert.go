package backend

/*
import "github.com/miekg/dns"
import "net"
import "regexp"

// Experimental attempt to factor out the JSON->DNS conversion function.
// Currently used only by namesync, not ncdns.

// suffix: Used to form the RRs. e.g. "example.bit."
// jsonValue: the name's JSON value string.
func Convert(suffix string, jsonValue string) ([]dns.RR, error) {
	d, err := jsonToDomain(jsonValue)
	if err != nil {
		return nil, err
	}

	rootNCV := d.ncv
	rrs := convertRecursive(nil, suffix, rootNCV, 0)

	return rrs, nil
}

// Try and tolerate errors.
func convertRecursive(out []dns.RR, suffix string, ncv *ncValue, depth int) []dns.RR {
	if depth > 64 {
		return out
	}

	out = convertAt(out, suffix, ncv)

	for k, v := range ncv.Map {
		subsuffix := k + "." + suffix
		if k == "" {
			subsuffix = suffix
		}
		out = convertRecursive(out, subsuffix, v, depth+1)
	}

	return out
}

// Conversion at a specific NCV non-recursivey for all types

func convertAt(out []dns.RR, suffix string, ncv *ncValue) []dns.RR {
	return convertAt_(out, suffix, ncv, 0)
}

func convertAt_(out []dns.RR, suffix string, ncv *ncValue, depth int) []dns.RR {
	if depth > 1 {
		return out
	}

	out = convertIPs(out, suffix, ncv)
	out = convertIP6s(out, suffix, ncv)
	out = convertNSs(out, suffix, ncv)
	out = convertDSs(out, suffix, ncv)
	out = convertTXTs(out, suffix, ncv)

	// XXX: should this apply only if no records were added above?
	if m, ok := ncv.Map[""]; ok {
		out = convertAt_(out, suffix, m, depth+1)
	}

	// TODO: CNAME
	// TODO: MX
	// TODO: SRV
	return out
}

// Conversion at a specific NCV non-recursively for specific types

func convertIPs(out []dns.RR, suffix string, ncv *ncValue) []dns.RR {
	ips, err := ncv.GetIPs()
	if err != nil {
		return out
	}

	for _, ip := range ips {
		pip := net.ParseIP(ip)
		if pip == nil || pip.To4() == nil {
			continue
		}

		out = append(out, &dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(suffix), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
			A:   pip,
		})
	}

	return out
}

func convertIP6s(out []dns.RR, suffix string, ncv *ncValue) []dns.RR {
	ips, err := ncv.GetIP6s()
	if err != nil {
		return out
	}

	for _, ip := range ips {
		pip := net.ParseIP(ip)
		if pip == nil || pip.To4() != nil {
			continue
		}

		out = append(out, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: dns.Fqdn(suffix), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 600},
			AAAA: pip,
		})
	}

	return out
}

func convertNSs(out []dns.RR, suffix string, ncv *ncValue) []dns.RR {
	nss, err := ncv.GetNSs()
	if err != nil {
		return out
	}

	for _, ns := range nss {
		if !validateHostName(ns) {
			continue
		}

		ns = dns.Fqdn(ns)
		out = append(out, &dns.NS{
			Hdr: dns.RR_Header{Name: dns.Fqdn(suffix), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 600},
			Ns:  ns,
		})
	}

	return out
}

func convertTXTs(out []dns.RR, suffix string, ncv *ncValue) []dns.RR {
	txts, err := ncv.GetTXTs()
	if err != nil {
		return out
	}

	for _, txt := range txts {
		out = append(out, &dns.TXT{
			Hdr: dns.RR_Header{Name: dns.Fqdn(suffix), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 600},
			Txt: txt,
		})
	}

	return out
}

func convertDSs(out []dns.RR, suffix string, ncv *ncValue) []dns.RR {
	dss, err := ncv.GetDSs()
	if err != nil {
		return out
	}

	for i := range dss {
		dss[i].Hdr.Name = dns.Fqdn(suffix)
		out = append(out, &dss[i])
	}

	return out
}

// Validation functions

var re_hostName = regexp.MustCompilePOSIX(`^([a-z0-9_-]+\.)*[a-z0-9_-]+\.?$`)

func validateHostName(name string) bool {
	name = dns.Fqdn(name)
	return len(name) <= 255 && re_hostName.MatchString(name)
}*/
