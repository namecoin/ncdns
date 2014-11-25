package backend

import "github.com/miekg/dns"
import "net"

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
	rrs := convertRecursive(suffix, rootNCV, 0)

	return rrs, nil
}

// Try and tolerate errors.
func convertRecursive(suffix string, ncv *ncValue, depth int) (rrs []dns.RR) {
	if depth > 64 {
		return
	}

	rrs = append(rrs, convertIPs(suffix, ncv)...)
	rrs = append(rrs, convertIP6s(suffix, ncv)...)
	//rrs = append(rrs, ...convertServices(suffix, ncv))
	//rrs = append(rrs, ...convertAlias(suffix, ncv))
	rrs = append(rrs, convertNSs(suffix, ncv)...)

	for k, v := range ncv.Map {
		subsuffix := k + "." + suffix
		if k == "" {
			subsuffix = suffix
		}
		rrs = append(rrs, convertRecursive(subsuffix, v, depth+1)...)
	}

	rrs = append(rrs, convertDSs(suffix, ncv)...)
	//rrs = append(rrs, ...convertTXT(suffix, ncv))
	return
}

func convertIPs(suffix string, ncv *ncValue) (rrs []dns.RR) {
	ips, err := ncv.GetIPs()
	if err != nil {
		return
	}

	for _, ip := range ips {
		pip := net.ParseIP(ip)
		if pip == nil || pip.To4() == nil {
			continue
		}

		rrs = append(rrs, &dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(suffix), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
			A:   pip,
		})
	}

	return
}

func convertIP6s(suffix string, ncv *ncValue) (rrs []dns.RR) {
	ips, err := ncv.GetIP6s()
	if err != nil {
		return
	}

	for _, ip := range ips {
		pip := net.ParseIP(ip)
		if pip == nil || pip.To4() != nil {
			continue
		}

		rrs = append(rrs, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: dns.Fqdn(suffix), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 600},
			AAAA: pip,
		})
	}

	return
}

func convertNSs(suffix string, ncv *ncValue) (rrs []dns.RR) {
	nss, err := ncv.GetNSs()
	if err != nil {
		return
	}

	for _, ns := range nss {
		ns = dns.Fqdn(ns)
		rrs = append(rrs, &dns.NS{
			Hdr: dns.RR_Header{Name: dns.Fqdn(suffix), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 600},
			Ns:  ns,
		})
	}

	return
}

func convertDSs(suffix string, ncv *ncValue) (rrs []dns.RR) {
	dss, err := ncv.GetDSs()
	if err != nil {
		return
	}

	for i := range dss {
		dss[i].Hdr.Name = dns.Fqdn(suffix)
		rrs = append(rrs, &dss[i])
	}

	return
}
