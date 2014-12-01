package backend

import "github.com/golang/groupcache/lru"
import "github.com/miekg/dns"
import "github.com/hlandau/degoutils/log"
import "fmt"
import "strings"
import "net"
import "github.com/hlandau/ncdns/namecoin"
import "github.com/hlandau/madns/merr"
import "github.com/hlandau/ncdns/util"
import "github.com/hlandau/ncdns/ncdomain"
import "sync"

// Provides an abstract zone file for the Namecoin .bit TLD.
type Backend struct {
	//s *Server
	nc         namecoin.Conn
	cache      lru.Cache // items are of type *Domain
	cacheMutex sync.Mutex
	cfg        Config
}

const (
	defaultMaxEntries = 100
)

// Backend configuration.
type Config struct {
	// Username and password to use for connecting to the Namecoin JSON-RPC interface.
	RPCUsername string
	RPCPassword string

	// hostname:port to use for connecting to the Namecoin JSON-RPC interface.
	RPCAddress string

	// Maximum entries to permit in name cache. If zero, a default value is used.
	CacheMaxEntries int

	// The hostname which should be advertised as the primary nameserver for the zone.
	// If left empty, a psuedo-hostname resolvable to SelfIP is used.
	SelfName string

	// Used only if SelfName is left blank. An IP which the internal psuedo-hostname
	// should resolve to. This should be the public IP of the nameserver serving the
	// zone expressed by this backend.
	SelfIP string

	// Map names (like "d/example") to strings containing JSON values. Used to provide
	// fake names for testing purposes. You don't need to use this.
	FakeNames map[string]string
}

// Creates a new Namecoin backend.
func New(cfg *Config) (backend *Backend, err error) {
	b := &Backend{}

	b.cfg = *cfg
	b.nc.Username = cfg.RPCUsername
	b.nc.Password = cfg.RPCPassword
	b.nc.Server = cfg.RPCAddress

	b.cache.MaxEntries = cfg.CacheMaxEntries
	if b.cache.MaxEntries == 0 {
		b.cache.MaxEntries = defaultMaxEntries
	}

	if b.cfg.FakeNames == nil {
		b.cfg.FakeNames = map[string]string{}
	}

	backend = b

	return
}

// Keep domains in parsed format.
type domain struct {
	ncv *ncdomain.Value
}

func toNamecoinName(basename string) (string, error) {
	return "d/" + basename, nil
}

func (b *Backend) getNamecoinEntry(name string) (*domain, error) {
	d := b.getNamecoinEntryCache(name)
	if d != nil {
		return d, nil
	}

	d, err := b.getNamecoinEntryLL(name)
	if err != nil {
		return nil, err
	}

	b.addNamecoinEntryToCache(name, d)
	return d, nil
}

func (b *Backend) getNamecoinEntryCache(name string) *domain {
	b.cacheMutex.Lock()
	defer b.cacheMutex.Unlock()

	if dd, ok := b.cache.Get(name); ok {
		d := dd.(*domain)
		return d
	}

	return nil
}

func (b *Backend) addNamecoinEntryToCache(name string, d *domain) {
	b.cacheMutex.Lock()
	defer b.cacheMutex.Unlock()

	b.cache.Add(name, d)
}

func (b *Backend) resolveName(name string) (jsonValue string, err error) {
	if fv, ok := b.cfg.FakeNames[name]; ok {
		if fv == "NX" {
			return "", merr.ErrNoSuchDomain
		}
		return fv, nil
	}

	v, err := b.nc.Query(name)
	if err != nil {
		return "", err
	}

	return v, nil
}

func (b *Backend) getNamecoinEntryLL(name string) (*domain, error) {
	v, err := b.resolveName(name)
	if err != nil {
		return nil, err
	}

	log.Info("namecoin query (", name, ") succeeded: ", v)

	d, err := b.jsonToDomain(name, v)
	if err != nil {
		log.Infoe(err, "cannot convert JSON to domain")
		return nil, err
	}

	return d, nil
}

func (b *Backend) jsonToDomain(name, jsonValue string) (*domain, error) {
	d := &domain{}

	v, err := ncdomain.ParseValue(name, jsonValue, b.resolveExtraName)
	if err != nil {
		return nil, err
	}

	d.ncv = v

	return d, nil
}

func (b *Backend) resolveExtraName(name string) (jsonValue string, err error) {
	return b.resolveName(name)
}

type btx struct {
	b     *Backend
	qname string

	subname, basename, rootname string
}

func (tx *btx) determineDomain() (subname, basename, rootname string, err error) {
	qname := tx.qname
	qname = strings.TrimRight(qname, ".")
	parts := strings.Split(qname, ".")
	if len(parts) < 2 {
		if parts[0] != "bit" {
			err = merr.ErrNotInZone
			return
		}

		rootname = parts[0]
		return
	}

	for i := len(parts) - 1; i >= 0; i-- {
		v := parts[i]

		// scanning for rootname
		if v == "bit" {
			if i == 0 {
				// i is already zero, so we have something like bit.x.y.z.
				rootname = qname
				return
			}
			rootname = strings.Join(parts[i:len(parts)], ".")
			basename = parts[i-1]
			subname = strings.Join(parts[0:i-1], ".")
			return
		}
	}

	err = merr.ErrNotInZone
	return
}

func (tx *btx) Do() (rrs []dns.RR, err error) {
	tx.subname, tx.basename, tx.rootname, err = tx.determineDomain()
	if err != nil {
		log.Infoe(err, "couldn't determine domain")
		return
	}

	log.Info("domain:  sub=", tx.subname, "  basename=", tx.basename, "  rootname=", tx.rootname)

	if tx.rootname == "" {
		// REFUSED
		return nil, merr.ErrNotInZone
	}

	if tx.subname == "" && tx.basename == "" {
		return tx.doRootDomain()
	}

	if tx.basename == "x--nmc" && tx.b.cfg.SelfName == "" {
		return tx.doMetaDomain()
	}

	rrs, err = tx.doUserDomain()

	log.Info("USER RECORDS YIELDED:")
	for _, rr := range rrs {
		log.Info("    ", rr.String())
	}

	return
}

func (tx *btx) doRootDomain() (rrs []dns.RR, err error) {
	nsname := tx.b.cfg.SelfName
	if nsname == "" {
		nsname = "this.x--nmc." + tx.rootname
	}

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(tx.rootname),
			Ttl:    86400,
			Class:  dns.ClassINET,
			Rrtype: dns.TypeSOA,
		},
		Ns:      dns.Fqdn(nsname),
		Mbox:    ".",
		Serial:  1,
		Refresh: 600,
		Retry:   600,
		Expire:  7200,
		Minttl:  600,
	}

	ns := &dns.NS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(tx.rootname),
			Ttl:    86400,
			Class:  dns.ClassINET,
			Rrtype: dns.TypeNS,
		},
		Ns: dns.Fqdn(nsname),
	}

	rrs = []dns.RR{soa, ns}
	return
}

func (tx *btx) doMetaDomain() (rrs []dns.RR, err error) {
	ip := net.ParseIP(tx.b.cfg.SelfIP)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid value specified for SelfIP")
	}

	switch tx.subname {
	case "this":
		rrs = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn("this." + tx.basename + "." + tx.rootname),
					Ttl:    86400,
					Class:  dns.ClassINET,
					Rrtype: dns.TypeA,
				},
				A: ip,
			},
		}

	default:
	}

	return
}

func (tx *btx) doUserDomain() (rrs []dns.RR, err error) {
	ncname, err := toNamecoinName(tx.basename)
	if err != nil {
		log.Infoe(err, "cannot determine namecoin name")
		return
	}

	d, err := tx.b.getNamecoinEntry(ncname)
	if err != nil {
		log.Infoe(err, "cannot get namecoin entry")
		return nil, err
	}

	rrs, err = tx.doUnderDomain(d)
	if err != nil {
		log.Infoe(err, "cannot process namecoin entry under domain")
		return nil, err
	}

	return rrs, nil
}

func (tx *btx) doUnderDomain(d *domain) (rrs []dns.RR, err error) {
	rrs, err = tx.addAnswersUnderNCValue(d.ncv, tx.subname)
	if err == merr.ErrNoResults {
		err = nil
	}

	return
}

func (tx *btx) addAnswersUnderNCValue(rncv *ncdomain.Value, subname string) (rrs []dns.RR, err error) {
	ncv, sn, err := tx.findNCValue(rncv, subname, nil /*hasNS*/)
	if err != nil {
		return
	}

	log.Info("ncv actual: ", sn)
	return tx.addAnswersUnderNCValueActual(ncv, sn)
}

/*func hasNS(ncv *ncdomain.Value) bool {
	nss, err := ncv.GetNSs()
	return err == nil && len(nss) > 0
}*/

func (tx *btx) findNCValue(ncv *ncdomain.Value, subname string, shortCircuitFunc func(curNCV *ncdomain.Value) bool) (xncv *ncdomain.Value, sn string, err error) {
	return tx._findNCValue(ncv, subname, "", 0, shortCircuitFunc)
}

func (tx *btx) _findNCValue(ncv *ncdomain.Value, isubname, subname string, depth int,
	shortCircuitFunc func(curNCV *ncdomain.Value) bool) (xncv *ncdomain.Value, sn string, err error) {

	if shortCircuitFunc != nil && shortCircuitFunc(ncv) {
		return ncv, subname, nil
	}

	if isubname != "" {
		head, rest := util.SplitDomainHead(isubname)

		sub, ok := ncv.Map[head]
		if !ok {
			sub, ok = ncv.Map["*"]
			if !ok {
				return nil, "", merr.ErrNoSuchDomain
			}
		}
		return tx._findNCValue(sub, rest, head+"."+subname, depth+1, shortCircuitFunc)
	}

	if shortCircuitFunc != nil {
		return nil, subname, merr.ErrNoSuchDomain
	}

	return ncv, subname, nil
}

func (tx *btx) addAnswersUnderNCValueActual(ncv *ncdomain.Value, sn string) (rrs []dns.RR, err error) {
	rrs, err = ncv.RRs(nil, dns.Fqdn(tx.qname), dns.Fqdn(tx.basename+"."+tx.rootname)) //convertAt(nil, dns.Fqdn(tx.qname), ncv)
	return
}

// a.b.c.d.e.f.g.zzz.bit
// f("a.b.c.d.e.f.g", "zzz.bit")
// f[g]("a.b.c.d.e.f", "g.zzz.bit")
// f[f]("a.b.c.d.e", "f.g.zzz.bit")
// f[e]("a.b.c.d", "e.f.g.zzz.bit")
// f[d]("a.b.c", "d.e.f.g.zzz.bit")
// f[c]("a.b", "c.d.e.f.g.zzz.bit")
// f[b]("a", "b.c.d.e.f.g.zzz.bit")
// f[a]("", "a.b.c.d.e.f.g.zzz.bit")

// Do low-level queries against an abstract zone file.
func (b *Backend) Lookup(qname string) (rrs []dns.RR, err error) {
	btx := &btx{}
	btx.b = b
	btx.qname = qname
	return btx.Do()
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
