package backend

import "github.com/miekg/dns"
import "github.com/golang/groupcache/lru"
import "gopkg.in/hlandau/madns.v2/merr"
import "github.com/namecoin/ncdns/namecoin"
import "github.com/namecoin/ncdns/util"
import "github.com/namecoin/ncdns/ncdomain"
import "github.com/namecoin/ncdns/tlshook"
import "github.com/hlandau/xlog"
import "sync"
import "fmt"
import "net"
import "net/mail"
import "strings"
import "time"

// Provides an abstract zone file for the Namecoin .bit TLD.
type Backend struct {
	//s *Server
	nc namecoin.Conn
	// caches map keys are stream isolation ID's; items are of type *Domain
	caches     map[string]*lru.Cache
	cacheMutex sync.Mutex
	cfg        Config
}

var log, Log = xlog.New("ncdns.backend")

// Backend configuration.
type Config struct {
	NamecoinConn namecoin.Conn

	// Timeout (in milliseconds) for Namecoin RPC requests
	NamecoinTimeout int

	// Maximum entries to permit in name cache.
	CacheMaxEntries int

	// Nameservers to advertise at zone apex. The first is considered the primary.
	// If empty, a pseudo-hostname resolvable to SelfIP is used.
	CanonicalNameservers []string

	// Vanity IPs to place at the zone apex.
	VanityIPs []net.IP

	// Used only if CanonicalNameservers is left blank. An IP which the internal
	// pseudo-hostname should resolve to. This should be the public IP of the
	// nameserver serving the zone expressed by this backend.
	SelfIP string

	// Hostmaster in e. mail form (e.g. "hostmaster@example.com").
	Hostmaster string

	// Map names (like "d/example") to strings containing JSON values. Used to provide
	// fake names for testing purposes. You don't need to use this.
	FakeNames map[string]string
}

// Creates a new Namecoin backend.
func New(cfg *Config) (backend *Backend, err error) {
	b := &Backend{}

	b.cfg = *cfg
	b.nc = b.cfg.NamecoinConn
	//b.nc.Username = cfg.RPCUsername
	//b.nc.Password = cfg.RPCPassword
	//b.nc.Server = cfg.RPCAddress

	b.caches = make(map[string]*lru.Cache)

	hostmaster, err := convertEmail(b.cfg.Hostmaster)
	if err != nil {
		return
	}
	b.cfg.Hostmaster = hostmaster

	backend = b

	return
}

func convertEmail(email string) (string, error) {
	if email == "" {
		return ".", nil
	}

	if util.ValidateHostName(email) {
		return email, nil
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", err
	}

	email = addr.Address
	parts := strings.SplitN(email, "@", 2)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid e. mail address specified")
	}

	return dns.Fqdn(parts[0] + "." + parts[1]), nil
}

// Do low-level queries against an abstract zone file. This is the per-query
// entrypoint from madns.
func (b *Backend) Lookup(qname, streamIsolationID string) (rrs []dns.RR, err error) {
	err = lookupReadyError()
	if err != nil {
		return
	}

	btx := &btx{}
	btx.b = b
	btx.qname = qname
	btx.streamIsolationID = streamIsolationID
	return btx.Do()
}

// Things to keep track of while processing a query.
type btx struct {
	b     *Backend
	qname string

	streamIsolationID string

	subname, basename, rootname string
}

func (tx *btx) Do() (rrs []dns.RR, err error) {
	// Split the domain up. 'rootname' is the TLD and everything after it,
	// basename is the name directly before that, and subname is every name
	// before that. So "a.b.example.bit.suffix.xyz." would have a subname
	// of "a.b", a basename of "example" and a rootname of "bit.suffix.xyz".
	tx.subname, tx.basename, tx.rootname, err = tx.determineDomain()
	if err != nil {
		// We get an error if '.bit.' does not appear anywhere. In that case
		// we're not authoritative for the query in question and error out.
		return
	}

	if tx.rootname == "" {
		// REFUSED
		return nil, merr.ErrNotInZone
	}

	// If subname and basename are "", this means the query was for a root name
	// such as "bit." or "bit.suffix.xyz." directly. Serve SOA, NS records, etc.
	// as requested.
	if tx.subname == "" && tx.basename == "" {
		return tx.doRootDomain()
	}

	// Where ncdns has not been configured with a hostname to identify itself by,
	// it generates one under a special meta domain "x--nmc". This domain is not
	// a valid Namecoin domain name, so it does not confict with the Namecoin
	// domain name namespace.
	if tx.basename == "x--nmc" && len(tx.b.cfg.CanonicalNameservers) == 0 {
		return tx.doMetaDomain()
	}

	// If we have reached this point the query must be a normal user query.
	rrs, err = tx.doUserDomain()
	return
}

func (tx *btx) determineDomain() (subname, basename, rootname string, err error) {
	return util.SplitDomainByFloatingAnchor(tx.qname, "bit")
}

func (tx *btx) doRootDomain() (rrs []dns.RR, err error) {
	nss := tx.b.cfg.CanonicalNameservers
	if len(tx.b.cfg.CanonicalNameservers) == 0 {
		nss = []string{dns.Fqdn("this.x--nmc." + tx.rootname)}
	}

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(tx.rootname),
			Ttl:    86400,
			Class:  dns.ClassINET,
			Rrtype: dns.TypeSOA,
		},
		Ns:      nss[0],
		Mbox:    tx.b.cfg.Hostmaster,
		Serial:  1,
		Refresh: 600,
		Retry:   600,
		Expire:  7200,
		Minttl:  600,
	}

	rrs = make([]dns.RR, 0, 1+len(nss)+len(tx.b.cfg.VanityIPs))
	rrs = append(rrs, soa)
	for _, cn := range nss {
		ns := &dns.NS{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(tx.rootname),
				Ttl:    86400,
				Class:  dns.ClassINET,
				Rrtype: dns.TypeNS,
			},
			Ns: dns.Fqdn(cn),
		}

		rrs = append(rrs, ns)
	}

	for _, ip := range tx.b.cfg.VanityIPs {
		if ip.To4() != nil {
			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(tx.rootname),
					Ttl:    86400,
					Class:  dns.ClassINET,
					Rrtype: dns.TypeA,
				},
				A: ip,
			}
			rrs = append(rrs, a)
		} else {
			a := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(tx.rootname),
					Ttl:    86400,
					Class:  dns.ClassINET,
					Rrtype: dns.TypeAAAA,
				},
				AAAA: ip,
			}
			rrs = append(rrs, a)
		}
	}

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
	ncname, err := util.BasenameToNamecoinKey(tx.basename)
	if err != nil {
		return
	}

	d, err := tx.b.getNamecoinEntry(ncname, tx.streamIsolationID)
	if err != nil {
		return nil, err
	}

	rrs, err = tx.doUnderDomain(d)
	if err != nil {
		return nil, err
	}

	return rrs, nil
}

// Keep domains in parsed format.
type domain struct {
	ncv *ncdomain.Value
}

func (b *Backend) getNamecoinEntry(name, streamIsolationID string) (*domain, error) {
	d := b.getNamecoinEntryCache(name, streamIsolationID)
	if d != nil {
		return d, nil
	}

	d, err := b.getNamecoinEntryLL(name, streamIsolationID)
	if err != nil {
		return nil, err
	}

	b.addNamecoinEntryToCache(name, d, streamIsolationID)
	return d, nil
}

func (b *Backend) getNamecoinEntryCache(name, streamIsolationID string) *domain {
	b.cacheMutex.Lock()
	defer b.cacheMutex.Unlock()

	cache, ok := b.caches[streamIsolationID]
	if !ok {
		return nil
	}

	if dd, ok := cache.Get(name); ok {
		d := dd.(*domain)
		return d
	}

	return nil
}

func (b *Backend) addNamecoinEntryToCache(name string, d *domain, streamIsolationID string) {
	b.cacheMutex.Lock()
	defer b.cacheMutex.Unlock()

	cache, ok := b.caches[streamIsolationID]
	if !ok {
		b.caches[streamIsolationID] = &lru.Cache{
			MaxEntries: b.cfg.CacheMaxEntries,
		}
		cache = b.caches[streamIsolationID]
	}

	cache.Add(name, d)
}

func (b *Backend) getNamecoinEntryLL(name, streamIsolationID string) (*domain, error) {
	v, err := b.resolveName(name, streamIsolationID)
	if err != nil {
		return nil, err
	}

	d, err := b.jsonToDomain(name, v, streamIsolationID)
	if err != nil {
		return nil, err
	}

	return d, nil
}

func (b *Backend) resolveName(name, streamIsolationID string) (jsonValue string, err error) {
	if fv, ok := b.cfg.FakeNames[name]; ok {
		if fv == "NX" {
			return "", merr.ErrNoSuchDomain
		}
		return fv, nil
	}

	// The btcjson package has quite a long timeout, far in excess of standard
	// DNS timeouts. We need to return an error response rapidly if we can't
	// query the backend. Be generous with the timeout as responses from the
	// Namecoin JSON-RPC seem sluggish sometimes.
	result := make(chan struct{}, 1)
	go func() {
		jsonValue, err = b.nc.Query(name, streamIsolationID)
		log.Errore(err, "failed to query namecoin")
		result <- struct{}{}
	}()

	select {
	case <-result:
		return
	case <-time.After(time.Duration(b.cfg.NamecoinTimeout) * time.Millisecond):
		return "", fmt.Errorf("timeout")
	}
}

func (b *Backend) jsonToDomain(name, jsonValue, streamIsolationID string) (*domain, error) {
	d := &domain{}

	resolveExtraIsolated := func(n string) (string, error) {
		return b.resolveExtraName(n, streamIsolationID)
	}

	v := ncdomain.ParseValue(name, jsonValue, resolveExtraIsolated, nil)
	if v == nil {
		return nil, fmt.Errorf("couldn't parse value")
	}

	d.ncv = v

	return d, nil
}

func (b *Backend) resolveExtraName(name, streamIsolationID string) (jsonValue string, err error) {
	return b.resolveName(name, streamIsolationID)
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

	return tx.addAnswersUnderNCValueActual(ncv, sn)
}

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
	rrs, err = ncv.RRs(nil, dns.Fqdn(tx.qname), dns.Fqdn(tx.basename+"."+tx.rootname))

	// TODO: add callback variable "OnValueReferencedFunc" to backend options so that we don't pollute this function with every hook that we want
	//       might need to add the other attributes of tx, and sn, to the callback variable for flexibility's sake
	// This doesn't normally return errors, but any errors during execution will be logged.
	tlshook.DomainValueHookTLS(tx.qname, ncv)

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

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
