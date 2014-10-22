package backend
import "github.com/golang/groupcache/lru"
import "github.com/miekg/dns"
import "github.com/hlandau/degoutils/log"
import "encoding/json"
import "encoding/base64"
import "encoding/hex"
import "fmt"
import "strings"
import "net"
import "github.com/hlandau/ncdns/namecoin"
import "github.com/hlandau/ncdns/ncerr"
import "github.com/hlandau/ncdns/util"
import "github.com/hlandau/ncdns/abstract"

type ncBackend struct {
  //s *Server
  nc namecoin.NamecoinConn
  cache lru.Cache // items are of type *Domain
  cfg Config
}

const (
  defaultMaxEntries = 100
)

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
}

// Creates a new Namecoin backend.
func New(cfg *Config) (backend abstract.Backend, err error) {
  b := &ncBackend{}

  b.cfg         = *cfg
  b.nc.Username = cfg.RPCUsername
  b.nc.Password = cfg.RPCPassword
  b.nc.Server   = cfg.RPCAddress

  b.cache.MaxEntries = cfg.CacheMaxEntries
  if b.cache.MaxEntries == 0 {
    b.cache.MaxEntries = defaultMaxEntries
  }

  backend = b

  return
}

// Keep domains in DNS format.
type domain struct {
  ncv *ncValue
}

// Root of a domain JSON structure
type ncValue struct {
  IP      interface{} `json:"ip"`
  IP6     interface{} `json:"ip6"`
  Service [][]interface{} `json:"service"`
  Alias   string `json:"alias"`
  NS      interface{} `json:"ns"`
  Map     map[string]*ncValue `json:"map"` // may contain "" and "*"
  DS      [][]interface{} `json:"ds"`
  TXT     interface{} `json:"txt"`
}

func toNamecoinName(basename string) (string, error) {
  return "d/" + basename, nil
}

func (b *ncBackend) getNamecoinEntry(name string) (*domain, error) {
  if dd, ok := b.cache.Get(name); ok {
    d := dd.(*domain)
    return d, nil
  }

  d, err := b.getNamecoinEntryLL(name)
  if err != nil {
    return nil, err
  }

  b.cache.Add(name, d)
  return d, nil
}

func (b *ncBackend) getNamecoinEntryLL(name string) (*domain, error) {
  v, err := b.nc.Query(name)
  if err != nil {
    log.Infoe(err, "namecoin query failed: ", err)
    return nil, err
  }

  log.Info("namecoin query (", name, ") succeeded: ", v)

  d, err := b.jsonToDomain(v)
  if err != nil {
    log.Infoe(err, "cannot convert JSON to domain")
    return nil, err
  }

  return d, nil
}

func (b *ncBackend) jsonToDomain(v string) (dd *domain, err error) {
  d := &domain{}
  ncv := &ncValue{}

  err = json.Unmarshal([]byte(v), ncv)
  if err != nil {
    log.Infoe(err, fmt.Sprintf("cannot unmarshal JSON: %+v", v))
    return
  }

  d.ncv = ncv

  dd = d
  return
}

type btx struct {
  b *ncBackend
  qname string

  subname, basename, rootname string
}

func (tx *btx) determineDomain() (subname, basename, rootname string, err error) {
  qname := tx.qname
  qname = strings.TrimRight(qname, ".")
  parts := strings.Split(qname, ".")
  if len(parts) < 2 {
    if parts[0] != "bit" {
      err = ncerr.ErrNotInZone
      return
    }

    rootname = parts[0]
    return
  }

  for i := len(parts)-1; i >= 0; i-- {
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
      subname  = strings.Join(parts[0:i-1], ".")
      return
    }
  }

  err = ncerr.ErrNotInZone
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
    return nil, ncerr.ErrNotInZone
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

  soa := &dns.SOA {
    Hdr: dns.RR_Header {
      Name: dns.Fqdn(tx.rootname),
      Ttl: 86400,
      Class: dns.ClassINET,
      Rrtype: dns.TypeSOA,
    },
    Ns: dns.Fqdn(nsname),
    Mbox: ".",
    Serial: 1,
    Refresh: 600,
    Retry: 600,
    Expire: 7200,
    Minttl: 600,
  }

  ns := &dns.NS {
    Hdr: dns.RR_Header {
      Name: dns.Fqdn(tx.rootname),
      Ttl: 86400,
      Class: dns.ClassINET,
      Rrtype: dns.TypeNS,
    },
    Ns: dns.Fqdn(nsname),
  }

  rrs = []dns.RR{ soa, ns, }
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
            Name: dns.Fqdn("this." + tx.basename + "." + tx.rootname),
            Ttl: 86400,
            Class: dns.ClassINET,
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
  if err == ncerr.ErrNoResults {
    err = nil
  }

  return
}

func (tx *btx) addAnswersUnderNCValue(rncv *ncValue, subname string) (rrs []dns.RR, err error) {
  ncv, sn, err := tx.findNCValue(rncv, subname, nil /*hasNS*/)
  if err != nil {
    return
  }

  log.Info("ncv actual: ", sn)
  return tx.addAnswersUnderNCValueActual(ncv, sn)
}

func hasNS(ncv *ncValue) bool {
  nss, err := ncv.GetNSs()
  return err == nil && len(nss) > 0
}

func (tx *btx) findNCValue(ncv *ncValue, subname string, shortCircuitFunc func(curNCV *ncValue) bool) (xncv *ncValue, sn string, err error) {
  return tx._findNCValue(ncv, subname, "", 0, shortCircuitFunc)
}

func (tx *btx) _findNCValue(ncv *ncValue, isubname, subname string, depth int,
  shortCircuitFunc func(curNCV *ncValue) bool) (xncv *ncValue, sn string, err error) {

  if shortCircuitFunc != nil && shortCircuitFunc(ncv) {
    return ncv, subname, nil
  }

  if isubname != "" {
    head, rest, err := util.SplitDomainHead(isubname)
    if err != nil {
      return nil, "", err
    }

    sub, ok := ncv.Map[head]
    if !ok {
      sub, ok = ncv.Map["*"]
      if !ok {
        return nil, "", ncerr.ErrNoSuchDomain
      }
    }
    return tx._findNCValue(sub, rest, head + "." + subname, depth+1, shortCircuitFunc)
  }

  if shortCircuitFunc != nil {
    return nil, subname, ncerr.ErrNoSuchDomain
  }

  return ncv, subname, nil
}

func (tx *btx) addAnswersUnderNCValueActual(ncv *ncValue, sn string) (rrs []dns.RR, err error) {
  // A
  ips, err := ncv.GetIPs()
  if err != nil {
    return
  }

  for _, ip := range ips {
    pip := net.ParseIP(ip)
    if pip == nil || pip.To4() == nil {
      continue
    }
    rrs = append(rrs, &dns.A {
      Hdr: dns.RR_Header { Name: dns.Fqdn(tx.qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600, },
      A: pip })
  }

  // AAAA
  ips, err = ncv.GetIP6s()
  if err != nil {
    return
  }

  for _, ip := range ips {
    pip := net.ParseIP(ip)
    if pip == nil || pip.To4() != nil {
      continue
    }
    rrs = append(rrs, &dns.AAAA {
      Hdr: dns.RR_Header { Name: dns.Fqdn(tx.qname), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 600, },
      AAAA: pip })
  }

  // NS
  nss, err := ncv.GetNSs()
  if err != nil {
    return
  }

  for _, ns := range nss {
    ns = dns.Fqdn(ns)
    rrs = append(rrs, &dns.NS {
      Hdr: dns.RR_Header { Name: dns.Fqdn(tx.qname), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 600, },
      Ns: ns })
  }

  // TXT
  txts, err := ncv.GetTXTs()
  if err != nil {
    return
  }

  for _, txt := range txts {
    rrs = append(rrs, &dns.TXT {
      Hdr: dns.RR_Header { Name: dns.Fqdn(tx.qname), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 600, },
      Txt: txt })
  }

  // TODO: MX
  // TODO: SRV

  // DS
  dss, err := ncv.GetDSs()
  if err != nil {
    return
  }

  for i := range dss {
    dss[i].Hdr.Name = dns.Fqdn(tx.qname)
    rrs = append(rrs, &dss[i])
  }

  if len(rrs) == 0 {
    if m, ok := ncv.Map[""]; ok {
      return tx.addAnswersUnderNCValueActual(m, sn)
    }
  }

  return
}

func (ncv *ncValue) getArray(a interface{}) (ips []string, err error) {
  if a == nil {
    return
  }

  ipa, ok := a.([]interface{})
  if ok {
    for _, v := range ipa {
      s, ok := v.(string)
      if ok {
        ips = append(ips, s)
      }
    }
  } else {
    s, ok := a.(string)
    if ok {
      ips = []string{s}
    } else {
      err = fmt.Errorf("malformed IP value")
    }
  }
  return
}

func (ncv *ncValue) GetIPs() (ips []string, err error) {
  return ncv.getArray(ncv.IP)
}

func (ncv *ncValue) GetIP6s() (ips []string, err error) {
  return ncv.getArray(ncv.IP6)
}

func (ncv *ncValue) GetNSs() (nss []string, err error) {
  return ncv.getArray(ncv.NS)
}

func (ncv *ncValue) getArrayTXT(a interface{}) (txts [][]string, err error) {
  if a == nil {
    return
  }

  if txta, ok := a.([]interface{}); ok {
    // ["...", "..."] or [["...","..."], ["...","..."]]
    for _, v := range txta {
      if sa, ok := v.([]string); ok {
        // [["...", "..."], ["...","..."]]
        txts = append(txts, sa)
      } else if s, ok := v.(string); ok {
        // ["...", "..."]
        txts = append(txts, segmentizeTXT(s))
      } else {
        err = fmt.Errorf("malformed TXT value")
        return
      }
    }
  } else {
    // "..."
    if s, ok := a.(string); ok {
      txts = append(txts, segmentizeTXT(s))
    } else {
      err = fmt.Errorf("malformed TXT value")
    }
  }
  return
}

func (ncv *ncValue) GetTXTs() (txts [][]string, err error) {
  return ncv.getArrayTXT(ncv.TXT)
}

func segmentizeTXT(txt string) (a []string) {
  for len(txt) > 255 {
    a = append(a, txt[0:255])
    txt = txt[255:]
  }
  a = append(a, txt)
  return
}

func (ncv *ncValue) GetDSs() (dss []dns.DS, err error) {
  for _, ds := range ncv.DS {
    //log.Info("  - DS: ", ds)
    if len(ds) != 4 {
      log.Info("  DS is bad len")
      continue
    }

    a1, ok := ds[0].(float64)
    if !ok {
      log.Info("  DS[0]")
      continue
    }
    a2, ok := ds[1].(float64)
    if !ok {
      log.Info("  DS[1]")
      continue
    }
    a3, ok := ds[2].(float64)
    if !ok {
      log.Info("  DS[2]")
      continue
    }
    a4, ok := ds[3].(string)
    if !ok {
      log.Info("  DS[3]")
      continue
    }

    a4b, err := base64.StdEncoding.DecodeString(a4)
    if err != nil {
      log.Info("can't decode: ", err)
      err = nil
      continue
    }

    a4h := hex.EncodeToString(a4b)

    d := dns.DS {
      Hdr: dns.RR_Header { Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 60, },
      KeyTag: uint16(a1),
      Algorithm: uint8(a2),
      DigestType: uint8(a3),
      Digest: a4h,
    }
    dss = append(dss, d)
  }
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
func (b *ncBackend) Lookup(qname string) (rrs []dns.RR, err error) {
  btx := &btx{}
  btx.b = b
  btx.qname = qname
  return btx.Do()
}
