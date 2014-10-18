package main
import "github.com/miekg/dns"
import "github.com/hlandau/degoutils/log"
import "os/signal"
import "os"
import "syscall"
import "fmt"
import "github.com/golang/groupcache/lru"
import "encoding/json"
import "encoding/base32"
import "encoding/base64"
import "encoding/hex"
import "strings"
import "net"
import "time"
import "sort"
import "github.com/hlandau/degoutils/config"

//import "crypto/rsa"
//import "crypto/rand"
//import "math/big"

// A Go daemon to serve Namecoin domain records via DNS.
// This daemon is intended to be used in one of the following situations:
//
// 1. It is desired to mirror a domain name suffix (bit.suffix) to the .bit TLD.
//    Accordingly, bit.suffix is delegated to one or more servers each running this daemon.
//
// 2. It is desired to act as an authoritative server for the .bit TLD directly.
//    For example, a recursive DNS resolver is configured to override the root zone and use
//    a server running this daemon for .bit. Or .bit is added to the root zone (when pigs fly).
//
//    If the Unbound recursive DNS resolver were used:
//      unbound.conf:
//        server:
//          stub-zone:
//            name: bit
//            stub-addr: 127.0.0.1@1153
//
// This daemon currently requires namecoind or a compatible daemon running with JSON-RPC interface.
// The name_* API calls are used to obtain .bit domain information.

type Server struct {
  mux *dns.ServeMux
  udpListener *dns.Server
  tcpListener *dns.Server
  nc NamecoinConn
  cache lru.Cache // items are of type *Domain
  ksk *dns.DNSKEY
  kskPrivate dns.PrivateKey
  zsk dns.DNSKEY
  zskPrivate dns.PrivateKey
  cfg ServerConfig
}

type ServerConfig struct {
  Bind string         `default:":53" usage:"Address to bind to (e.g. 0.0.0.0:53)"`
  PublicKey string    `default:"ncdns.key" usage:"Path to the DNSKEY public key file"`
  PrivateKey string   `default:"ncdns.private" usage:"Path to the corresponding private key file"`
  NamecoinRPCUsername string `default:"" usage:"Namecoin RPC username"`
  NamecoinRPCPassword string `default:"" usage:"Namecoin RPC password"`
  NamecoinRPCAddress  string `default:"localhost:8336" usage:"Namecoin RPC server address"`
  CacheMaxEntries     int    `default:"1000" usage:"Maximum name cache entries"`
  SelfIP              string `default:"127.127.127.127" usage:"The canonical IP address for this service"`
}

func (s *Server) doRunListener(ds *dns.Server) {
  err := ds.ListenAndServe()
  log.Fatale(err)
}

func (s *Server) runListener(net string) *dns.Server {
  ds := &dns.Server {
    Addr: s.cfg.Bind,
    //"127.0.0.2:53",
    //Addr: ":1153",
    Net: net,
    Handler: s.mux,
  }
  go s.doRunListener(ds)
  return ds
}

// Keep domains in DNS format.
type Domain struct {
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
}

func (s *Server) getNamecoinEntry(name string) (*Domain, error) {
  if dd, ok := s.cache.Get(name); ok {
    d := dd.(*Domain)
    return d, nil
  }

  d, err := s.getNamecoinEntryLL(name)
  if err != nil {
    return nil, err
  }

  s.cache.Add(name, d)
  return d, nil
}

func (s *Server) getNamecoinEntryLL(name string) (*Domain, error) {
  v, err := s.nc.Query(name)
  if err != nil {
    log.Infoe(err, "namecoin query failed: ", err)
    return nil, err
  }

  log.Info("namecoin query (", name, ") succeeded: ", v)

  d, err := s.jsonToDomain(v)
  if err != nil {
    log.Infoe(err, "cannot convert JSON to domain")
    return nil, err
  }

  return d, nil
}

func (s *Server) jsonToDomain(v string) (dd *Domain, err error) {
  d := &Domain{}
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

func toNamecoinName(basename string) (string, error) {
  return "d/" + basename, nil
}

func splitDomainHead(name string) (head string, rest string, err error) {
  parts := strings.Split(name, ".")

  head = parts[len(parts)-1]

  if len(parts) >= 2 {
    rest = strings.Join(parts[0:len(parts)-1], ".")
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
    s, ok := ncv.IP.(string)
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

func (ncv *ncValue) GetDSs() (dss []dns.DS, err error) {
  for _, ds := range ncv.DS {
    log.Info("  - DS: ", ds)
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

var ErrNoSuchDomain = fmt.Errorf("no such domain")
var ErrNotNamecoin = fmt.Errorf("not a namecoin domain")
var ErrNoResults = fmt.Errorf("no results")

func stepName(n string) string {
  if len(n) == 0 {
    return ""
  }

  b, err := base32.HexEncoding.DecodeString(n)
  log.Panice(err, n)

  for i := len(b)-1; i>=0; i-- {
    b[i] += 1
    if b[i] != 0 { // didn't rollover, don't need to continue
      break
    }
  }

  return base32.HexEncoding.EncodeToString(b)
}

func absname(n string) string {
  if n == "" {
    return "."
  }
  if n[len(n)-1] != '.' {
    return n + "."
  }
  return n
}

func (tx *Tx) addAnswersUnderNCValueActual(ncv *ncValue, sn string) error {
  toAdd          := []dns.RR{}
  toAddAuthority := []dns.RR{}

  nss, nsserr := ncv.GetNSs()
  //log.Info("ncv  isub=", isubname, "  sub=", subname, "  base=", tx.basename, "  root=", tx.rootname, "  qtype=", tx.qtype, "  nss=", nss, "  nsserr=", nsserr)

  if nsserr == nil && len(nss) > 0 {
    nsn := sn
    if len(sn) > 0 {
      nsn += "."
    }
    nsn += tx.basename + "." + tx.rootname
    log.Info("ncv nsn=", nsn)
    for _, ns := range nss {
      toAddAuthority = append(toAddAuthority, &dns.NS {
        Hdr: dns.RR_Header { Name: absname(nsn), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60, },
        Ns: absname(ns),
      })
    }
  }

  if tx.istype(dns.TypeA) {
    ips, err := ncv.GetIPs()
    if err != nil {
      return err
    }

    for _, ip := range ips {
      pip := net.ParseIP(ip)
      if pip == nil || pip.To4() == nil {
        continue
      }
      toAdd = append(toAdd, &dns.A {
        Hdr: dns.RR_Header { Name: absname(tx.qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60, },
        A: pip })
    }
  }

  if tx.istype(dns.TypeAAAA) {
    ips, err := ncv.GetIP6s()
    if err != nil {
      return err
    }

    for _, ip := range ips {
      pip := net.ParseIP(ip)
      if pip == nil || pip.To4() != nil {
        continue
      }
      toAdd = append(toAdd, &dns.AAAA {
        Hdr: dns.RR_Header { Name: absname(tx.qname), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60, },
        AAAA: pip })
    }
  }

  if tx.istype(dns.TypeNS) && len(toAddAuthority) == 0 {
    if nsserr != nil {
      return nsserr
    }

    for _, ns := range nss {
      ns = absname(ns)
      toAdd = append(toAdd, &dns.NS {
        Hdr: dns.RR_Header { Name: absname(tx.qname), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60, },
        Ns: ns })
    }
  }

    //case dns.TypeTXT:
      // TODO
    //case dns.TypeMX:
      // TODO
    //case dns.TypeSRV:
      // TODO

  if tx.istype(dns.TypeDS) {
    dss, err := ncv.GetDSs()
    if err != nil {
      return err
    }

    for i := range dss {
      dss[i].Hdr.Name = absname(tx.qname)
      toAddAuthority = append(toAddAuthority, &dss[i])
    }
    log.Info("ds: ", dss, "  ", err)
  }


  if len(toAdd) == 0 && len(toAddAuthority) == 0 {
    // we didn't get anything, so try the "" entry in the map
    if m, ok := ncv.Map[""]; ok {
      return tx.addAnswersUnderNCValueActual(m, sn)
    }
  }

  for i := range toAdd {
    tx.res.Answer = append(tx.res.Answer, toAdd[i])
  }

  if tx.qtype != dns.TypeDS {
    for i := range toAddAuthority {
      tx.res.Ns = append(tx.res.Ns, toAddAuthority[i])
    }
  }

  return nil
}

func (tx *Tx) _findNCValue(ncv *ncValue, isubname, subname string, depth int,
    shortCircuitFunc func(curNCV *ncValue) bool) (xncv *ncValue, sn string, err error) {

  if shortCircuitFunc != nil && shortCircuitFunc(ncv) {
    return ncv, subname, nil
  }

  if isubname != "" {
    head, rest, err := splitDomainHead(isubname)
    if err != nil {
      return nil, "", err
    }

    sub, ok := ncv.Map[head]
    if !ok {
      sub, ok = ncv.Map["*"]
      if !ok {
        return nil, "", ErrNoSuchDomain
      }
    }
    return tx._findNCValue(sub, rest, head + "." + subname, depth+1, shortCircuitFunc)
  }

  if shortCircuitFunc != nil {
    return nil, subname, ErrNoSuchDomain
  }

  return ncv, subname, nil
}

func (tx *Tx) findNCValue(ncv *ncValue, subname string,
    shortCircuitFunc func(curNCV *ncValue) bool) (xncv *ncValue, sn string, err error) {
  return tx._findNCValue(ncv, subname, "", 0, shortCircuitFunc)
}

func hasNS(ncv *ncValue) bool {
  nss, err := ncv.GetNSs()
  return err == nil && len(nss) > 0
}

func (tx *Tx) addAnswersUnderNCValue(rncv *ncValue, subname string) error {
  ncv, sn, err := tx.findNCValue(rncv, subname, hasNS)
  if err != nil {
    return err
  }

  log.Info("ncv actual: ", sn)
  return tx.addAnswersUnderNCValueActual(ncv, sn)
}

func (tx *Tx) addAnswersUnderDomain(d *Domain) error {
  err := tx.addAnswersUnderNCValue(d.ncv, tx.subname)
  if err == ErrNoResults {
    err = nil
  }
  return err
}

func (tx *Tx) determineDomain() (subname, basename, rootname string, err error) {
  qname := tx.qname
  qname = strings.TrimRight(qname, ".")
  parts := strings.Split(qname, ".")
  if len(parts) < 2 {
    if parts[0] != "bit" {
      err = ErrNotNamecoin
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

  err = ErrNotNamecoin
  return
}

func (tx *Tx) addMetaAnswers() error {
  ip := net.ParseIP(tx.s.cfg.SelfIP)
  if ip == nil || ip.To4() == nil {
    return fmt.Errorf("invalid value specified for SelfIP")
  }

  switch tx.subname {
    case "this":
      if tx.istype(dns.TypeA) {
        tx.res.Answer = append(tx.res.Answer, &dns.A {
          Hdr: dns.RR_Header {
            Name: tx.subname + "." + tx.basename + "." + tx.rootname + ".",
            Ttl: 86400,
            Class: dns.ClassINET,
            Rrtype: dns.TypeA,
          },
          A: ip,
        })
      }
    case "":
    default:
      tx.setRcode(dns.RcodeNameError)
  }

  return nil
}

func (tx *Tx) addRootSOA() error {
  soa := &dns.SOA {
    Hdr: dns.RR_Header {
      Name: absname(tx.rootname),
      Ttl: 86400,
      Class: dns.ClassINET,
      Rrtype: dns.TypeSOA,
    },
    Ns: absname("this.x--nmc." + tx.rootname),
    Mbox: ".",
    Serial: 1,
    Refresh: 600,
    Retry: 600,
    Expire: 7200,
    Minttl: 600,
  }
  if tx.istype(dns.TypeSOA) && absname(tx.rootname) == absname(tx.qname) {
    tx.res.Answer = append(tx.res.Answer, soa)
  } else {
    tx.res.Ns = append(tx.res.Ns, soa)
  }
  return nil
}

func (tx *Tx) istype(x uint16) bool {
  return tx.qtype == x || tx.qtype == dns.TypeANY
}

func (tx *Tx) addRootAnswers() error {
  //useKSK := false

  tx.s.zsk.Hdr.Name = tx.rootname + "."

  if tx.istype(dns.TypeNS) {
    tx.res.Answer = append(tx.res.Answer, &dns.NS {
      Hdr: dns.RR_Header {
        Name: absname(tx.rootname),
        Ttl: 86400,
        Class: dns.ClassINET,
        Rrtype: dns.TypeNS,
      },
      Ns: "this.x--nmc.bit.",
    })
  }

  if tx.istype(dns.TypeDNSKEY) {
    tx.s.ksk.Hdr.Name = absname(tx.rootname)
    tx.s.zsk.Hdr.Name = tx.s.ksk.Hdr.Name

    tx.res.Answer = append(tx.res.Answer, tx.s.ksk)
    tx.res.Answer = append(tx.res.Answer, &tx.s.zsk)
    //useKSK = true
  }

  log.Info("addRootAnswers/sr")

  if len(tx.res.Answer) == 0 || tx.istype(dns.TypeSOA) {
    err := tx.addRootSOA()
    if err != nil {
      return err
    }
  }

  log.Info("done sr")

  return nil
}

func (tx *Tx) signRRs(rra []dns.RR, useKSK bool) (dns.RR, error) {
  if len(rra) == 0 {
    return nil, fmt.Errorf("no RRs to such")
  }

  now := time.Now()
  rrsig := &dns.RRSIG {
    Hdr: dns.RR_Header { Ttl: rra[0].Header().Ttl, },
    Algorithm: dns.RSASHA256,
    Expiration: uint32(now.Add(time.Duration(10)*time.Minute).Unix()),
    Inception: uint32(now.Unix()),
    SignerName: tx.rootname + ".",
  }
  pk := tx.s.zskPrivate
  if useKSK {
    pk = tx.s.kskPrivate
    rrsig.KeyTag = tx.s.ksk.KeyTag()
  } else {
    rrsig.KeyTag = tx.s.zsk.KeyTag()
  }

  err := rrsig.Sign(pk, rra)
  if err != nil {
    return nil, err
  }

  return rrsig, nil
}

func shouldSignType(t uint16, isAuthoritySection bool) bool {
  //log.Info("shouldSignType ", t, " ", isAuthoritySection)
  switch t {
    case dns.TypeOPT:
      return false
    case dns.TypeNS:
      return !isAuthoritySection
    default:
      return true
  }
}

func (tx *Tx) signResponseSection(rra *[]dns.RR, useKSK bool) error {
  if len(*rra) == 0 {
    return nil
  }
  //log.Info("sign section: ", *rra)

  i := 0
  a := []dns.RR{}
  pt := (*rra)[0].Header().Rrtype
  t := uint16(0)

  origrra := *rra

  for i < len(origrra) {
    for i < len(origrra) {
      t = (*rra)[i].Header().Rrtype
      if t != pt {
        break
      }

      a = append(a, origrra[i])
      i++
    }

    if shouldSignType(pt, (rra == &tx.res.Ns) ) {
      srr, err := tx.signRRs(a, useKSK)
      if err != nil {
        return err
      }

      *rra = append(*rra, srr)
    }

    pt = t
    a = []dns.RR{}
  }

  return nil
}

func (tx *Tx) useDNSSEC() bool {
  opt := tx.req.IsEdns0()
  if opt == nil {
    return false
  }
  return opt.Do()
}

func (tx *Tx) signResponse(useKSK bool) error {
  if !tx.useDNSSEC() {
    return nil
  }

  for _, r := range []*[]dns.RR { &tx.res.Answer, &tx.res.Ns, &tx.res.Extra } {
    err := tx.signResponseSection(r, useKSK)
    if err != nil {
      log.Infoe(err, "fail signResponse")
      return err
    }
  }

  log.Info("done signResponse")
  return nil
}

var ErrNoRoot = fmt.Errorf("invalid domain name, no root")

var allPossibleTypes []uint16 = []uint16 {
  dns.TypeSOA, dns.TypeDNSKEY, dns.TypeDS,
  dns.TypeNS, //dns.TypeCNAME,
  dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeSRV, dns.TypeTXT,
}

type uint16Slice []uint16
func (p uint16Slice) Len() int { return len(p) }
func (p uint16Slice) Less(i, j int) bool { return p[i] < p[j] }
func (p uint16Slice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

func (tx *Tx) addNSEC3RR() error {
  // Map of what possibly exists
  m := map[uint16]struct{}{}
  for _, rr := range tx.res.Answer {
    // Definitely exists
    m[rr.Header().Rrtype] = struct{}{}
  }

  // If qtype is ANY, the only record types which exist are those we found above.
  if tx.qtype != dns.TypeANY {
    // Any record type which wasn't the one we asked for might exist.
    for _, t := range allPossibleTypes {
      if t != tx.qtype {
        m[t] = struct{}{}
      }
    }
  }

  tbm := []uint16{}
  for t, _ := range m {
    tbm = append(tbm, t)
  }

  // The DNS library is buggy unless tbm is sorted.
  sort.Sort(uint16Slice(tbm))

  log.Info("NSEC3: qname=", tx.qname, "  base=", tx.basename, "  root=", tx.rootname)
  nsr1n  := dns.HashName(tx.qname, dns.SHA1, 1, "8F")
  nsr1nn := stepName(nsr1n)
  nsr1   := &dns.NSEC3 {
    Hdr: dns.RR_Header {
      Name: nsr1n + "." + tx.rootname + ".",
      Rrtype: dns.TypeNSEC3,
      Class: dns.ClassINET,
      Ttl: 600,
    },
    Hash: dns.SHA1,
    Flags: 0,
    Iterations: 1,
    SaltLength: 1,
    Salt: "8F",
    HashLength: uint8(len(nsr1nn)),
    NextDomain: nsr1nn,
    TypeBitMap: tbm,
  }
  tx.res.Ns = append(tx.res.Ns, nsr1)
  return nil
}

func (tx *Tx) addNSEC() error {
  if !tx.useDNSSEC() {
    return nil
  }

  // NSEC replies should be given in the following circumstances:
  //
  //   - No ANSWER SECTION responses for type requested, qtype != DS
  //   - No ANSWER SECTION responses for type requested, qtype == DS
  //   - Wildcard, no data responses
  //   - Wildcard, data response
  //   - Name error response
  //   - Direct NSEC request
  if len(tx.res.Answer) == 0 /*&& qtype != dns.TypeDS*/ {
    log.Info("adding NSEC3")
    err := tx.addNSEC3RR()
    if err != nil {
      return err
    }

    /*err = s.addNSEC3RR("*", rootname, "*." + qname, qtype, res)
    if err != nil {
      return err
    }*/
  }

  //if len(toAdd) == 0 && (len(toAddAuthority) == 0 || qtype == dns.TypeDS) {
  //}

  return nil
}

func (tx *Tx) setRcode(x int) {
  if tx.rcode == 0 {
    tx.rcode = x
  }
}

func (tx *Tx) addAnswersMain() error {
  if tx.rootname == "" {
    tx.setRcode(dns.RcodeRefused)
    return ErrNoRoot
  }

  if tx.basename == "x--nmc" {
    return tx.addMetaAnswers()
  }

  if tx.subname == "" && tx.basename == "" {
    err := tx.addRootAnswers()
    return err
  }

  ncname, err := toNamecoinName(tx.basename)
  if err != nil {
    log.Infoe(err, "cannot determine namecoin name")
    return err
  }

  d, err := tx.s.getNamecoinEntry(ncname)
  if err != nil {
    log.Infoe(err, "cannot get namecoin entry")
    if err == ErrNoSuchDomain {
      tx.setRcode(dns.RcodeNameError)
    }
    return err
  }

  err = tx.addAnswersUnderDomain(d)
  if err != nil {
    log.Infoe(err, "cannot add answers")
    return err
  }

  return nil
}

func (tx *Tx) addAnswersMainOuter() error {
  err := tx.addAnswersMain()

  if len(tx.res.Answer) == 0 && len(tx.res.Ns) > 0 {
    tx.res.Authoritative = false
  }

  // Do not use istype here, we do not want to match ANY
  if err == nil && !(len(tx.res.Answer) == 0 && tx.qtype == dns.TypeDS) {
    return nil
  }

  // If an error occurred, and we have NXDOMAIN, add SOA
  err2 := tx.addRootSOA()
  if err2 != nil {
    // currently, let the first error take precedence
  }

  return err
}

func (tx *Tx) addAnswers() error {
  var err error
  tx.subname, tx.basename, tx.rootname, err = tx.determineDomain()
  if err != nil {
    log.Infoe(err, "cannot determine domain name, refusing")
    tx.setRcode(dns.RcodeRefused)
    return err
  }

  log.Info("DD: sub=", tx.subname, "  base=", tx.basename, "  root=", tx.rootname)

  err = tx.addAnswersMainOuter()
  if err != nil {
    // eat name errors
    if err != ErrNoSuchDomain {
      return err
    }
  }

  err = tx.addNSEC()
  if err != nil {
    log.Infoe(err, "cannot add NSEC")
    return err
  }

  // XXX
  useKSK := (tx.qtype == dns.TypeDNSKEY)
  err = tx.signResponse(useKSK)
  if err != nil {
    log.Infoe(err, "cannot sign response")
    return err
  }

  return nil
}

type Tx struct {
  req *dns.Msg
  res *dns.Msg
  qname  string
  qtype  uint16
  qclass uint16
  s      *Server
  rcode  int

  subname string  // the subname:  www.bitcoin.bit -> "www", bitcoin.bit -> ""
  basename string // the basename: bitcoin.bit -> "bitcoin"
  rootname string // the TLD: bitcoin.bit -> "bit", bitcoin.bit.example.com -> "bit.example.com"
}

func (s *Server) handle(rw dns.ResponseWriter, reqMsg *dns.Msg) {
  tx := Tx{}
  tx.req = reqMsg
  tx.res = &dns.Msg{}
  tx.res.SetReply(tx.req)
  tx.res.Authoritative = true
  tx.res.Compress = true
  tx.s = s
  tx.rcode = 0

  opt := tx.req.IsEdns0()
  if opt != nil {
    tx.res.Extra = append(tx.res.Extra, opt)
  }

  for _, q := range tx.req.Question {
    tx.qname  = strings.ToLower(q.Name)
    tx.qtype  = q.Qtype
    tx.qclass = q.Qclass

    if q.Qclass != dns.ClassINET && q.Qclass != dns.ClassANY {
      continue
    }

    err := tx.addAnswers()
    if err != nil {
      if tx.rcode == 0 {
        log.Infoe(err, "Handler error, doing SERVFAIL")
        tx.rcode = dns.RcodeServerFailure
      }
      break
    }

  }

  tx.res.SetRcode(tx.req, tx.rcode)

  //log.Info("response: ", res.String())
  err := rw.WriteMsg(tx.res)
  log.Infoe(err, "Couldn't write response: " + tx.res.String())
}

func (s *Server) Run() {
  s.mux = dns.NewServeMux()
  s.mux.HandleFunc(".", s.handle)

  // key setup
  kskf, err := os.Open(s.cfg.PublicKey)
  log.Fatale(err)

  kskRR, err := dns.ReadRR(kskf, s.cfg.PublicKey)
  log.Fatale(err)

  ksk, ok := kskRR.(*dns.DNSKEY)
  if !ok {
    log.Fatal("loaded record from key file, but it wasn't a DNSKEY")
    return
  }

  s.ksk = ksk

  kskPrivatef, err := os.Open(s.cfg.PrivateKey)
  log.Fatale(err)

  s.kskPrivate, err = s.ksk.ReadPrivateKey(kskPrivatef, s.cfg.PrivateKey)
  log.Fatale(err)

  s.zsk.Hdr.Rrtype = dns.TypeDNSKEY
  s.zsk.Hdr.Class  = dns.ClassINET
  s.zsk.Hdr.Ttl    = 3600
  s.zsk.Algorithm = dns.RSASHA256
  s.zsk.Protocol = 3
  s.zsk.Flags = dns.ZONE

  s.zskPrivate, err = s.zsk.Generate(2048)
  log.Fatale(err)

  // run
  s.udpListener = s.runListener("udp")
  s.tcpListener = s.runListener("tcp")
  s.nc.Username = s.cfg.NamecoinRPCUsername
  s.nc.Password = s.cfg.NamecoinRPCPassword
  s.nc.Server   = s.cfg.NamecoinRPCAddress
  s.cache.MaxEntries = s.cfg.CacheMaxEntries

  log.Info("Ready.")

  // wait
  sig := make(chan os.Signal)
  signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
  for {
    s := <-sig
    fmt.Printf("Signal %v received, stopping.", s)
    break
  }
}

func NewServer(cfg *ServerConfig) *Server {
  s := &Server{}
  s.cfg = *cfg
  return s
}

func main() {
  cfg := ServerConfig {}
  config := config.Configurator{
    ProgramName: "ncdns",
    ConfigFilePaths: []string { "etc/ncdns.conf", "/etc/ncdns/ncdns.conf", },
  }
  config.ParseFatal(&cfg)
  s := NewServer(&cfg)
  s.Run()
}

// © 2014 Hugo Landau <hlandau@devever.net>      GPLv3 or later
