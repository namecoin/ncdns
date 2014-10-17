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
}

func (s *Server) doRunListener(ds *dns.Server) {
  err := ds.ListenAndServe()
  log.Fatale(err)
}

func (s *Server) runListener(net string) *dns.Server {
  ds := &dns.Server {
    Addr: "127.0.0.2:53",
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

func (s *Server) addAnswersUnderNCValue(ncv *ncValue, subname, basename, rootname string, qtype uint16, res *dns.Msg, depth int) error {
  toAdd          := []dns.RR{}
  toAddAuthority := []dns.RR{}

  nss, nsserr := ncv.GetNSs()
  log.Info("ncv  sub=", subname, "  base=", basename, "  root=", rootname, "  qtype=", qtype, "  nss=", nss, "  nsserr=", nsserr)

  if nsserr == nil && len(nss) > 0 {
    for _, ns := range nss {
      toAddAuthority = append(toAddAuthority, &dns.NS {
        Hdr: dns.RR_Header { Name: strings.TrimRight(basename, ".") + ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60, },
        Ns: strings.TrimRight(ns, ".") + ".",
      })
    }
  }

  if subname != "" {
    head, rest, err := splitDomainHead(subname)
    if err != nil {
      return err
    }

    sub, ok := ncv.Map[head]
    if !ok {
      sub, ok = ncv.Map["*"]
      if !ok {
        return ErrNoSuchDomain
      }
    }
    return s.addAnswersUnderNCValue(sub, rest, head + "." + basename, rootname, qtype, res, depth+1)
  }

  switch qtype {
    case dns.TypeA:
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
          Hdr: dns.RR_Header { Name: basename, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60, },
          A: pip })
      }

    case dns.TypeAAAA:
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
          Hdr: dns.RR_Header { Name: basename, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60, },
          AAAA: pip })
      }

    case dns.TypeNS:
      if nsserr != nil {
        return nsserr
      }

      for _, ns := range nss {
        ns = strings.TrimRight(ns, ".") + "."
        toAdd = append(toAdd, &dns.NS {
          Hdr: dns.RR_Header { Name: basename, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60, },
          Ns: ns })
      }

    case dns.TypeTXT:
      // TODO
    case dns.TypeMX:
      // TODO
    case dns.TypeSRV:
      // TODO

    case dns.TypeDS:
      dss, err := ncv.GetDSs()
      if err != nil {
        return err
      }

      for i := range dss {
        dss[i].Hdr.Name = basename
        toAdd = append(toAdd, &dss[i])
      }
      log.Info("ds: ", dss, "  ", err)

    default:
      // ...
  }

  if len(toAdd) == 0 && len(toAddAuthority) == 0 {
    // we didn't get anything, so try the "" entry in the map
    if m, ok := ncv.Map[""]; ok {
      return s.addAnswersUnderNCValue(m, "", basename, rootname, qtype, res, depth+1)
    }
  }

  for i := range toAdd {
    res.Answer = append(res.Answer, toAdd[i])
  }

  if qtype != dns.TypeDS {
    for i := range toAddAuthority {
      res.Ns = append(res.Ns, toAddAuthority[i])
    }
  }

  return nil
}

func (s *Server) addAnswersUnderDomain(d *Domain, subname, basename, rootname string, qtype uint16, res *dns.Msg) error {
  err := s.addAnswersUnderNCValue(d.ncv, subname, basename, rootname, qtype, res, 0)
  if err == ErrNoResults {
    err = nil
  }
  return err
}

func (s *Server) determineDomain(qname string) (subname, basename, rootname string, err error) {
  qname = strings.TrimRight(qname, ".")
  parts := strings.Split(qname, ".")
  if len(parts) < 2 {
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

  err = fmt.Errorf("not a namecoin domain: ", qname)
  return
}

func (s *Server) addMetaAnswers(subname, basename, rootname string, qtype uint16, res *dns.Msg) error {
  switch subname {
    case "this":
      switch qtype {
        case dns.TypeA, dns.TypeANY:
          res.Answer = append(res.Answer, &dns.A {
            Hdr: dns.RR_Header {
              Name: subname + "." + basename + "." + rootname + ".",
              Ttl: 86400,
              Class: dns.ClassINET,
              Rrtype: dns.TypeA,
            },
            A: net.IPv4(127,127,127,127),
          })
        default:
      }
    default:
  }

  return nil
}

func (s *Server) addRootAnswers(rootname string, qtype uint16, res *dns.Msg) error {
  //useKSK := false

  s.zsk.Hdr.Name = rootname + "."

  if qtype != dns.TypeNS && qtype != dns.TypeDNSKEY {
    soa := &dns.SOA {
      Hdr: dns.RR_Header {
        Name: rootname + ".",
        Ttl: 86400,
        Class: dns.ClassINET,
        Rrtype: dns.TypeSOA,
      },
      Ns: "this.x--nmc.bit.",
      Mbox: ".",
      Serial: 1,
      Refresh: 600,
      Retry: 600,
      Expire: 7200,
      Minttl: 600,
    }
    if qtype == dns.TypeSOA || qtype == dns.TypeANY {
      res.Answer = append(res.Answer, soa)
    } else {
      res.Ns = append(res.Ns, soa)
    }
  }

  if qtype == dns.TypeNS || qtype == dns.TypeANY {
    res.Answer = append(res.Answer, &dns.NS {
      Hdr: dns.RR_Header {
        Name: rootname + ".",
        Ttl: 86400,
        Class: dns.ClassINET,
        Rrtype: dns.TypeNS,
      },
      Ns: "this.x--nmc.bit.",
    })
  }

  if qtype == dns.TypeDNSKEY || qtype == dns.TypeANY {
    res.Answer = append(res.Answer, s.ksk)
    res.Answer = append(res.Answer, &s.zsk)
    //useKSK = true
  }

  log.Info("addRootAnswers/sr")

  /*err := s.signResponse(res, useKSK, rootname)
  if err != nil {
    log.Infoe(err, "/sr")
    return err
  }*/

  log.Info("done sr")

  return nil
}

func (s *Server) signRRs(rra []dns.RR, useKSK bool, rootname string) (dns.RR, error) {
  if len(rra) == 0 {
    return nil, fmt.Errorf("no RRs to such")
  }

  now := time.Now()
  rrsig := &dns.RRSIG {
    Hdr: dns.RR_Header { Ttl: rra[0].Header().Ttl, },
    Algorithm: dns.RSASHA256,
    Expiration: uint32(now.Add(time.Duration(10)*time.Minute).Unix()),
    Inception: uint32(now.Unix()),
    SignerName: rootname + ".",
  }
  pk := s.zskPrivate
  if useKSK {
    pk = s.kskPrivate
    rrsig.KeyTag = s.ksk.KeyTag()
  } else {
    rrsig.KeyTag = s.zsk.KeyTag()
  }

  err := rrsig.Sign(pk, rra)
  if err != nil {
    return nil, err
  }

  return rrsig, nil
}

func shouldSignType(t uint16) bool {
  switch t {
    case dns.TypeOPT:
      return false
    default:
      return true
  }
}

func (s *Server) signResponseSection(rra *[]dns.RR, useKSK bool, rootname string) error {
  if len(*rra) == 0 {
    return nil
  }

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

    if shouldSignType(t) {
      srr, err := s.signRRs(a, useKSK, rootname)
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

func useDNSSEC(msg *dns.Msg) bool {
  opt := msg.IsEdns0()
  if opt == nil {
    return false
  }
  return opt.Do()
}

func (s *Server) signResponse(res *dns.Msg, useKSK bool, rootname string) error {
  if !useDNSSEC(res) {
    return nil
  }

  for _, r := range []*[]dns.RR { &res.Answer, &res.Ns, &res.Extra } {
    err := s.signResponseSection(r, useKSK, rootname)
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

func (s *Server) addNSEC3RR(basename, rootname, qname string, qtype uint16, res *dns.Msg) error {
  // Map of what possibly exists
  m := map[uint16]struct{}{}
  for _, rr := range res.Answer {
    // Definitely exists
    m[rr.Header().Rrtype] = struct{}{}
  }

  // If qtype is ANY, the only record types which exist are those we found above.
  if qtype != dns.TypeANY {
    // Any record type which wasn't the one we asked for might exist.
    for _, t := range allPossibleTypes {
      if t != qtype {
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

  log.Info("NSEC3: qname=", qname, "  base=", basename, "  root=", rootname)
  nsr1n  := dns.HashName(qname, dns.SHA1, 1, "8F")
  nsr1nn := stepName(nsr1n)
  nsr1   := &dns.NSEC3 {
    Hdr: dns.RR_Header {
      Name: nsr1n + "." + rootname + ".",
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
  res.Ns = append(res.Ns, nsr1)
  return nil
}

func (s *Server) addNSEC(basename, rootname, qname string, qtype uint16, res *dns.Msg) error {
  if !useDNSSEC(res) {
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
  if len(res.Answer) == 0 /*&& qtype != dns.TypeDS*/ {
    log.Info("adding NSEC3")
    err := s.addNSEC3RR(basename, rootname, qname, qtype, res)
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

func (s *Server) addAnswersMain(subname, basename, rootname, qname string, qtype uint16, res *dns.Msg) error {
  if rootname == "" {
    return ErrNoRoot
  }

  if basename == "x--nmc" {
    return s.addMetaAnswers(subname, basename, rootname, qtype, res)
  }

  if subname == "" && basename == "" {
    err := s.addRootAnswers(rootname, qtype, res)
    return err
  }

  ncname, err := toNamecoinName(basename)
  if err != nil {
    log.Infoe(err, "cannot determine namecoin name")
    return err
  }

  d, err := s.getNamecoinEntry(ncname)
  if err != nil {
    log.Infoe(err, "cannot get namecoin entry")
    return err
  }

  err = s.addAnswersUnderDomain(d, subname, basename + "." + rootname + ".", rootname, qtype, res)
  if err != nil {
    log.Infoe(err, "cannot add answers")
    return err
  }

  return nil
}

func (s *Server) addAnswers(qname string, qtype uint16, res *dns.Msg) error {
  subname, basename, rootname, err := s.determineDomain(qname)
  if err != nil {
    log.Infoe(err, "cannot determine domain name")
    return err
  }

  log.Info("DD: sub=", subname, "  base=", basename, "  root=", rootname)

  err = s.addAnswersMain(subname, basename, rootname, qname, qtype, res)
  if err != nil {
    return err
  }

  err = s.addNSEC(basename, rootname, qname, qtype, res)
  if err != nil {
    log.Infoe(err, "cannot add NSEC")
    return err
  }

  useKSK := (qtype == dns.TypeDNSKEY)
  err = s.signResponse(res, useKSK, rootname)
  if err != nil {
    log.Infoe(err, "cannot sign response")
    return err
  }

  return nil
}

func (s *Server) handle(rw dns.ResponseWriter, req *dns.Msg) {
  res := dns.Msg{}
  res.SetReply(req)
  res.Authoritative = true
  res.Compress = true
  opt := req.IsEdns0()
  if opt != nil {
    res.Extra = append(res.Extra, opt)
  }

  for _, q := range req.Question {
    if q.Qclass != dns.ClassINET && q.Qclass != dns.ClassANY {
      continue
    }

    err := s.addAnswers(q.Name, q.Qtype, &res)
    if err == ErrNoSuchDomain {
      res.SetRcode(req, dns.RcodeNameError)
      break
    } else if err == ErrNoRoot {
      res.SetRcode(req, dns.RcodeRefused)
      break
    } else if err != nil {
      // TODO
      log.Infoe(err, "Could not determine answer for query, doing SERVFAIL.")
      res.SetRcode(req, dns.RcodeServerFailure)
      break
    }
  }

  //log.Info("response: ", res.String())
  err := rw.WriteMsg(&res)
  log.Infoe(err, "Couldn't write response: " + res.String())
}

func (s *Server) Run() {
  s.mux = dns.NewServeMux()
  s.mux.HandleFunc(".", s.handle)

  // key setup
  kskf, err := os.Open("Kbit.dt.qien.net.+008+60970.key")
  log.Fatale(err)

  kskRR, err := dns.ReadRR(kskf, "Kbit.dt.qien.net.+008+60970.key")
  log.Fatale(err)

  ksk, ok := kskRR.(*dns.DNSKEY)
  if !ok {
    log.Fatal("loaded record from key file, but it wasn't a DNSKEY")
    return
  }

  s.ksk = ksk

  kskPrivatef, err := os.Open("Kbit.dt.qien.net.+008+60970.private")
  log.Fatale(err)

  s.kskPrivate, err = s.ksk.ReadPrivateKey(kskPrivatef, "Kbit.dt.qien.net.+008+60970.private")
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
  s.nc.Username = "user"
  s.nc.Password = "password"
  s.nc.Server   = "127.0.0.1:8336"
  s.cache.MaxEntries = 1000

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

func main() {
  s := Server{}
  s.Run()
}

// © 2014 Hugo Landau <hlandau@devever.net>      GPLv3 or later
