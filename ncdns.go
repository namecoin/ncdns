package main
import "github.com/miekg/dns"
import "github.com/hlandau/degoutils/log"
import "os/signal"
import "os"
import "syscall"
import "fmt"
import "github.com/golang/groupcache/lru"
import "encoding/json"
import "strings"
import "net"
import "time"

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
    Addr: ":1153",
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
    return nil, err
  }

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

func (s *Server) addAnswersUnderNCValue(ncv *ncValue, subname, basename, rootname string, qtype uint16, res *dns.Msg) error {
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
    return s.addAnswersUnderNCValue(sub, rest, head + "." + basename, rootname, qtype, res)
  }

  toAdd := []dns.RR{}

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
      nss, err := ncv.GetNSs()
      if err != nil {
        return err
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
    default:
      // ...
  }

  if len(toAdd) == 0 {
    // we didn't get anything, so try the "" entry in the map
    if m, ok := ncv.Map[""]; ok {
      return s.addAnswersUnderNCValue(m, "", basename, rootname, qtype, res)
    }
  }

  for i := range toAdd {
    res.Answer = append(res.Answer, toAdd[i])
  }

  if len(res.Answer) > 0 {
    now := time.Now()
    rrsig := &dns.RRSIG {
      Algorithm: dns.RSASHA256,
      Expiration: uint32(now.Add(time.Duration(5)*time.Minute).Unix()),
      Inception: uint32(now.Unix()),
      KeyTag: s.zsk.KeyTag(),
      SignerName: rootname + ".",
    }
    err := rrsig.Sign(s.zskPrivate, res.Answer)
    if err != nil {
      return err
    }

    res.Answer = append(res.Answer, rrsig)
  }

  return nil
}

func (s *Server) addAnswersUnderDomain(d *Domain, subname, basename, rootname string, qtype uint16, res *dns.Msg) error {
  return s.addAnswersUnderNCValue(d.ncv, subname, basename, rootname, qtype, res)
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
      rootname = strings.Join(parts[i:len(parts)], ".")
      basename = parts[i-1]
      subname  = strings.Join(parts[0:i-1], ".")
      return
    }
  }

  err = fmt.Errorf("not a namecoin domain")
  return
}

func (s *Server) addRootAnswers(rootname string, qtype uint16, res *dns.Msg) error {
  useKSK := false

  s.zsk.Hdr.Name = rootname + "."

  switch qtype {
    case dns.TypeDNSKEY:
      res.Answer = append(res.Answer, s.ksk)
      res.Answer = append(res.Answer, &s.zsk)
      useKSK = true

    default:
  }

  if len(res.Answer) > 0 {
    now := time.Now()
    rrsig := &dns.RRSIG {
      Algorithm: dns.RSASHA256,
      Expiration: uint32(now.Add(time.Duration(5)*time.Minute).Unix()),
      Inception: uint32(now.Unix()),
      KeyTag: s.zsk.KeyTag(),
      SignerName: rootname + ".",
    }
    pk := s.zskPrivate
    if useKSK {
      pk = s.kskPrivate
      rrsig.KeyTag = s.ksk.KeyTag()
    }

    err := rrsig.Sign(pk, res.Answer)
    if err != nil {
      return err
    }

    res.Answer = append(res.Answer, rrsig)
  }

  return nil
}

func (s *Server) addAnswers(qname string, qtype uint16, res *dns.Msg) error {
  subname, basename, rootname, err := s.determineDomain(qname)
  if err != nil {
    log.Infoe(err, "cannot determine domain name")
    return err
  }
  //log.Info("DD: sub=", subname, "  base=", basename, "  root=", rootname)

  if rootname == "" {
    return fmt.Errorf("invalid domain name, no root")
  }

  if subname == "" && basename == "" {
    return s.addRootAnswers(rootname, qtype, res)
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

func (s *Server) handle(rw dns.ResponseWriter, req *dns.Msg) {
  res := dns.Msg{}
  res.SetReply(req)
  res.Authoritative = true
  res.Compress = true

  for _, q := range req.Question {
    if q.Qclass != dns.ClassINET && q.Qclass != dns.ClassANY {
      continue
    }

    err := s.addAnswers(q.Name, q.Qtype, &res)
    if err == ErrNoSuchDomain {
      res.SetRcode(req, dns.RcodeNameError)
      break
    } else if err != nil {
      // TODO
      log.Infoe(err, "Could not determine answer for query, doing SERVFAIL.")
      res.SetRcode(req, dns.RcodeServerFailure)
      break
    }
  }

  err := rw.WriteMsg(&res)
  log.Infoe(err, "Couldn't write response: " + res.String())
}

func (s *Server) Run() {
  s.mux = dns.NewServeMux()
  s.mux.HandleFunc(".", s.handle)

  // key setup
  kskf, err := os.Open("Kbit.+008+04050.key")
  log.Fatale(err)

  kskRR, err := dns.ReadRR(kskf, "Kbit.+008+04050.key")
  log.Fatale(err)

  ksk, ok := kskRR.(*dns.DNSKEY)
  if !ok {
    log.Fatal("loaded record from key file, but it wasn't a DNSKEY")
    return
  }

  s.ksk = ksk

  kskPrivatef, err := os.Open("Kbit.+008+04050.private")
  log.Fatale(err)

  s.kskPrivate, err = s.ksk.ReadPrivateKey(kskPrivatef, "Kbit.+008+04050.private")
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
