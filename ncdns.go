package main
import "github.com/miekg/dns"
import "github.com/hlandau/degoutils/log"
import "os/signal"
import "os"
import "syscall"
import "fmt"
import "strings"
import "sort"
import "github.com/hlandau/degoutils/config"

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

func NewServer(cfg *ServerConfig) *Server {
  s := &Server{}
  s.cfg = *cfg
  return s
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

  s.b, err = NewNCBackend(s)
  log.Fatale(err)

  // run
  s.udpListener = s.runListener("udp")
  s.tcpListener = s.runListener("tcp")

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

type Server struct {
  mux *dns.ServeMux
  udpListener *dns.Server
  tcpListener *dns.Server
  ksk *dns.DNSKEY
  kskPrivate dns.PrivateKey
  zsk dns.DNSKEY
  zskPrivate dns.PrivateKey
  cfg ServerConfig
  b Backend
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
    Net: net,
    Handler: s.mux,
  }
  go s.doRunListener(ds)
  return ds
}

var ErrNoSuchDomain = rerrorf(dns.RcodeNameError, "no such domain")
var ErrNotInZone = rerrorf(dns.RcodeRefused, "domain not in zone")
var ErrNoResults = rerrorf(0, "no results")

type Tx struct {
  req *dns.Msg
  res *dns.Msg
  qname  string
  qtype  uint16
  qclass uint16
  s      *Server
  rcode  int

  typesAtQname map[uint16]struct{}
  soa *dns.SOA
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
  tx.typesAtQname = map[uint16]struct{}{}

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

func (tx *Tx) blookup(qname string) (rrs []dns.RR, err error) {
  log.Info("blookup: ", qname)
  rrs, err = tx.s.b.Lookup(qname)
  if err == nil && len(rrs) == 0 {
    err = ErrNoResults
  }
  return
}


func rrsetHasType(rrs []dns.RR, t uint16) dns.RR {
  for i := range rrs {
    if rrs[i].Header().Rrtype == t {
      return rrs[i]
    }
  }
  return nil
}

func (tx *Tx) addAnswers() error {
  err := tx.addAnswersMain()
  if err != nil {
    return err
  }

  // If we are at the zone apex...
  if _, ok := tx.typesAtQname[dns.TypeSOA]; tx.soa != nil && ok {
    // Add DNSKEYs.
    if tx.istype(dns.TypeDNSKEY) {
      tx.s.ksk.Hdr.Name = tx.soa.Hdr.Name
      tx.s.zsk.Hdr.Name = tx.s.ksk.Hdr.Name

      tx.res.Answer = append(tx.res.Answer, tx.s.ksk)
      tx.res.Answer = append(tx.res.Answer, &tx.s.zsk)
    }

    tx.typesAtQname[dns.TypeDNSKEY] = struct{}{}
  }

  err = tx.addNSEC()
  if err != nil {
    return err
  }

  err = tx.signResponse()
  if err != nil {
    return err
  }

  return nil
}

func (tx *Tx) addAnswersMain() error {
  var soa *dns.SOA
  var origq []dns.RR
  var origerr error
  var firsterr error
  nss := []*dns.NS{}
  var firsttype uint16

  // We have to find out the zone root by trying to find SOA for progressively shorter domain names.
  norig := strings.TrimRight(tx.qname, ".")
  n := norig

A:
  for len(n) > 0 {
    rrs, err := tx.blookup(n)
    if len(n) == len(norig) { // keep track of the results for the original qname
      origq = rrs
      origerr = err
    }
    if err == nil { // success
      for i := range rrs {
        t := rrs[i].Header().Rrtype
        switch t {
          case dns.TypeSOA:
            // found the apex of the closest zone for which we are authoritative
            // We haven't found any nameservers at this point, so we can serve without worrying about delegations.
            if soa == nil {
              soa = rrs[i].(*dns.SOA)
            }

            if firsttype == 0 {
              firsttype = dns.TypeSOA
            }

            break A

          case dns.TypeNS:
            // found an NS on the path; we are not authoritative for this owner or anything under it
            // We need to return Authority data regardless of the nature of the query.
            nss = append(nss, rrs[i].(*dns.NS))

            if firsttype == 0 {
              firsttype = dns.TypeNS
            }

          default:
        }
      }
    } else if firsterr == nil {
      firsterr = err
    }

    nidx := strings.Index(n, ".")
    if nidx < 0 {
      break
    }
    n = n[nidx+1:]
  }

  if soa == nil {
    // If we didn't even get a SOA at any point, we don't have any appropriate zone for this query.
    return ErrNotInZone
  }

  tx.soa = soa

  // firsttype is now either dns.TypeSOA or dns.TypeNS
  if firsttype == dns.TypeSOA {
    // We got a SOA first, so we're not a delegation even if we have NS.
    return tx.addAnswersAuthoritative(origq, origerr)
  } else if firsttype == dns.TypeNS {
    // We have a delegation.
    return tx.addAnswersDelegation(nss)
  } else {
    // This should not be possible.
    panic("unreachable")
  }
}

func (tx *Tx) addAnswersAuthoritative(rrs []dns.RR, origerr error) error {
  // A call to blookup either succeeds or fails.
  //
  // If it fails:
  //   ErrNotInZone     -- you're looking fundamentally in the wrong place; if there is no other
  //                       appropriate zone, fail with REFUSED
  //   ErrNoSuchDomain  -- there are no records at this name of ANY type, nor are there at any
  //                       direct or indirect descendant domain; fail with NXDOMAIN
  //   ErrNoResult      -- There are no records of the given type of class. However, there are
  //                       other records at the given domain and/or records at a direct or
  //                       indirect descendant domain; NOERROR
  //   any other error  -- SERVFAIL
  //
  // If it succeeds:
  //   If there are zero records, treat the response as ErrNoResult above. Otherwise, each record
  //   can be classified into one of the following categories:
  //
  //     - A NS record not at the zone apex and thus not authoritative (handled in addAnswersDelegation)
  //
  //     - A record not within the zone and thus not authoritative (glue records)
  //
  //     - A CNAME record (must not be glue) (TODO: DNAME)
  //
  //     - Any other record
  if origerr != nil {
    return origerr
  }

  cn := rrsetHasType(rrs, dns.TypeCNAME)
  if cn != nil && !tx.istype(dns.TypeCNAME) {
    // We have an alias.
    // TODO: check that the CNAME record is actually in the zone and not some bizarro CNAME glue record
    return tx.addAnswersCNAME(cn.(*dns.CNAME))
  }

  // Add every record which was requested.
  for i := range rrs {
    t := rrs[i].Header().Rrtype
    if tx.istype(t) {
      tx.res.Answer = append(tx.res.Answer, rrs[i])
    }

    // Keep track of the types that really do exist here in case we have to NSEC.
    tx.typesAtQname[t] = struct{}{}
  }

  if len(tx.res.Answer) == 0 {
    // no matching records, hand out the SOA
    tx.res.Ns = append(tx.res.Ns, tx.soa)
  }

  return nil
}

func (tx *Tx) addAnswersCNAME(cn *dns.CNAME) error {
  tx.res.Answer = append(tx.res.Answer, cn)
  return nil
}

func (tx *Tx) addAnswersDelegation(nss []*dns.NS) error {
  log.Info("TODO: DELEGATION")

  // Note that this is not authoritative data and thus does not get signed.
  for _, ns := range nss {
    tx.res.Ns = append(tx.res.Ns, ns)
  }

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

  if len(tx.res.Answer) == 0 {
    log.Info("adding NSEC3")
    err := tx.addNSEC3RR()
    if err != nil {
      return err
    }
  }

  return nil
}

func (tx *Tx) addNSEC3RR() error {
  tbm := []uint16{}
  for t, _ := range tx.typesAtQname {
    tbm = append(tbm, t)
  }

  // The DNS library is buggy unless tbm is sorted.
  sort.Sort(uint16Slice(tbm))

  //log.Info("NSEC3: qname=", tx.qname, "  base=", tx.basename, "  root=", tx.rootname)
  nsr1n  := dns.HashName(tx.qname, dns.SHA1, 1, "8F")
  nsr1nn := stepName(nsr1n)
  nsr1   := &dns.NSEC3 {
    Hdr: dns.RR_Header {
      Name: absname(nsr1n + "." + tx.soa.Hdr.Name),
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

// © 2014 Hugo Landau <hlandau@devever.net>      GPLv3 or later
