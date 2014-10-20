package main
import "encoding/base32"
import "fmt"
import "strings"
import "github.com/miekg/dns"
import "github.com/hlandau/degoutils/log"
import "time"

func splitDomainHead(name string) (head string, rest string, err error) {
  parts := strings.Split(name, ".")

  head = parts[len(parts)-1]

  if len(parts) >= 2 {
    rest = strings.Join(parts[0:len(parts)-1], ".")
  }

  return
}

// unused
func splitDomainName(name string) (parts []string) {
  if len(name) == 0 {
    return
  }

  if name[len(name)-1] == '.' {
    name = name[0:len(name)-1]
  }

  parts = strings.Split(name, ".")

  return
}

func (tx *Tx) istype(x uint16) bool {
  return tx.qtype == x || tx.qtype == dns.TypeANY
}

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

func (tx *Tx) useDNSSEC() bool {
  opt := tx.req.IsEdns0()
  if opt == nil {
    return false
  }
  return opt.Do()
}

func (tx *Tx) setRcode(x int) {
  if tx.rcode == 0 {
    tx.rcode = x
  }
}

type Error interface {
  error
  Rcode() int
}

type Rerr struct {
  error
  e error
  rcode int
}

func (re *Rerr) Error() string {
  return re.e.Error()
}

func (re *Rerr) Rcode() int {
  return re.rcode
}

func rerrorf(rcode int, fmts string, args ...interface{}) Error {
  re := &Rerr{}
  re.e = fmt.Errorf(fmts, args...)
  re.rcode = rcode
  return re
}

func rraMaxTTL(rra []dns.RR) uint32 {
  x := uint32(0)
  for _, rr := range rra {
    ttl := rr.Header().Ttl
    if ttl > x {
      x = ttl
    }
  }
  return x
}

func (tx *Tx) signRRs(rra []dns.RR, useKSK bool) (dns.RR, error) {
  if len(rra) == 0 {
    return nil, fmt.Errorf("no RRs to such")
  }

  maxttl := rraMaxTTL(rra)
  exp := time.Duration(maxttl)*time.Second + time.Duration(10)*time.Minute

  log.Info("maxttl: ", maxttl, "  expiration: ", exp)

  now := time.Now()
  rrsig := &dns.RRSIG {
    Hdr: dns.RR_Header { Ttl: maxttl, },
    Algorithm: dns.RSASHA256,
    Expiration: uint32(now.Add(exp).Unix()),
    Inception: uint32(now.Unix()),
    SignerName: absname(tx.soa.Hdr.Name),
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

func (tx *Tx) signResponseSection(rra *[]dns.RR) error {
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
      useKSK := (pt == dns.TypeDNSKEY)
      if useKSK {
        srr, err := tx.signRRs(a, true)
        if err != nil {
          return err
        }

        *rra = append(*rra, srr)
      }

      srr, err := tx.signRRs(a, false)
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

func (tx *Tx) signResponse() error {
  if !tx.useDNSSEC() {
    return nil
  }

  for _, r := range []*[]dns.RR { &tx.res.Answer, &tx.res.Ns, &tx.res.Extra } {
    err := tx.signResponseSection(r)
    if err != nil {
      log.Infoe(err, "fail signResponse")
      return err
    }
  }

  log.Info("done signResponse")
  return nil
}

type uint16Slice []uint16
func (p uint16Slice) Len() int { return len(p) }
func (p uint16Slice) Less(i, j int) bool { return p[i] < p[j] }
func (p uint16Slice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
