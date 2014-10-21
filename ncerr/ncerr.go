package ncerr
import "github.com/miekg/dns"
import "fmt"

// An Error interface which allows an associated rcode to be queried.
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

// Standard errors.
var ErrNoSuchDomain = rerrorf(dns.RcodeNameError, "no such domain")
var ErrNotInZone = rerrorf(dns.RcodeRefused, "domain not in zone")
var ErrNoResults = rerrorf(0, "no results")
