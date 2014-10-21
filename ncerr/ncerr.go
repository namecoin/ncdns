// Error types for processing DNS requests.
package ncerr

import "github.com/miekg/dns"
import "fmt"

// An Error interface which allows an associated rcode to be queried.
type Error interface {
  error

  // Returns the rcode which this error should be represented as in the DNS protocol.
  Rcode() int
}

type rerr struct {
  error
  e error
  rcode int
}

func (re *rerr) Error() string {
  return re.e.Error()
}

func (re *rerr) Rcode() int {
  return re.rcode
}

// Used to generate an Error which has a particular rcode. Otherwise like fmt.Errorf.
func Rerrorf(rcode int, fmts string, args ...interface{}) Error {
  re := &rerr{}
  re.e = fmt.Errorf(fmts, args...)
  re.rcode = rcode
  return re
}

// Standard errors.

// Represents NXDOMAIN. Used when the name requested lies within a zone for
// which this server is authoritative, but does not exist.
//
// Note that a name is considered to exist if there exist any records of any
// type at a name, even if those records were not requested or sent. A name is
// also considered to exist if there are any names under it.
//
// In other words, b.c should return NOERROR even if it has no records of any
// type if there is a record at a.b.c, or so on.
var ErrNoSuchDomain = Rerrorf(dns.RcodeNameError, "no such domain")

// Represents REFUSED, which we use when a request is received for a zone for
// which the server is not authoritative.
var ErrNotInZone = Rerrorf(dns.RcodeRefused, "domain not in zone")

// Represents NOERROR. This error is used when NXDOMAIN is not an appropriate
// response code, but no results were returned. (DNS also uses NOERROR when results
// are returned, but we return nil in that case.)
var ErrNoResults = Rerrorf(0, "no results")
