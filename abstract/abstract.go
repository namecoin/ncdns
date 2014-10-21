package abstract
import "github.com/miekg/dns"

type Backend interface {
  // Lookup all resource records having a given fully-qualified owner name,
  // regardless of type or class. Returns a slice of all those resource records
  // or an error.
  //
  // The returned slice may contain both authoritative and non-authoritative records
  // (for example, NS records for delegations and glue records.)
  //
  // The existence of wildcard records will be determined by doing a lookup for a name
  // like "*.example.com", so there is no need to process the wildcard logic other than
  // to make sure such a lookup functions correctly.
  Lookup(qname string) (rrs []dns.RR, err error)
}
