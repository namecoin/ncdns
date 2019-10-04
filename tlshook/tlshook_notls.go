// +build no_namecoin_tls

package tlshook

import (
	"github.com/namecoin/ncdns/ncdomain"
)

func DomainValueHookTLS(qname string, ncv *ncdomain.Value) error {
	return nil
}
