//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package tlshook

import (
	"github.com/namecoin/ncdns/logconfig"
	"github.com/namecoin/ncdns/ncdomain"
)

var log = logconfig.New("ncdns.tlshook")

func DomainValueHookTLS(qname string, ncv *ncdomain.Value) (err error) {

	log.Info().Msgs("Intercepted a Value for ", qname)
	if protocol, ok := ncv.Map["_tcp"]; ok { // TODO: look into allowing non-TCP protocols
		log.Info().Msg("Saw a request with TCP")
		if _, ok := protocol.Map["_443"]; ok { // TODO: check all ports, not just 443
			log.Info().Msg("Saw a request with TCP port 443")

			// TODO: maybe find something to do here?
			// We used to do dehydrated certificate injection here, but that's ancient.
		}
	}

	err = nil

	return

}
