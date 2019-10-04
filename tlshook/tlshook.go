// +build !no_namecoin_tls

package tlshook

import (
	"github.com/hlandau/xlog"
	"github.com/namecoin/ncdns/certdehydrate"
	"github.com/namecoin/ncdns/certinject"
	"github.com/namecoin/ncdns/ncdomain"
)

var log, Log = xlog.New("ncdns.tlshook")

func DomainValueHookTLS(qname string, ncv *ncdomain.Value) (err error) {

	log.Info("Intercepted a Value for ", qname)
	if protocol, ok := ncv.Map["_tcp"]; ok { // TODO: look into allowing non-TCP protocols
		log.Info("Saw a request with TCP")
		if port, ok := protocol.Map["_443"]; ok { // TODO: check all ports, not just 443
			log.Info("Saw a request with TCP port 443")

			// For dehydrated certificates
			if len(port.TLSAGenerated) > 0 {

				log.Info("Just saw a TLS port 443 capable domain request for ", qname, "!")

				for index, cert := range port.TLSAGenerated {

					log.Info("Using dehydrated certificate # ", index)

					template := cert

					var derBytes []byte

					derBytes, err = certdehydrate.FillRehydratedCertTemplate(template, qname)
					if err != nil {
						log.Info("Failed to create certificate: ", err)
						continue
					}

					// TODO: check return value
					certinject.InjectCert(derBytes)

				}

			}

			// TODO: support non-dehydrated certificates
		}
	}

	// remove any certs that aren't valid anymore
	certinject.CleanCerts()

	err = nil

	return

}
