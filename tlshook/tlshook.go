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

			// For non-dehydrated certificates
			// TODO: test this code.
			//       since this code has not been tested yet, it's disabled for safety reasons.
			//if len(port.TLSA) > 0 {
			if false {
				
				log.Info("Just saw a TLS port 443 capable domain request for ", qname, "!")
				
				for index, cert := range port.TLSA {
					
					// cert usage 3 is end-entity cert that need not pass CA-based validation
					// cert selector 0 is a full certificate (not just public key)
					// cert matching type 0 is exact match (not hashed)
					if cert.Usage == 3 && cert.Selector == 0 && cert.MatchingType == 0 {
					
						log.Info("Certificate # ", index, " is usable with hex value ", cert.Certificate)
						
						origCertBytes, err:= hex.DecodeString(cert.Certificate)
						if err != nil {
							log.Info("Failed to decode hex string of TLSA certificate, ", err)
							continue
						}
						
						origCert, err := x509.ParseCertificate(origCertBytes)
						if err != nil {
							log.Info("Failed to parse TLSA certificate, ", err)
							continue
						}
						
						// TODO: look into being a bit more flexible with cert serial number, validity period, and subject serial number.
						//       The uniformity in those fields is due to compression rather than security concerns.
						//       So we could possibly pass those through in cases like this.
						//       Subject serial number is also there due to transparency concerns, so maybe don't allow customizing it.
						
						dehydrated, err := certdehydrate.DehydrateCert(origCert)
						if err != nil {
							log.Info("Failed to dehydrate TLSA certificate, ", err)
							continue
						}
						
						rehydrated, err := certdehydrate.RehydrateCert(dehydrated)
						if err != nil {
							log.Info("Failed to rehydrate TLSA certificate, ", err)
							continue
						}
						
						rehydratedDerBytes, err := certdehydrate.FillRehydratedCertTemplate(*rehydrated, qname)
						if err != nil {
							log.Info("Failed to fill rehydrated TLSA certificate, ", err)
							continue
						}
						
						if ! bytes.Equal(origCertBytes, rehydratedDerBytes) {
							log.Info("TLSA certificate didn't conform to dehydration template; skipping certificate.")
							continue
						}
						
						// TODO: check return value
						certinject.InjectCert(rehydratedDerBytes)
						
					} else {
					
						log.Info("Certificate # ", index, " is not usable because we cannot recover the full end-entity certificate from the TLSA record.")
					
					}
					
				}
			}
		}
	}

	// remove any certs that aren't valid anymore
	certinject.CleanCerts()

	err = nil

	return

}
