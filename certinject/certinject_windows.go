package certinject

import (
	"github.com/hlandau/xlog"
	"gopkg.in/hlandau/easyconfig.v1/cflag"
)

// This package is used to add and remove certificates to the system trust
// store.
// Currently only supports Windows CryptoAPI and NSS sqlite3 stores.

var log, Log = xlog.New("ncdns.certinject")

var (
	cryptoApiFlag = cflag.Bool(flagGroup, "cryptoapi", false, "Synchronize TLS certs to the CryptoAPI trust store?  This enables HTTPS to work with Chromium/Chrome.  Only use if you've set up NUMS HPKP in Chromium/Chrome as per documentation.  If you haven't set up NUMS HPKP, or if you access ncdns from browsers not based on Chromium or Firefox, this is unsafe and should not be used.")
)

// Injects the given cert into all configured trust stores.
func InjectCert(derBytes []byte) {

	if cryptoApiFlag.Value() {
		injectCertCryptoApi(derBytes)
	}
	if nssFlag.Value() {
                injectCertNss(derBytes)
        }
}

// Cleans expired certs from all configured trust stores.
func CleanCerts() {

	if cryptoApiFlag.Value() {
		cleanCertsCryptoApi()
	}
	if nssFlag.Value() {
                cleanCertsNss()
        }

}
