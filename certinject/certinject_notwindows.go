// +build !windows

package certinject

// This package is used to add and remove certificates to the system trust
// store.
// Currently only supports NSS sqlite3 stores.

// InjectCert injects the given cert into all configured trust stores.
func InjectCert(derBytes []byte) {

	if nssFlag.Value() {
		injectCertNss(derBytes)
	}
}

// CleanCerts cleans expired certs from all configured trust stores.
func CleanCerts() {

	if nssFlag.Value() {
		cleanCertsNss()
	}

}
