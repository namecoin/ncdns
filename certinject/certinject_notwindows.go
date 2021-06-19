// +build !windows

package certinject

import "fmt"

// This package is used to add and remove certificates to the system trust
// store.
// Currently only supports NSS sqlite3 stores.

// InjectCert injects the given cert into all configured trust stores.
func InjectCert(derBytes []byte) error {
	if !nssFlag.Value() {
		return fmt.Errorf("no trusted store chosen, did you mean to use %q flag?", nssFlag.CfName())
	}
	if nssFlag.Value() {
		if err := injectCertNss(derBytes); err != nil {
			return err
		}
	}
	return nil
}

// CleanCerts cleans expired certs from all configured trust stores.
func CleanCerts() error {
	if !nssFlag.Value() {
		return fmt.Errorf("no trusted store chosen, did you mean to use %q flag?", nssFlag.CfName())
	}
	if nssFlag.Value() {
		if err := cleanCertsNss(); err != nil {
			return err
		}
	}
	return nil
}
