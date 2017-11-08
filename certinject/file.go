package certinject

import (
	"encoding/pem"
	"io/ioutil"
)

// Injects a certificate by writing to a file.  Might be relevant for non-CryptoAPI trust stores.
func injectCertFile(derBytes []byte, fileName string) {

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	err := ioutil.WriteFile(fileName, pemBytes, 0644)
	if err != nil {
		log.Errore(err, "Error writing cert!")
		return
	}
}
