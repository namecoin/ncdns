package certinject

import "crypto/sha256"
import "encoding/hex"
import "io/ioutil"
import "os"
import "os/exec"
import "strings"
import "math"
import "time"
import "gopkg.in/hlandau/easyconfig.v1/cflag"

var certDir = cflag.String(flagGroup, "nsscertdir", "", "Directory to store "+
	"certificate files.  Only use a directory that only ncdns can write "+
	"to.  (Required if nss is set.)")
var nssDir = cflag.String(flagGroup, "nssdbdir", "", "Directory that "+
	"contains NSS's cert9.db.  (Required if nss is set.)")

func injectCertNss(derBytes []byte) {

	if certDir.Value() == "" {
		log.Fatal("Empty nsscertdir configuration.")
	}
	if nssDir.Value() == "" {
		log.Fatal("Empty nssdbdir configuration.")
	}

	fingerprint := sha256.Sum256(derBytes)

	fingerprintHex := hex.EncodeToString(fingerprint[:])

	path := certDir.Value() + "/" + fingerprintHex + ".pem"

	injectCertFile(derBytes, path)

	nickname := nicknameFromFingerprintHexNss(fingerprintHex)

	// TODO: check whether we can replace CP with just P.
	cmd := exec.Command(nssCertutilName, "-d", "sql:"+nssDir.Value(), "-A",
		"-t", "CP,,", "-n", nickname, "-a", "-i", path)

	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(stdoutStderr), "SEC_ERROR_PKCS11_GENERAL_ERROR") {
			log.Warn("Temporary SEC_ERROR_PKCS11_GENERAL_ERROR injecting certificate to NSS database; retrying in 1ms...")
			time.Sleep(1 * time.Millisecond)
			injectCertNss(derBytes)
		} else {
			log.Errorf("Error injecting cert to NSS database: %s\n%s", err, stdoutStderr)
		}
	}

}

func cleanCertsNss() {

	if certDir.Value() == "" {
		log.Fatal("Empty nsscertdir configuration.")
	}
	if nssDir.Value() == "" {
		log.Fatal("Empty nssdbdir configuration.")
	}

	certFiles, err := ioutil.ReadDir(certDir.Value() + "/")
	if err != nil {
		log.Fatalf("Error enumerating files in cert directory: %s", err)
	}

	// for all Namecoin certs in the folder
	for _, f := range certFiles {

		// Check if the cert is expired
		expired, err := checkCertExpiredNss(f)
		if err != nil {
			log.Fatalf("Error checking if NSS cert is expired: %s", err)
		}

		// delete the cert if it's expired
		if expired {

			filename := f.Name()

			fingerprintHex := strings.Replace(filename, ".pem", "",
				-1)

			nickname := nicknameFromFingerprintHexNss(
				fingerprintHex)

			// Delete the cert from NSS
			cmd := exec.Command(nssCertutilName, "-d", "sql:"+
				nssDir.Value(), "-D", "-n", nickname)

			stdoutStderr, err := cmd.CombinedOutput()
			if err != nil {
				if strings.Contains(string(stdoutStderr), "SEC_ERROR_UNRECOGNIZED_OID") {
					log.Warn("Tried to delete certificate from NSS database, but the certificate was already not present in NSS database")
				} else if strings.Contains(string(stdoutStderr), "SEC_ERROR_PKCS11_GENERAL_ERROR") {
					log.Warn("Temporary SEC_ERROR_PKCS11_GENERAL_ERROR deleting certificate from NSS database; retrying in 1ms...")
					time.Sleep(1 * time.Millisecond)
					cleanCertsNss()
				} else {
					log.Fatalf("Error deleting cert from NSS database: %s\n%s", err, stdoutStderr)
				}
			}

			// Also delete the cert from the filesystem
			err = os.Remove(certDir.Value() + "/" + filename)
			if err != nil {
				log.Fatalf("Error deleting NSS cert from filesystem: %s", err)
			}
		}
	}

}

func checkCertExpiredNss(certFile os.FileInfo) (bool, error) {

	// Get the last modified time
	certFileModTime := certFile.ModTime()

	age := time.Since(certFileModTime)
	ageSeconds := age.Seconds()

	// If the cert's last modified timestamp differs too much from the
	// current time in either direction, consider it expired
	expired := math.Abs(ageSeconds) > float64(certExpirePeriod.Value())

	log.Debugf("Age of certificate: %s = %f seconds; expired = %t", age, ageSeconds, expired)

	return expired, nil

}

func nicknameFromFingerprintHexNss(fingerprintHex string) string {
	return "Namecoin-" + fingerprintHex
}
