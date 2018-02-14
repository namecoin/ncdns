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

	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

}

func cleanCertsNss() {

	if certDir.Value() == "" {
		log.Fatal("Empty nsscertdir configuration.")
	}
	if nssDir.Value() == "" {
		log.Fatal("Empty nssdbdir configuration.")
	}

	certFiles, _ := ioutil.ReadDir(certDir.Value() + "/")

	// for all Namecoin certs in the folder
	for _, f := range certFiles {

		// Check if the cert is expired
		expired, err := checkCertExpiredNss(f)
		if err != nil {
			log.Fatal(err)
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

			err := cmd.Run()
			if err != nil {
				log.Fatal(err)
			}

			// Also delete the cert from the filesystem
			err = os.Remove(certDir.Value() + "/" + filename)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

}

func checkCertExpiredNss(certFile os.FileInfo) (bool, error) {

	// Get the last modified time
	certFileModTime := certFile.ModTime()

	// If the cert's last modified timestamp differs too much from the
	// current time in either direction, consider it expired
	expired := math.Abs(time.Since(certFileModTime).Seconds()) >
		float64(certExpirePeriod.Value())

	return expired, nil

}

func nicknameFromFingerprintHexNss(fingerprintHex string) string {
	return "Namecoin-" + fingerprintHex
}
