package certinject

import "crypto/sha256"
import "encoding/hex"
import "io/ioutil"
import "os"
import "os/exec"
import "strings"
import "math"
import "time"

var homeDir = os.Getenv("HOME")

var certDir = homeDir + "/.ncdns/certs"
var nssDir = "sql:" + homeDir + "/.pki/nssdb"

func injectCertNssShared(derBytes []byte) {

	fingerprint := sha256.Sum256(derBytes)

	fingerprintHex := hex.EncodeToString(fingerprint[:])

	path := certDir + "/" + fingerprintHex + ".pem"

	injectCertFile(derBytes, path)

	nickname := nicknameFromFingerprintHexNssShared(fingerprintHex)

	cmd := exec.Command("certutil", "-d", nssDir, "-A", "-t", "CP,,", "-n", nickname, "-a", "-i", path)

	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

}

func cleanCertsNssShared() {

	certFiles, _ := ioutil.ReadDir(certDir + "/")

	// for all Namecoin certs in the folder
	for _, f := range certFiles {

		// Check if the cert is expired
		expired, err := checkCertExpiredNssShared(f)
		if err != nil {
			log.Fatal(err)
		}

		// delete the cert if it's expired
		if expired {

			filename := f.Name()

			fingerprintHex := strings.Replace(filename, ".pem", "", -1)

			nickname := nicknameFromFingerprintHexNssShared(fingerprintHex)

			// Delete the cert from NSS
			cmd := exec.Command("certutil", "-d", nssDir, "-D", "-n", nickname)

			err := cmd.Run()
			if err != nil {
				log.Fatal(err)
			}

			// Also delete the cert from the filesystem
			err = os.Remove(certDir + "/" + filename)
		}
	}

}

func checkCertExpiredNssShared(certFile os.FileInfo) (bool, error) {

	// Get the last modified time
	certFileModTime := certFile.ModTime()

	// If the cert's last modified timestamp differs too much from the current time in either direction, consider it expired
	expired := math.Abs( time.Since(certFileModTime).Seconds() ) > float64(certExpirePeriod.Value())

	return expired, nil

}

func nicknameFromFingerprintHexNssShared(fingerprintHex string) string {
	return "Namecoin-" + fingerprintHex
}
