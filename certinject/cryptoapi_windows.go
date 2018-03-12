package certinject

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// In 64-bit Windows, this key is shared between 64-bit and 32-bit applications.
// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa384253.aspx
const cryptoApiCertStoreRegistryBase = registry.LOCAL_MACHINE
const cryptoApiCertStoreRegistryKey = `SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates`
const cryptoApiMagicName = "Namecoin"
const cryptoApiMagicValue = 1

func injectCertCryptoApi(derBytes []byte) {

	// Format documentation of Microsoft's "Certificate Registry Blob":

	// 5c 00 00 00 // propid
	// 01 00 00 00 // unknown (possibly a version or flags field; value is always the same in my testing)
	// 04 00 00 00 // size (little endian)
	// subject public key bit length // data[size]

	// 19 00 00 00
	// 01 00 00 00
	// 10 00 00 00
	// MD5 of ECC pubkey of certificate

	// 0f 00 00 00
	// 01 00 00 00
	// 20 00 00 00
	// Signature Hash

	// 03 00 00 00
	// 01 00 00 00
	// 14 00 00 00
	// Cert SHA1 hash

	// 14 00 00 00
	// 01 00 00 00
	// 14 00 00 00
	// Key Identifier

	// 04 00 00 00
	// 01 00 00 00
	// 10 00 00 00
	// Cert MD5 hash

	// 20 00 00 00
	// 01 00 00 00
	// cert length
	// cert

	// But, guess what?  All you need is the "20" record.
	// Windows will happily regenerate all the others for you, whenever you actually try to use the certificate.
	// How cool is that?

	// Length of cert
	certLength := len(derBytes)

	// Header for a stripped Windows Certificate Registry Blob
	certBlobHeader := []byte{0x20, 0, 0, 0, 0x01, 0, 0, 0, byte((certLength >> 0) & 0xFF), byte((certLength >> 8) & 0xFF), byte((certLength >> 16) & 0xFF), byte((certLength >> 24) & 0xFF)}

	// Construct the Blob
	certBlob := append(certBlobHeader, derBytes...)

	// Open up the cert store.
	certStoreKey, err := registry.OpenKey(cryptoApiCertStoreRegistryBase, cryptoApiCertStoreRegistryKey, registry.ALL_ACCESS)
	if err != nil {
		log.Errorf("Couldn't open cert store: %s", err)
		return
	}
	defer certStoreKey.Close()

	// Windows CryptoAPI uses the SHA-1 fingerprint to identify a cert.
	// This is probably a Bad Thing (TM) since SHA-1 is weak.
	// However, that's Microsoft's problem to fix, not ours.
	fingerprint := sha1.Sum(derBytes)

	// Windows CryptoAPI uses a hex string to represent the fingerprint.
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	// Windows CryptoAPI uses uppercase hex strings
	fingerprintHexUpper := strings.ToUpper(fingerprintHex)

	// Create the registry key in which we will store the cert.
	// The 2nd result of CreateKey is openedExisting, which tells us if the cert already existed.
	// This doesn't matter to us.  If true, the "last modified" metadata won't update,
	// but we delete and recreate the magic value inside it as a workaround.
	certKey, _, err := registry.CreateKey(certStoreKey, fingerprintHexUpper, registry.ALL_ACCESS)
	if err != nil {
		log.Errorf("Couldn't create registry key for certificate: %s", err)
		return
	}
	defer certKey.Close()

	// Add a magic value which indicates that the certificate is a
	// Namecoin cert.  This will be used for deleting expired certs.
	// However, we have to delete it before we create it, so that we make sure that the "last modified" metadata gets updated.
	// If an error occurs during deletion, we ignore it, since it probably just means it wasn't there already.
	_ = certKey.DeleteValue(cryptoApiMagicName)
	err = certKey.SetDWordValue(cryptoApiMagicName, cryptoApiMagicValue)
	if err != nil {
		log.Errorf("Couldn't set magic registry value for certificate: %s", err)
		return
	}

	// Create the registry value which holds the certificate.
	err = certKey.SetBinaryValue("Blob", certBlob)
	if err != nil {
		log.Errorf("Couldn't set blob registry value for certificate: %s", err)
		return
	}

}

func cleanCertsCryptoApi() {

	// Open up the cert store.
	certStoreKey, err := registry.OpenKey(cryptoApiCertStoreRegistryBase, cryptoApiCertStoreRegistryKey, registry.ALL_ACCESS)
	if err != nil {
		log.Errorf("Couldn't open cert store: %s", err)
		return
	}
	defer certStoreKey.Close()

	// get all subkey names in the cert store
	subKeys, err := certStoreKey.ReadSubKeyNames(0)
	if err != nil {
		log.Errorf("Couldn't list certs in cert store: %s", err)
		return
	}

	// for all certs in the cert store
	for _, subKeyName := range subKeys {

		// Check if the cert is expired
		expired, err := checkCertExpiredCryptoApi(certStoreKey, subKeyName)
		if err != nil {
			log.Errorf("Couldn't check if cert is expired: %s", err)
			return
		}

		// delete the cert if it's expired
		if expired {
			registry.DeleteKey(certStoreKey, subKeyName)
		}

	}

}

func checkCertExpiredCryptoApi(certStoreKey registry.Key, subKeyName string) (bool, error) {

	// Open the cert
	certKey, err := registry.OpenKey(certStoreKey, subKeyName, registry.ALL_ACCESS)
	if err != nil {
		return false, fmt.Errorf("Couldn't open cert registry key: %s", err)
	}
	defer certKey.Close()

	// Check for magic value
	isNamecoin, _, err := certKey.GetIntegerValue(cryptoApiMagicName)
	if err != nil {
		// Magic value wasn't found.  Therefore don't consider it expired.
		return false, nil
	}
	if isNamecoin != cryptoApiMagicValue {
		// Magic value was found but it wasn't the one we recognize.  Therefore don't consider it expired.
		return false, nil
	}

	// Get metadata about the cert key
	certKeyInfo, err := certKey.Stat()
	if err != nil {
		return false, fmt.Errorf("Couldn't read metadata for cert registry key: %s", err)
	}

	// Get the last modified time
	certKeyModTime := certKeyInfo.ModTime()

	// If the cert's last modified timestamp differs too much from the current time in either direction, consider it expired
	expired := math.Abs(time.Since(certKeyModTime).Seconds()) > float64(certExpirePeriod.Value())

	return expired, nil
}
