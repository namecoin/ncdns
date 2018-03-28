package tlsoverridefirefox

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/namecoin/ncdns/util"
)

// OverrideFromRR returns a Firefox certificate override (in cert_override.txt
// format) derived from rr.  If no such override can be derived, returns an
// empty string.
func OverrideFromRR(rr dns.RR) (string, error) {
	tlsa, ok := rr.(*dns.TLSA)

	if !ok {
		return "", nil
	}

	portLabel, protocolLabelAndHost := util.SplitDomainTail(tlsa.Hdr.Name)
	protocolLabel, hostFQDN := util.SplitDomainTail(protocolLabelAndHost)

	if protocolLabel != "_tcp" {
		return "", nil
	}

	if !strings.HasPrefix(portLabel, "_") {
		return "", nil
	}

	port := strings.TrimPrefix(portLabel, "_")

	if !strings.HasSuffix(hostFQDN, ".") {
		return "", fmt.Errorf("TLSA not a FQDN")
	}

	host := strings.TrimSuffix(hostFQDN, ".")

	// SHA256, as per https://dxr.mozilla.org/mozilla-central/source/security/manager/ssl/nsCertOverrideService.cpp
	fingerprintAlgo := "OID.2.16.840.1.101.3.4.2.1"

	// Possible Usage values:
	// 0: CA constraint.  No override is necessary.
	// 1: Service certificate constraint.  No override is necessary.
	// 2: Trust anchor assertion.  Firefox doesn't support these.
	// 3: Domain-issued certificate.  Do an override in this case.

	if tlsa.Usage != 3 {
		return "", nil
	}

	// Only a full certificate selector can yield a SHA256 certificate
	// fingerprint.
	if tlsa.Selector != 0 {
		return "", nil
	}

	fingerprint, err := getFingerprint(tlsa)
	if err != nil {
		return "", nil
	}

	overrideMask := "U"

	// Format documented in https://dxr.mozilla.org/mozilla-central/source/security/manager/ssl/nsNSSCertificate.cpp
	// However, it looks empirically like we can just use 0-length serial
	// number and 0-length DN, and Firefox doesn't care.
	dbKey := base64.StdEncoding.EncodeToString([]byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	return host + ":" + port + "\t" + fingerprintAlgo + "\t" +
		fingerprint + "\t" + overrideMask + "\t" + dbKey + "\n", nil
}

func getFingerprint(tlsa *dns.TLSA) (string, error) {
	var fingerprint string

	// SHA512 fingerprint can't yield a SHA256 fingerprint
	if tlsa.MatchingType == 2 {
		return "", fmt.Errorf("SHA512 fingerprint can't yield a " +
			"SHA256 fingerprint")
	}

	if tlsa.MatchingType == 1 {
		// SHA256 fingerprint

		fingerprintBytes, err := hex.DecodeString(tlsa.Certificate)
		if err != nil {
			return "", err
		}

		fingerprint = insertColons(fingerprintBytes)
	} else if tlsa.MatchingType == 0 {
		// Exact match

		certificateBytes, err := hex.DecodeString(tlsa.Certificate)
		if err != nil {
			return "", err
		}

		fingerprintArray := sha256.Sum256(certificateBytes)

		fingerprint = insertColons(fingerprintArray[:])
	} else {
		// Unknown MatchingType
		return "", fmt.Errorf("Unknown MatchingType")
	}

	return strings.ToUpper(fingerprint), nil
}

// Based on FingerprintLegacyMD5 from
// https://github.com/golang/crypto/blob/master/ssh/keys.go
func insertColons(input []byte) string {
	hexarray := make([]string, len(input))
	for i, c := range input {
		hexarray[i] = hex.EncodeToString([]byte{c})
	}
	return strings.Join(hexarray, ":")
}
