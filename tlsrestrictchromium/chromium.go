package tlsrestrictchromium

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/miekg/dns"
)

// DNSHash converts an FQDN to DNS wire format, takes the SHA256 of it, and
// then returns the result as a base64-encoded string.  This happens to be how
// Chromium's HSTS/HPKP database internally stores domain names.
func DNSHash(fqdn string) (string, error) {
	domainNamePacked := make([]byte, 256)
	offset, err := dns.PackDomainName(fqdn, domainNamePacked, 0, nil, false)
	if err != nil {
		return "", fmt.Errorf("Error packing domain name %s: %s", fqdn, err)
	}

	domainNameHashBytes := sha256.Sum256(domainNamePacked[:offset])
	domainNameHashB64String := base64.StdEncoding.EncodeToString(domainNameHashBytes[:])

	return domainNameHashB64String, nil
}

// BlockAllCAs returns an HSTS/HPKP rule (serializable to Chromium JSON format)
// that blacklists all built-in CA's from signing certs for subdomains of the
// given domain name.  It doesn't include the domain name.  It has only been
// tested with TLD's; it is unclear whether the rule will have any undesired
// effects if applied to a 2nd-level (or higher level) domain name.
func BlockAllCAs() (map[string]interface{}, error) {
	ruleJSON := `{
		"dynamic_spki_hashes": [ "" ],
		"dynamic_spki_hashes_expiry": 99999999999.9999,
		"expiry": 99999999999.9999,
		"mode": "force-https",
		"pkp_include_subdomains": true,
		"pkp_observed": 1.0000,
		"report-uri": "",
		"sts_include_subdomains": false,
		"sts_observed": 1.0000
	}`

	var rule map[string]interface{}

	err := json.Unmarshal([]byte(ruleJSON), &rule)
	if err != nil {
		return nil, fmt.Errorf("Error parsing BlockAllCAs rule: %s", err)
	}

	sleeve, err := Sleeve256()
	if err != nil {
		return nil, fmt.Errorf("Error generating sleeve256: %s", err)
	}
	rule["dynamic_spki_hashes"].([]interface{})[0] = "sha256/" + sleeve

	return rule, nil
}

// Sleeve256 calculates floor(2**256/pi), and encodes the result as base64.  It
// is intended to be used as a SHA256 hash where I don't have a preimage up my
// sleeve.
//
// Python2 version originally by Ryan Castellucci.  Go port, pi sourcing, and
// base64 output by Jeremy Rand.
func Sleeve256() (string, error) {
	var pi big.Float
	var exp256Float big.Float
	var fraction big.Float

	var exp256 big.Int
	var fractionFloored big.Int

	// 1024 bits of precision
	pi.SetPrec(1024)
	exp256Float.SetPrec(1024)
	fraction.SetPrec(1024)

	// 1000 digits of pi from https://www.angio.net/pi/digits/1000.txt (first HTTPS result in Startpage results for "digits of pi")
	// (retrieved 2017 May 13.)
	piString := "3.141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067982148086513282306647093844609550582231725359408128481117450284102701938521105559644622948954930381964428810975665933446128475648233786783165271201909145648566923460348610454326648213393607260249141273724587006606315588174881520920962829254091715364367892590360011330530548820466521384146951941511609433057270365759591953092186117381932611793105118548074462379962749567351885752724891227938183011949129833673362440656643086021394946395224737190702179860943702770539217176293176752384674818467669405132000568127145263560827785771342757789609173637178721468440901224953430146549585371050792279689258923542019956112129021960864034418159813629774771309960518707211349999998372978049951059731732816096318595024459455346908302642522308253344685035261931188171010003137838752886587533208381420617177669147303598253490428755468731159562863882353787593751957781857780532171226806613001927876611195909216420198"

	_, _, err := pi.Parse(piString, 10)
	if err != nil {
		return "", fmt.Errorf("Error parsing pi: %s", err)
	}

	exp256.Exp(big.NewInt(2), big.NewInt(256), nil)
	exp256Float.SetInt(&exp256)

	fraction.Quo(&exp256Float, &pi)
	fraction.Int(&fractionFloored)

	resultHex := fractionFloored.Text(16)

	resultBytes, err := hex.DecodeString(resultHex)
	if err != nil {
		return "", fmt.Errorf("Error decoding hex: %s", err)
	}

	resultB64 := base64.StdEncoding.EncodeToString(resultBytes)

	return resultB64, nil
}
