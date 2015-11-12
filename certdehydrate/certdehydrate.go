package certdehydrate

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

import "github.com/namecoin/ncdns/x509"

// TODO: add a version field
type DehydratedCertificate struct {
	PubkeyB64 string
	NotBeforeScaled int64
	NotAfterScaled int64
	SignatureAlgorithm int64
	SignatureB64 string
}

func (dehydrated DehydratedCertificate) SerialNumber(name string) ([]byte, error){

	nameHash := sha256.Sum256([]byte(name))

	pubkeyBytes, err := base64.StdEncoding.DecodeString(dehydrated.PubkeyB64)
	if err != nil {
		return nil, fmt.Errorf("Dehydrated cert pubkey is not valid base64: %s", err)
	}
	pubkeyHash := sha256.Sum256(pubkeyBytes)

	notBeforeScaledBuf := new(bytes.Buffer)
	err = binary.Write(notBeforeScaledBuf, binary.BigEndian, dehydrated.NotBeforeScaled)
	if err != nil {
		return nil, fmt.Errorf("binary.Write of notBefore failed: %s", err)
	}
	notBeforeHash := sha256.Sum256(notBeforeScaledBuf.Bytes())

	notAfterScaledBuf := new(bytes.Buffer)
	err = binary.Write(notAfterScaledBuf, binary.BigEndian, dehydrated.NotAfterScaled)
	if err != nil {
		return nil, fmt.Errorf("binary.Write of notAfter failed: %s", err)
	}
	notAfterHash := sha256.Sum256(notAfterScaledBuf.Bytes())

	serialHash := sha256.New()
	serialHash.Write(nameHash[:])
	serialHash.Write(pubkeyHash[:])
	serialHash.Write(notBeforeHash[:])
	serialHash.Write(notAfterHash[:])

	// 19 bytes will be less than 2^159, see https://crypto.stackexchange.com/a/260
	return serialHash.Sum(nil)[0:19], nil
}

func (dehydrated DehydratedCertificate) String() string {
	output := []interface{}{1, dehydrated.PubkeyB64, dehydrated.NotBeforeScaled, dehydrated.NotAfterScaled, dehydrated.SignatureAlgorithm, dehydrated.SignatureB64}
	binOutput, _ := json.Marshal(output)
	return string(binOutput)
}

func ParseDehydratedCert(data interface{}) (*DehydratedCertificate, error) {
	dehydrated, ok := data.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Dehydrated cert is not a list")
	}

	if len(dehydrated) < 1 {
		return nil, fmt.Errorf("Dehydrated cert must have a version field")
	}

	version, ok := dehydrated[0].(float64)
	if !ok {
		return nil, fmt.Errorf("Dehydrated cert version must be an integer")
	}

	if version != 1 {
		return nil, fmt.Errorf("Dehydrated cert has an unrecognized version")
	}

	if len(dehydrated) < 6 {
		return nil, fmt.Errorf("Dehydrated cert must have 6 items")
	}

	pubkeyB64, ok := dehydrated[1].(string)
	if !ok {
		return nil, fmt.Errorf("Dehydrated cert pubkey must be a string")
	}

	notBeforeScaled, ok := dehydrated[2].(float64)
	if !ok {
		return nil, fmt.Errorf("Dehydrated cert notBefore must be an integer")
	}

	notAfterScaled, ok := dehydrated[3].(float64)
	if !ok {
		return nil, fmt.Errorf("Dehydrated cert notAfter must be an integer")
	}

	signatureAlgorithm, ok := dehydrated[4].(float64)
	if !ok {
		return nil, fmt.Errorf("Dehydrated cert signature algorithm must be an integer")
	}

	signatureB64, ok := dehydrated[5].(string)
	if !ok {
		return nil, fmt.Errorf("Dehydrated cert signature must be a string")
	}

	result := DehydratedCertificate {
		PubkeyB64:             pubkeyB64,
		NotBeforeScaled:       int64(notBeforeScaled),
		NotAfterScaled:        int64(notAfterScaled),
		SignatureAlgorithm:    int64(signatureAlgorithm),
		SignatureB64:          signatureB64,
	}

	return &result, nil
}

func DehydrateCert(cert *x509.Certificate) (*DehydratedCertificate, error) {

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal parsed public key: %s", err)
	}

	pubkeyB64 := base64.StdEncoding.EncodeToString(pubkeyBytes)

	notBeforeInt := cert.NotBefore.Unix()
	notAfterInt := cert.NotAfter.Unix()

	timestampPrecision := int64(5 * 60) // 5 minute precision

	notBeforeScaled := notBeforeInt / timestampPrecision
	notAfterScaled := notAfterInt / timestampPrecision

	signatureAlgorithm := int64(cert.SignatureAlgorithm)
	signatureBytes := cert.Signature
	signatureB64 := base64.StdEncoding.EncodeToString(signatureBytes)

	result := DehydratedCertificate{
		PubkeyB64:             pubkeyB64,
		NotBeforeScaled:       notBeforeScaled,
		NotAfterScaled:        notAfterScaled,
		SignatureAlgorithm:    signatureAlgorithm,
		SignatureB64:          signatureB64,
	}

	return &result, nil
}

// Accepts as input the bare minimum data needed to produce a valid cert.
// The input is untrusted.
// The output is safe.
// The timestamps are in 5-minute increments.
func RehydrateCert(dehydrated *DehydratedCertificate) (*x509.Certificate, error) {

	pubkeyBin, err := base64.StdEncoding.DecodeString(dehydrated.PubkeyB64)
	if err != nil {
		return nil, fmt.Errorf("Dehydrated cert pubkey must be valid base64: %s", err)
	}

	pubkey, err := x509.ParsePKIXPublicKey(pubkeyBin)
	if err != nil {
		return nil, fmt.Errorf("Dehydrated cert pubkey is invalid: %s", err)
	}

	timestampPrecision := int64(5 * 60) // 5 minute precision

	notBeforeInt := dehydrated.NotBeforeScaled * timestampPrecision
	notAfterInt := dehydrated.NotAfterScaled * timestampPrecision

	notBefore := time.Unix(int64(notBeforeInt), 0)
	notAfter := time.Unix(int64(notAfterInt), 0)

	signatureAlgorithm := x509.SignatureAlgorithm(dehydrated.SignatureAlgorithm)

	signature, err := base64.StdEncoding.DecodeString(dehydrated.SignatureB64)
	if err != nil {
		return nil, fmt.Errorf("Dehydrated cert signature must be valid base64: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore: notBefore,
		NotAfter: notAfter,

		// x509.KeyUsageKeyEncipherment is used for RSA key exchange, but not DHE/ECDHE key exchange.  Since everyone should be using ECDHE (due to forward secrecy), we disallow x509.KeyUsageKeyEncipherment in our template.
		//KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		KeyUsage:              x509.KeyUsageDigitalSignature, 

		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		SignatureAlgorithm: signatureAlgorithm,
		PublicKey: pubkey,
		Signature: signature,
	}

	return &template, nil
}

func FillRehydratedCertTemplate(template x509.Certificate, name string) ([]byte, error) {

	template.Subject = pkix.Name{
		CommonName: name,
		SerialNumber: "Namecoin TLS Certificate",
	}

	// DNS name
	template.DNSNames = append(template.DNSNames, name)

	// Serial number
	dehydrated, err := DehydrateCert(&template)
	if err != nil {
		return nil, fmt.Errorf("Error dehydrating filled cert template: %s", err)
	}
	serialNumberBytes, err := dehydrated.SerialNumber(name)
	if err != nil {
		return nil, fmt.Errorf("Error calculating serial number: %s", err)
	}
	template.SerialNumber.SetBytes(serialNumberBytes)

	derBytes, err := x509.CreateCertificateWithSplicedSignature(&template, &template)
	if err != nil {
		return nil, fmt.Errorf("Error splicing signature: %s", err)
	}

	return derBytes, nil

}
