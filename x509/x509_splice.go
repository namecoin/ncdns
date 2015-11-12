// Copyright 2009 The Go Authors, 2015-2016 Jeremy Rand. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This code is modified from the stock CreateCertificate to use a
// pre-existing signature.

// Last rebased on Go 1.6.2
//go:generate bash install.sh

// Package x509 parses X.509-encoded keys and certificates.
package x509

import (
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"
)

// CreateCertificate creates a new certificate based on a template. The
// following members of template are used: SerialNumber, Subject, NotBefore,
// NotAfter, KeyUsage, ExtKeyUsage, UnknownExtKeyUsage, BasicConstraintsValid,
// IsCA, MaxPathLen, SubjectKeyId, DNSNames, PermittedDNSDomainsCritical,
// PermittedDNSDomains, SignatureAlgorithm.
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// signee and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// All keys types that are implemented via crypto.Signer are supported (This
// includes *rsa.PublicKey and *ecdsa.PublicKey.)

//func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{}) (cert []byte, err error) {
func CreateCertificateWithSplicedSignature(template, parent *Certificate) (cert []byte, err error) {

	//key, ok := priv.(crypto.Signer)
	//if !ok {
	//	return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	//}

	//hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(key.Public(), template.SignatureAlgorithm)
	//if err != nil {
	//	return nil, err
	//}

	// This block added
	_, signatureAlgorithm, err := signingParamsForPublicKey(parent.PublicKey, template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	// This line added
	pub := template.PublicKey

	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}

	if len(parent.SubjectKeyId) > 0 {
		template.AuthorityKeyId = parent.SubjectKeyId
	}

	extensions, err := buildExtensions(template)
	if err != nil {
		return
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return
	}

	c.Raw = tbsCertContents

	//h := hashFunc.New()
	//h.Write(tbsCertContents)
	//digest := h.Sum(nil)

	//var signature []byte
	//signature, err = key.Sign(rand, digest, hashFunc)
	//if err != nil {
	//	return
	//}

	// This line added
	signature := template.Signature

	return asn1.Marshal(certificate{
		nil,
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}
