// Copyright 2009 The Go Authors. All rights reserved.
// Modifications Copyright 2015-2018 Jeremy Rand. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This code is modified from the stock CreateCertificate to use a
// pre-existing signature.

// Last rebased on Go 1.10
// Remove all content between "import" and "CreateCertificate" in original.
// Remove all content after "CreateCertificate" in original.
//go:generate bash install.sh

// Package x509 parses X.509-encoded keys and certificates.
//
// On UNIX systems the environment variables SSL_CERT_FILE and SSL_CERT_DIR
// can be used to override the system default locations for the SSL certificate
// file and SSL certificate files directory, respectively.
package x509

import (
	"bytes"
	//"crypto"
	//"crypto/dsa"
	//"crypto/ecdsa"
	//"crypto/elliptic"
	//"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	//"crypto/x509/pkix"
	"encoding/asn1"
	//"encoding/pem"
	"errors"
	//"fmt"
	//"io"
	//"math/big"
	//"net"
	//"net/url"
	//"strconv"
	//"strings"
	//"time"
	//"unicode/utf8"
	//
	//"golang_org/x/crypto/cryptobyte"
	//cryptobyte_asn1 "golang_org/x/crypto/cryptobyte/asn1"
)

// CreateCertificate creates a new X.509v3 certificate based on a template.
// The following members of template are used: AuthorityKeyId,
// BasicConstraintsValid, DNSNames, ExcludedDNSDomains, ExtKeyUsage,
// IsCA, KeyUsage, MaxPathLen, MaxPathLenZero, NotAfter, NotBefore,
// PermittedDNSDomains, PermittedDNSDomainsCritical, SerialNumber,
// SignatureAlgorithm, Subject, SubjectKeyId, and UnknownExtKeyUsage.
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// signee and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// All keys types that are implemented via crypto.Signer are supported (This
// includes *rsa.PublicKey and *ecdsa.PublicKey.)
//
// The AuthorityKeyId will be taken from the SubjectKeyId of parent, if any,
// unless the resulting certificate is self-signed. Otherwise the value from
// template will be used.
//func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{}) (cert []byte, err error) {
func CreateCertificateWithSplicedSignature(template, parent *Certificate) (cert []byte, err error) {
	//key, ok := priv.(crypto.Signer)
	//if !ok {
	//	return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	//}

	if template.SerialNumber == nil {
		return nil, errors.New("x509: no SerialNumber given")
	}

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

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return
	}

	authorityKeyId := template.AuthorityKeyId
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}

	extensions, err := buildExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), authorityKeyId)
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

	//var signerOpts crypto.SignerOpts
	//signerOpts = hashFunc
	//if template.SignatureAlgorithm != 0 && template.SignatureAlgorithm.isRSAPSS() {
	//	signerOpts = &rsa.PSSOptions{
	//		SaltLength: rsa.PSSSaltLengthEqualsHash,
	//		Hash:       hashFunc,
	//	}
	//}

	//var signature []byte
	//signature, err = key.Sign(rand, digest, signerOpts)
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
