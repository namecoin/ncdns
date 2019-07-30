package certdehydrate_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/namecoin/ncdns/certdehydrate"
	"github.com/namecoin/x509-signature-splice/x509"
)

func TestDehydratedCertIdentityOperation(t *testing.T) {
	bytesJson := []byte(`[1, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/hy1t4jB14ronx6n1m8VQh02jblRfu2cV3/LcyomfVljypUQMGjmuxWNbPI0a3cF6miNOijSCutqTZdb7TLvig==",4944096,5049216,10,"MEQCIGXXk6gYx95vQoknRwiQ4e27I+DXUWkE8L6dmLwAiGncAiBbtEX1nnZINx1YGzT5Fx8SxpjLwNDTUBkq22NpazHLIA=="]`)

	var parsedJson []interface{}

	if err := json.Unmarshal(bytesJson, &parsedJson); err != nil {
		t.Error("Error parsing JSON:", err)
	}

	dehydrated, err := certdehydrate.ParseDehydratedCert(parsedJson)
	if err != nil {
		t.Error("Error parsing dehydrated certificate:", err)
	}

	template, err := certdehydrate.RehydrateCert(dehydrated)
	if err != nil {
		t.Error("Error rehydrating certificate:", err)
	}

	dehydrated2, err := certdehydrate.DehydrateCert(template)
	if err != nil {
		t.Error("Error dehydrating certificate:", err)
	}

	// Test to make sure that rehydrating and then dehydrating a cert doesn't change it.
	if !reflect.DeepEqual(dehydrated, dehydrated2) {
		t.Error(dehydrated, "!=", dehydrated2)
	}
}

func TestDehydratedCertSignatureValid(t *testing.T) {
	bytesJson := []byte(`[1,"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGm0zZlzrnwEYvub3BG3+VTKjvXWdMntoTanw3cwGAqcb0ALFrt5MdChT9t4josaefnGdVHa+ZBNmSEIaNZNhnw==",4944096,5154336,10,"MEUCIQCEkb4Q+AV8FsQgRoWSZ3S+1Ww/SySl4238SjTv5d/WAgIgX2rAhfCQ3gGG1Abhme8mDTG641vIYHJuz8d6m7IrgJo="]`)

	var parsedJson []interface{}

	if err := json.Unmarshal(bytesJson, &parsedJson); err != nil {
		t.Error("Error parsing JSON:", err)
	}

	dehydrated, err := certdehydrate.ParseDehydratedCert(parsedJson)
	if err != nil {
		t.Error("Error parsing dehydrated certificate:", err)
	}

	template, err := certdehydrate.RehydrateCert(dehydrated)
	if err != nil {
		t.Error("Error rehydrating certificate:", err)
	}

	derBytes, err := certdehydrate.FillRehydratedCertTemplate(*template, "www.veclabs.bit")
	if err != nil {
		t.Error("Error filling domain into rehydrated certificate template:", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Error("Error parsing DER certificate:", err)
	}

	// cert.CheckSignatureFrom(cert) won't work because the CA bit is disabled
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Error("Valid signature rejected:", err)
	}
}

func TestDehydratedCertSignatureInvalid(t *testing.T) {
	bytesJson := []byte(`[1,"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGm0zZlzrnwEYvub3BG3+VTKjvXWdMntoTanw3cwGAqcb0ALFrt5MdChT9t4josaefnGdVHa+ZBNmSEIaNZNhnw==",4944096,5154336,10,"MEUCIQCEkb4Q+AV8FsQgRoWSZ3S+1Ww/SySl4238SjTv5d/WAgIgX2rAhfCQ3gGG1Abhme8mDTG641vIYHJuz8d6m7IrgJo="]`)

	var parsedJson []interface{}

	if err := json.Unmarshal(bytesJson, &parsedJson); err != nil {
		t.Error("Error parsing JSON:", err)
	}

	dehydrated, err := certdehydrate.ParseDehydratedCert(parsedJson)
	if err != nil {
		t.Error("Error parsing dehydrated certificate:", err)
	}

	template, err := certdehydrate.RehydrateCert(dehydrated)
	if err != nil {
		t.Error("Error rehydrating certificate:", err)
	}

	derBytes, err := certdehydrate.FillRehydratedCertTemplate(*template, "www2.veclabs.bit")
	if err != nil {
		t.Error("Error filling domain into rehydrated certificate template:", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Error("Error parsing DER certificate:", err)
	}

	// cert.CheckSignatureFrom(cert) won't work because the CA bit is disabled
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err == nil {
		t.Error("Invalid signature accepted:", err)
	}
}
