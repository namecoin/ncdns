package certdehydrate_test

import (
	"encoding/json"
	"github.com/namecoin/ncdns/certdehydrate"
	"reflect"
	"testing"
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
