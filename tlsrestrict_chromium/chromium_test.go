package tlsrestrict_chromium_test

import (
	"testing"
	"github.com/namecoin/ncdns/tlsrestrict_chromium"
)

func TestDnsHash(t *testing.T) {
	bitHash, err := tlsrestrict_chromium.DnsHash("bit.")
	if err != nil {
		t.Error(err)
	}

	reference := "nprXwzm7mHINFnNah1Seo5SG0Pz9vW6dTXsYyvEC/PQ="

	if bitHash != reference {
		t.Error("Wrong DNS hash of 'bit.' calculated: ", bitHash, " should be ", reference)
	}
}

func TestSleeve256(t *testing.T) {
	sleeve, err := tlsrestrict_chromium.Sleeve256()
	if err != nil {
		t.Error(err)
	}

	reference := "UXzBtyciCpT+E6vo+ppu4G2xSsyeIcgg/yix1e9d4rA="

	if sleeve != reference {
		t.Error("Wrong sleeve256 calculated: ", sleeve, " should be ", reference)
	}
}
