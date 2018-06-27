package tlsrestrictchromium_test

import (
	"testing"

	"github.com/namecoin/ncdns/tlsrestrictchromium"
)

func TestDnsHash(t *testing.T) {
	bitHash, err := tlsrestrictchromium.DNSHash("bit.")
	if err != nil {
		t.Error(err)
	}

	reference := "nprXwzm7mHINFnNah1Seo5SG0Pz9vW6dTXsYyvEC/PQ="

	if bitHash != reference {
		t.Error("Wrong DNS hash of 'bit.' calculated: ", bitHash, " should be ", reference)
	}
}

func TestSleeve256(t *testing.T) {
	sleeve, err := tlsrestrictchromium.Sleeve256()
	if err != nil {
		t.Error(err)
	}

	// To reproduce this with web-based tools, use https://www.wolframalpha.com/input/?i=hex%28floor%282^256%2Fpi%29%29
	// and then convert from hex to base64 via https://holtstrom.com/michael/tools/hextopem.php
	reference := "UXzBtyciCpT+E6vo+ppu4G2xSsyeIcgg/yix1e9d4rA="

	if sleeve != reference {
		t.Error("Wrong sleeve256 calculated: ", sleeve, " should be ", reference)
	}
}
