package main

import (
	"encoding/json"
	"io/ioutil"
	"log"

	"github.com/namecoin/ncdns/tlsrestrictchromium"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/easyconfig.v1/cflag"
)

var (
	flagGroup                 = cflag.NewGroup(nil, "tlsrestrict")
	transportSecurityPathFlag = cflag.String(flagGroup, "chromium-ts-path", "", "Path to the TransportSecurity file in Chromium's profile folder.  Make sure that no running instance of Chromium is using this profile folder; profile corruption could result otherwise.")
	domainFlag                = cflag.String(flagGroup, "domain", "bit.", "Block built-in CA's from signing for any subdomains of this fully-qualified domain name.")
)

func main() {
	config := easyconfig.Configurator{
		ProgramName: "tlsrestrict_chromium",
	}
	err := config.Parse(nil)
	if err != nil {
		log.Fatalf("Couldn't parse configuration: %s", err)
	}

	transportSecurityPath := transportSecurityPathFlag.Value()
	domain := domainFlag.Value()

	if transportSecurityPath == "" {
		log.Fatalf("Missing required --tlsrestrict.chromium-ts-path parameter")
	}

	rawIn, err := ioutil.ReadFile(transportSecurityPath)
	if err != nil {
		log.Fatalf("Couldn't read file %s: %s", transportSecurityPath, err)
	}

	var data map[string]interface{}

	err = json.Unmarshal(rawIn, &data)
	if err != nil {
		log.Fatalf("Couldn't parse file %s: %s", transportSecurityPath, err)
	}

	// Chromium's TransportSecurity database uses keys of the form base64(sha256(dnsPack(fqdn)))
	domainDNSHashB64String, err := tlsrestrictchromium.DNSHash(domain)
	if err != nil {
		log.Fatalf("Couldn't hash domain name %s: %s", domain, err)
	}

	data[domainDNSHashB64String], err = tlsrestrictchromium.BlockAllCAs()
	if err != nil {
		log.Fatalf("Couldn't assign BlockAllCAs: %s", err)
	}

	rawOut, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Couldn't marshal data: %s", err)
	}

	// 0600 seems to be the default mode in Chromium on Fedora
	err = ioutil.WriteFile(transportSecurityPath, rawOut, 0600)
	if err != nil {
		log.Fatalf("Couldn't write file %s: %s", transportSecurityPath, err)
	}
}
