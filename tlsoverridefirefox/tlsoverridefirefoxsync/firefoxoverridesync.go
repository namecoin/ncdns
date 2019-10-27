package tlsoverridefirefoxsync

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hlandau/xlog"
	"gopkg.in/hlandau/easyconfig.v1/cflag"

	"github.com/namecoin/ncdns/namecoin"
	"github.com/namecoin/ncdns/ncdumpzone"
	"github.com/namecoin/ncdns/tlsoverridefirefox"
)

var (
	flagGroup      = cflag.NewGroup(nil, "tlsoverridefirefox")
	syncEnableFlag = cflag.Bool(flagGroup, "sync", false,
		"Synchronize TLSA records from the Namecoin zone to Firefox's "+
			"cert_override.txt")
	firefoxProfileDirFlag = cflag.String(flagGroup, "profiledir", "",
		"Firefox profile directory")
)

var log, Log = xlog.New("ncdns.tlsoverridefirefoxsync")

var zoneData string
var zoneDataReady = false
var zoneDataMux sync.Mutex

// Note: the reason for the Fatal reaction to errors is that, if we stop
// syncing the override list, Firefox will continue trusting .bit certs that
// might be revoked in Namecoin.  Therefore, it is important that, in such a
// situation, .bit domains must stop resolving until the issue is corrected.
// Forcing ncdns to exit is the least complex way to achieve this.

func watchZone(conn *namecoin.Client) {
	for {
		var result bytes.Buffer

		err := ncdumpzone.Dump(conn, &result, "firefox-override")
		log.Fatale(err, "Couldn't dump zone for Firefox override sync")

		zoneDataMux.Lock()
		zoneData = result.String()
		zoneDataReady = true
		zoneDataMux.Unlock()

		time.Sleep(10 * time.Minute)
	}
}

func watchProfile(suffix string) {
	if firefoxProfileDirFlag.Value() == "" {
		log.Fatal("Missing required config option tlsoverridefirefox.profiledir")
	}

	for {
		if profileInUse() {
			time.Sleep(1 * time.Second)
			continue
		}

		// At this point we know that Firefox is not running.

		zoneDataMux.Lock()
		zoneDataReadyLocal := zoneDataReady
		zoneDataLocal := zoneData
		zoneDataMux.Unlock()

		if !zoneDataReadyLocal {
			time.Sleep(1 * time.Second)
			continue
		}

		log.Debug("Syncing zone to cert_override.txt...")

		prevOverrides, err := ioutil.ReadFile(
			firefoxProfileDirFlag.Value() + "/cert_override.txt")
		if err != nil {
			if os.IsNotExist(err) {
				// cert_override.txt doesn't exist in a default
				// Firefox install; it's only created once the
				// first override is configured in the Firefox
				// GUI.  If it's not there, we can pretend we
				// read an empty file.
				prevOverrides = []byte(``)
			} else {
				log.Fatale(err,
					"Couldn't read Firefox "+
						"cert_override.txt")
			}
		}

		filteredPrevOverrides, err := tlsoverridefirefox.
			FilterOverrides(string(prevOverrides), suffix)
		log.Fatale(err, "Couldn't filter Firefox overrides")

		newOverrides := filteredPrevOverrides + zoneDataLocal + "\n"

		// TODO: Does 0600 match the default behavior of Firefox?
		// TODO: maybe instead write to a temp file and then move the file into place?
		err = ioutil.WriteFile(firefoxProfileDirFlag.Value()+
			"/cert_override.txt", []byte(newOverrides), 0600)
		log.Fatale(err, "Couldn't write Firefox cert_override.txt")

		log.Debug("Finished syncing zone to cert_override.txt")

		time.Sleep(10 * time.Minute)
	}
}

func profileInUse() bool {
	// This glob pattern matches the ".sqlite-wal" and ".sqlite-shm" files
	// that are only present when Firefox's databases are open.
	matches, err := filepath.Glob(firefoxProfileDirFlag.Value() + "/*.sqlite-*")
	log.Fatale(err, "Couldn't check if Firefox is running for override sync")

	return matches != nil
}

// Start starts 2 background threads that synchronize the blockchain's TLSA
// records to a Firefox profile's cert_override.txt.  It accepts a connection
// to access Namecoin Core, as well as a host suffix (usually "bit").
func Start(conn *namecoin.Client, suffix string) error {
	if syncEnableFlag.Value() {
		go watchZone(conn)
		go watchProfile(suffix)
	}
	return nil
}
