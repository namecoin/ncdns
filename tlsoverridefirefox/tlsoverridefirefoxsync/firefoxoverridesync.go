package tlsoverridefirefoxsync

import (
	"bytes"
	"fmt"
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

// This is true when an error occurred during sync.  Such an error could leave
// the cert_override.txt with positive overrides that have since been revoked
// by the blockchain, which would be a security issue if .bit resolving isn't
// stopped.
var syncFailure = true
var syncFailureMux sync.Mutex

func checkFlagsSane() error {
	if firefoxProfileDirFlag.Value() == "" {
		return fmt.Errorf("Missing required config option tlsoverridefirefox.profiledir")
	}

	return nil
}

func watchZone(conn namecoin.Conn) {
	for {
		var result bytes.Buffer

		err := ncdumpzone.Dump(conn, &result, "firefox-override")
		if err != nil {
			log.Errore(err, "Couldn't dump zone for Firefox override sync")

			syncFailureMux.Lock()
			syncFailure = true
			syncFailureMux.Unlock()

			time.Sleep(1 * time.Second)
			continue
		}

		zoneDataMux.Lock()
		zoneData = result.String()
		zoneDataReady = true
		zoneDataMux.Unlock()

		time.Sleep(10 * time.Minute)
	}
}

func watchProfile(suffix string) {
	for {
		inUse, err := profileInUse()
		if err != nil {
			log.Errore(err, "Couldn't check if Firefox is running for override sync")

			syncFailureMux.Lock()
			syncFailure = true
			syncFailureMux.Unlock()

			time.Sleep(1 * time.Second)
			continue
		}
		if inUse {
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
				log.Errore(err,
					"Couldn't read Firefox "+
						"cert_override.txt")

				syncFailureMux.Lock()
				syncFailure = true
				syncFailureMux.Unlock()

				time.Sleep(1 * time.Second)
				continue
			}
		}

		filteredPrevOverrides, err := tlsoverridefirefox.
			FilterOverrides(string(prevOverrides), suffix)
		if err != nil {
			log.Errore(err, "Couldn't filter Firefox overrides")

			syncFailureMux.Lock()
			syncFailure = true
			syncFailureMux.Unlock()

			time.Sleep(1 * time.Second)
			continue
		}

		newOverrides := filteredPrevOverrides + zoneDataLocal + "\n"

		// TODO: Does 0600 match the default behavior of Firefox?
		// TODO: maybe instead write to a temp file and then move the file into place?
		err = ioutil.WriteFile(firefoxProfileDirFlag.Value()+
			"/cert_override.txt", []byte(newOverrides), 0600)
		if err != nil {
			log.Errore(err, "Couldn't write Firefox cert_override.txt")

			syncFailureMux.Lock()
			syncFailure = true
			syncFailureMux.Unlock()

			time.Sleep(1 * time.Second)
			continue
		}

		syncFailureMux.Lock()
		syncFailure = false
		syncFailureMux.Unlock()
		log.Debug("Finished syncing zone to cert_override.txt")

		time.Sleep(10 * time.Minute)
	}
}

func profileInUse() (bool, error) {
	// This glob pattern matches the ".sqlite-wal" and ".sqlite-shm" files
	// that are only present when Firefox's databases are open.
	matches, err := filepath.Glob(firefoxProfileDirFlag.Value() + "/*.sqlite-*")
	if err != nil {
		return true, err
	}

	return matches != nil, nil
}

// IsReady returns true if the overrides are successfully synced.  If it
// returns false, it may be unsafe for TLS connections to rely on the synced
// overrides.
func IsReady() bool {
	syncFailureMux.Lock()
	result := !syncFailure
	syncFailureMux.Unlock()

	return result
}

// Start starts 2 background threads that synchronize the blockchain's TLSA
// records to a Firefox profile's cert_override.txt.  It accepts a connection
// to access Namecoin Core, as well as a host suffix (usually "bit").
func Start(conn namecoin.Conn, suffix string) error {
	if syncEnableFlag.Value() {
		err := checkFlagsSane()
		if err != nil {
			return err
		}

		go watchZone(conn)
		go watchProfile(suffix)
	} else {
		syncFailureMux.Lock()
		syncFailure = false
		syncFailureMux.Unlock()
	}
	return nil
}
