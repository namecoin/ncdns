// +build !windows,!linux

package certinject

import "github.com/hlandau/xlog"

var log, Log = xlog.New("ncdns.certinject")

func InjectCert(derBytes []byte) {

}

func CleanCerts() {

}
