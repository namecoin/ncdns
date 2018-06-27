package certinject

import (
	"github.com/hlandau/xlog"
	"gopkg.in/hlandau/easyconfig.v1/cflag"
)

var log, Log = xlog.New("ncdns.certinject")

var (
	flagGroup        = cflag.NewGroup(nil, "certstore")
	nssFlag          = cflag.Bool(flagGroup, "nss", false, nssExplain)
	certExpirePeriod = cflag.Int(flagGroup, "expire", 60*30, "Duration "+
		"(in seconds) after which TLS certs will be removed from the "+
		"trust store.  Making this smaller than the DNS TTL (default "+
		"600) may cause TLS errors.")
)
