//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package tlshook

import (
	"github.com/hlandau/xlog"
	"github.com/namecoin/ncdns/ncdomain"
)

var log, Log = xlog.New("ncdns.tlshook")

func DomainBaseValueHook(qname string, ncv *ncdomain.Value) (err error) {

	log.Debug("Intercepted a Value for ", qname)

	// PKI cache
	cacheTrustInfo(qname, ncv)

	err = nil

	return

}
