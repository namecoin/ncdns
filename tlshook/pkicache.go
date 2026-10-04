//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package tlshook

import (
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/namecoin/ncdns/ncdomain"
	"github.com/namecoin/ncdns/util"
)

type cachedTrustInfo struct {
	expiration time.Time

	// Value for the eTLD+1 domain
	ncv *ncdomain.Value
}

var (
	pkiCache      map[string]cachedTrustInfo
	pkiCacheMutex sync.RWMutex
)

func init() {
	pkiCache = map[string]cachedTrustInfo{}
}

func getETLD1(qname string) string {
	_, basename, rootname, err := util.SplitDomainByFloatingAnchor(qname, "bit")
	if err != nil {
		// The only possible error is NotInZone, and that can't occur here.
		panic(err)
	}

	return basename + "." + rootname
}

func getCachedTrustInfo(qname string) *ncdomain.Value {
	key := getETLD1(qname)

	pkiCacheMutex.RLock()
	defer pkiCacheMutex.RUnlock()

	trustInfo, ok := pkiCache[key]
	if !ok {
		return nil
	}

	// TODO: remove expired entries.
	// In practice, this cache should be pretty small, so expiry doesn't matter much.

	return trustInfo.ncv
}

func cacheTrustInfo(qname string, ncv *ncdomain.Value) {
	key := getETLD1(qname)

	trustInfo := cachedTrustInfo{
		// TODO: An hour should be long enough for Unbound cache to expire, right?
		expiration: time.Now().Add(time.Hour),
		ncv    :    ncv,
	}

	pkiCacheMutex.Lock()
	defer pkiCacheMutex.Unlock()

	pkiCache[key] = trustInfo
}

// Returns all TLSA records that existed for the given qname at the time of the
// most recent DNS query for that qname. No refreshing is done; no network
// traffic is generated. Resistant to FPI leaks.
func GetTLSARecords(qname string) ([]*dns.TLSA, error) {
	trustInfo := getCachedTrustInfo(qname)

	subname, _, _, err := util.SplitDomainByFloatingAnchor(qname, "bit")
	if err != nil {
		return nil, err
	}

	wildcardSubname := "*." + subname

	subTrustInfo, err := trustInfo.FindSubdomainByName(wildcardSubname)
	if err != nil {
		return nil, err
	}

	return subTrustInfo.TLSA, nil
}
