// +build !linux

package certinject

var (
	nssExplain = "(Unsafe and experimental!)  Synchronize TLS certs to " +
		"an NSS sqlite3 trust store?  This enables HTTPS to work " +
		"with some NSS-based software.  This is currently unsafe " +
		"and should not be used."
)
