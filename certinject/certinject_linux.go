package certinject

var (
	nssExplain = "Synchronize TLS certs to an NSS sqlite3 trust store?  " +
		"This enables HTTPS to work with NSS web browsers such as " +
		"Chromium/Chrome.  Only use if you've set up NUMS HPKP in " +
		"Chromium/Chrome as per documentation.  If you haven't set " +
		"up NUMS HPKP, or if you access the configured NSS sqlite3 " +
		"trust store from browsers not based on Chromium, this is " +
		"unsafe and should not be used."
)
