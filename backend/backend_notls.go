//go:build no_namecoin_tls
// +build no_namecoin_tls

package backend

func lookupReadyError() error {
	return nil
}
