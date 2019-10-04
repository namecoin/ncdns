// +build !no_namecoin_tls

package backend

import "github.com/namecoin/tlsrestrictnss/tlsrestrictnsssync"
import "fmt"

func lookupReadyError() error {
	if !tlsrestrictnsssync.IsReady() {
		return fmt.Errorf("tlsrestrictnss not ready")
	}

	return nil
}
