//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package server

import (
	"fmt"

	"github.com/namecoin/ncdns/tlsoverridefirefox/tlsoverridefirefoxsync"
)

func (s *Server) StartBackgroundTasks() error {
	err := tlsoverridefirefoxsync.Start(s.namecoinConn, s.cfg.CanonicalSuffix)
	if err != nil {
		return fmt.Errorf("Couldn't start Firefox override sync: %s", err)
	}

	return nil
}
