//go:build no_namecoin_tls
// +build no_namecoin_tls

package server

import "github.com/namecoin/ncdns/config"

func RegisterBackgroundConfig(r *config.Loader) error {
	return nil
}

func (s *Server) StartBackgroundTasks() error {
	return nil
}
