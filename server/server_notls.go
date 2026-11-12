//go:build no_namecoin_tls
// +build no_namecoin_tls

package server

func (s *Server) StartBackgroundTasks() error {
	if s.cfg.ListenAIA {
		log.Fatal("AIA requested but not built")
	}

	return nil
}
