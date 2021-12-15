//go:build no_namecoin_tls
// +build no_namecoin_tls

package server

func (s *Server) StartBackgroundTasks() error {
	return nil
}
