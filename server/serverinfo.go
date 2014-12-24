package server

import denet "github.com/hlandau/degoutils/net"

func (s *Server) ServerName() string {
	n := s.cfg.SelfName
	if n == "" {
		n = denet.Hostname()
	}
	return n
}
