package server

import "os"
import "net"

var hostname string

func init() {
	names, err := net.LookupAddr("127.0.0.1")
	if err != nil || len(names) == 0 {
		hn, err := os.Hostname()
		if err != nil {
			panic(err)
		}
		hostname = hn
		return
	}

	hostname = names[0]
}

func (s *Server) ServerName() string {
	n := s.cfg.SelfName
	if n == "" {
		n = hostname
	}
	return n
}
