//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package server

import encaya "github.com/namecoin/encaya/server"

func (s *Server) StartBackgroundTasks() error {
	if s.cfg.ListenAIA {
		cfg := &encaya.Config {
			DNSAddress: "127.0.0.1",
			DNSPort:    5391,
			ListenIP:   s.cfg.SelfIP,

			RootCert:    s.cfg.RootCert,
			RootKey:     s.cfg.RootKey,
			ListenChain: s.cfg.ListenChain,
			ListenKey:   s.cfg.ListenKey,

			NamecoinRPCUsername:   s.cfg.NamecoinRPCUsername,
			NamecoinRPCPassword:   s.cfg.NamecoinRPCPassword,
			NamecoinRPCAddress:    s.cfg.NamecoinRPCAddress,
			NamecoinRPCCookiePath: s.cfg.NamecoinRPCCookiePath,
			NamecoinRPCTimeout:    s.cfg.NamecoinRPCTimeout,

			ConfigDir:    s.cfg.ConfigDir,
		}

		encayaServer, err := encaya.New(cfg)
		if err != nil {
			return err
		}

		err = encayaServer.Start()
		if err != nil {
			return err
		}
	}

	return nil
}
