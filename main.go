package main

import (
	"path/filepath"

	"github.com/namecoin/ncdns/config"
	"github.com/namecoin/ncdns/logconfig"
	"github.com/namecoin/ncdns/server"
	"github.com/namecoin/ncdns/tlsoverridefirefox/tlsoverridefirefoxsync"
	"gopkg.in/hlandau/service.v2"
)

func main() {
	cfg := server.Config{}
	logCfg := logconfig.Config{}

	loader := config.New("ncdns")
	if err := loader.Register("ncdns", &cfg); err != nil {
		panic(err)
	}
	if err := loader.Register("xlog", &logCfg); err != nil {
		panic(err)
	}
	if err := tlsoverridefirefoxsync.RegisterConfig(loader); err != nil {
		panic(err)
	}
	loader.ParseFatal()
	logconfig.Init(&logCfg)

	// We use the configPath to resolve paths relative to the config file.
	cfg.ConfigDir = filepath.Dir(loader.ConfigFilePath())

	service.Main(&service.Info{
		Description:   "Namecoin to DNS Daemon",
		DefaultChroot: service.EmptyChrootPath,
		NewFunc: func() (service.Runnable, error) {
			return server.New(&cfg)
		},
	})
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
