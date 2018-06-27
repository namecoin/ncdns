package main

import (
	"path/filepath"

	"github.com/hlandau/dexlogconfig"
	"github.com/namecoin/ncdns/server"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/service.v2"
)

func main() {
	cfg := server.Config{}

	config := easyconfig.Configurator{
		ProgramName: "ncdns",
	}
	config.ParseFatal(&cfg)
	dexlogconfig.Init()

	// We use the configPath to resolve paths relative to the config file.
	cfg.ConfigDir = filepath.Dir(config.ConfigFilePath())

	service.Main(&service.Info{
		Description:   "Namecoin to DNS Daemon",
		DefaultChroot: service.EmptyChrootPath,
		NewFunc: func() (service.Runnable, error) {
			return server.New(&cfg)
		},
	})
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
