package main

import "gopkg.in/hlandau/service.v2"
import "gopkg.in/hlandau/easyconfig.v1"
import "github.com/hlandau/ncdns/server"
import "github.com/hlandau/degoutils/xlogconfig"
import "path/filepath"

func main() {
	cfg := server.Config{}

	config := easyconfig.Configurator{
		ProgramName: "ncdns",
	}
	config.ParseFatal(&cfg)
	xlogconfig.Init()

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
