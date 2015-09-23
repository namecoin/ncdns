package main

import "gopkg.in/hlandau/service.v1"
import "gopkg.in/hlandau/easyconfig.v1"
import "github.com/hlandau/ncdns/server"
import "path/filepath"

func main() {
	cfg := server.ServerConfig{}

	config := easyconfig.Configurator{
		ProgramName: "ncdns",
	}
	config.ParseFatal(&cfg)

	// We use the configPath to resolve paths relative to the config file.
	cfg.ConfigDir = filepath.Dir(config.ConfigFilePath())

	service.Main(&service.Info{
		Name:          "ncdns",
		Description:   "Namecoin to DNS Daemon",
		DefaultChroot: service.EmptyChrootPath,
		RunFunc: func(smgr service.Manager) error {
			s, err := server.NewServer(&cfg)
			if err != nil {
				return err
			}

			err = s.Start()
			if err != nil {
				return err
			}

			err = smgr.DropPrivileges()
			if err != nil {
				return err
			}

			smgr.SetStarted()
			smgr.SetStatus("ncdns: running ok")

			<-smgr.StopChan()

			return nil
		},
	})
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
