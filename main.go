package main
import "github.com/hlandau/degoutils/config"
import "github.com/hlandau/degoutils/log"
import "github.com/hlandau/degoutils/daemon"
import "github.com/hlandau/ncdns/server"

func main() {
  cfg := server.ServerConfig{}
  config := config.Configurator{
    ProgramName: "ncdns",
    ConfigFilePaths: []string { "etc/ncdns.conf", "/etc/ncdns/ncdns.conf", },
  }
  config.ParseFatal(&cfg)

  err := daemon.Init()
  log.Fatale(err)

  if cfg.Daemonize {
    err := daemon.Daemonize()
    log.Fatale(err)
  }

  err = daemon.DropPrivileges(cfg.UID, cfg.GID)
  log.Fatale(err, "can't drop privileges")

  s, err := server.NewServer(&cfg)
  log.Fatale(err)

  s.Run()
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
