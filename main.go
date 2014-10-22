package main
import "github.com/hlandau/degoutils/config"
import "github.com/hlandau/degoutils/log"
import "github.com/hlandau/ncdns/server"

func main() {
  cfg := server.ServerConfig{}
  config := config.Configurator{
    ProgramName: "ncdns",
    ConfigFilePaths: []string { "etc/ncdns.conf", "/etc/ncdns/ncdns.conf", },
  }
  config.ParseFatal(&cfg)
  s, err := server.NewServer(&cfg)
  log.Fatale(err)

  s.Run()
}
