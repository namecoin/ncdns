package main

import (
	"os"

	"github.com/btcsuite/btcd/rpcclient"

	"github.com/namecoin/ncdns/config"
	"github.com/namecoin/ncdns/logconfig"
	"github.com/namecoin/ncdns/namecoin"
	"github.com/namecoin/ncdns/ncdumpzone"
)

var log = logconfig.New("ncdumpzone-main")

type Config struct {
	NamecoinRPCAddress  string `default:"127.0.0.1:8336" usage:"Namecoin RPC host:port"`
	NamecoinRPCUsername string `default:"" usage:"Namecoin RPC username"`
	NamecoinRPCPassword string `default:"" usage:"Namecoin RPC password"`

	NamecoinRPCCookiePath string `default:"" usage:"Namecoin RPC cookie path (used if password is unspecified)"`
	Format                string `default:"zonefile" usage:"Output format.  \"zonefile\" = DNS zone file.  \"firefox-override\" = Firefox cert_override.txt format.  \"url-list\" = URL list."`
}

var conn *namecoin.Client

func main() {
	cfg := Config{}
	logCfg := logconfig.Config{}

	loader := config.New("ncdumpzone")
	if err := loader.Register("ncdumpzone", &cfg); err != nil {
		panic(err)
	}
	if err := loader.Register("xlog", &logCfg); err != nil {
		panic(err)
	}

	err := loader.Parse()
	if err != nil {
		logconfig.Init(&logCfg)
		log.Fatal().Err(err).Msg("Couldn't parse configuration")
	}

	logconfig.Init(&logCfg)

	// Connect to local namecoin core RPC server using HTTP POST mode.
	connCfg := &rpcclient.ConnConfig{
		Host:         cfg.NamecoinRPCAddress,
		User:         cfg.NamecoinRPCUsername,
		Pass:         cfg.NamecoinRPCPassword,
		CookiePath:   cfg.NamecoinRPCCookiePath,
		HTTPPostMode: true, // Namecoin core only supports HTTP POST mode
		DisableTLS:   true, // Namecoin core does not provide TLS by default
	}

	// Notice the notification parameter is nil since notifications are
	// not supported in HTTP POST mode.
	conn, err = namecoin.New(connCfg, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create RPC client")
	}
	defer conn.Shutdown()

	err = ncdumpzone.Dump(conn, os.Stdout, cfg.Format)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't dump zone")
	}
}
