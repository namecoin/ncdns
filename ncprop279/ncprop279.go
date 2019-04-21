package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/hlandau/buildinfo"
	"github.com/miekg/dns"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/madns.v1"

	"github.com/namecoin/ncdns/backend"
	"github.com/namecoin/ncdns/namecoin"
)

var prop279Reader *bufio.Reader

type Server struct {
	cfg Config

	engine       madns.Engine
	namecoinConn namecoin.Conn
}

type Config struct {
	NamecoinRPCUsername   string `default:"" usage:"Namecoin RPC username"`
	NamecoinRPCPassword   string `default:"" usage:"Namecoin RPC password"`
	NamecoinRPCAddress    string `default:"127.0.0.1:8336" usage:"Namecoin RPC server address"`
	NamecoinRPCCookiePath string `default:"" usage:"Namecoin RPC cookie path (if set, used instead of password)"`
	NamecoinRPCTimeout    int    `default:"1500" usage:"Timeout (in milliseconds) for Namecoin RPC requests"`
	CacheMaxEntries       int    `default:"100" usage:"Maximum name cache entries"`
}

var ncdnsVersion string

func New(cfg *Config) (s *Server, err error) {
	ncdnsVersion = buildinfo.VersionSummary("github.com/namecoin/ncdns", "ncdns")

	s = &Server{
		cfg: *cfg,
		namecoinConn: namecoin.Conn{
			Username: cfg.NamecoinRPCUsername,
			Password: cfg.NamecoinRPCPassword,
			Server:   cfg.NamecoinRPCAddress,
		},
	}

	if s.cfg.NamecoinRPCCookiePath != "" {
		s.namecoinConn.GetAuth = cookieRetriever(s.cfg.NamecoinRPCCookiePath)
	}

	b, err := backend.New(&backend.Config{
		NamecoinConn:         s.namecoinConn,
		NamecoinTimeout:      cfg.NamecoinRPCTimeout,
		CacheMaxEntries:      cfg.CacheMaxEntries,
		SelfIP:               "127.127.127.127",
		Hostmaster:           "",
		CanonicalNameservers: []string{},
		VanityIPs:            []net.IP{},
	})
	if err != nil {
		return
	}

	ecfg := &madns.EngineConfig{
		Backend:       b,
		VersionString: ncdnsVersion,
	}

	s.engine, err = madns.NewEngine(ecfg)
	if err != nil {
		return
	}

	return
}

func createReqMsg(qname string, qtype uint16) *dns.Msg {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     true,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	m.Question[0] = dns.Question{Name: dns.Fqdn(qname), Qtype: qtype, Qclass: dns.ClassINET}
	m.Id = dns.Id()

	return m
}

type prop279Status int
const StatusSuccess prop279Status = 0
const StatusGenericFail prop279Status = 1
const StatusNotInZone prop279Status = 2
const StatusNxDomain prop279Status = 3
const StatusTimeout prop279Status = 4

type prop279ResponseWriter struct {
	queryID int
	parseOnion bool
	result *prop279Status
}

func (rw *prop279ResponseWriter) LocalAddr() net.Addr {
	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")
	return addr
}

func (rw *prop279ResponseWriter) RemoteAddr() net.Addr {
	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")
	return addr
}

func (rw *prop279ResponseWriter) WriteMsg(res *dns.Msg) error {
	switch res.MsgHdr.Rcode {
	case dns.RcodeNameError:
		*rw.result = StatusNxDomain
	case dns.RcodeRefused:
		*rw.result = StatusNotInZone
		fmt.Printf("RESOLVED %d %d %s\n", rw.queryID, *rw.result, "\"Not in Namecoin zone\"")
	case dns.RcodeSuccess:
		if rw.parseOnion {
			for _, answer := range res.Answer {
				answerTXT, ok := answer.(*dns.TXT)
				if ok {
					onion := answerTXT.Txt[0]

					_, isDomainName := dns.IsDomainName(onion)
					if ! isDomainName {
						continue
					}

					if ! strings.HasSuffix(onion, ".onion") {
						continue
					}

					*rw.result = StatusSuccess
					fmt.Printf("RESOLVED %d %d %s\n", rw.queryID, *rw.result, onion)
					return nil
				}
			}
		} else {
			for _, answer := range res.Answer {
				answerA, ok := answer.(*dns.A)
				if ok {
					*rw.result = StatusSuccess
					fmt.Printf("RESOLVED %d %d %s\n", rw.queryID, *rw.result, answerA.A.String())
					return nil
				}
			}

			for _, answer := range res.Answer {
				answerAAAA, ok := answer.(*dns.AAAA)
				if ok {
					*rw.result = StatusSuccess
					fmt.Printf("RESOLVED %d %d %s\n", rw.queryID, *rw.result, answerAAAA.AAAA.String())
					return nil
				}
			}

			for _, answer := range res.Answer {
				answerCNAME, ok := answer.(*dns.CNAME)
				if !ok {
					continue
				}

				target := answerCNAME.Target

				if ! dns.IsFqdn(target) {
					continue
				}
				target = strings.TrimSuffix(target, ".")

				*rw.result = StatusSuccess
				fmt.Printf("RESOLVED %d %d %s\n", rw.queryID, *rw.result, target)
				return nil
			}
		}

		*rw.result = StatusNxDomain
	default:
		*rw.result = StatusGenericFail
		fmt.Printf("RESOLVED %d %d %s\n", rw.queryID, *rw.result, "\"Server failure\"")
	}

	return nil
}

func (rw *prop279ResponseWriter) Write(rawMsg []byte) (int, error) {
	return 0, fmt.Errorf("Unimplemented")
}

func (rw *prop279ResponseWriter) Close() error {
	return nil
}

func (rw *prop279ResponseWriter) TsigStatus() error {
	return nil
}

func (rw *prop279ResponseWriter) TsigTimersOnly(t bool) {
}

func (rw *prop279ResponseWriter) Hijack() {
}

func (s *Server) doResolve(queryID int, qname string, qtype uint16, parseOnion bool) prop279Status {
	var result prop279Status

	reqMsg := createReqMsg(qname, qtype)
	responseWriter := &prop279ResponseWriter{queryID: queryID, parseOnion: parseOnion, result: &result}
	s.engine.ServeDNS(responseWriter, reqMsg)

	return result
}

func main() {
	cfg := Config{}

	config := easyconfig.Configurator{
		ProgramName: "ncprop279",
	}
	config.ParseFatal(&cfg)

	s, err := New(&cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't create server: %s\n", err)
		os.Exit(3)
	}

	prop279Reader = bufio.NewReader(os.Stdin)
	fmt.Println("INIT 1 0")

	for {
		line, err := prop279Reader.ReadString('\n')

		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't read stdin: %s\n", err)
			os.Exit(3)
		}

		words := strings.Fields(line)

		if len(words) < 1 {
			continue
		}

		if words[0] == "RESOLVE" {
			if len(words) < 3 {
				continue
			}

			queryIDStr := words[1]
			queryID, err := strconv.Atoi(queryIDStr)
			if err != nil {
				continue
			}

			name := words[2]
			originalName := name
			onlyOnion := false

			if strings.HasSuffix(name, ".onion") {
				name = strings.TrimSuffix(name, ".onion")
				onlyOnion = true
			}

			result := StatusNxDomain

			if result == StatusNxDomain {
				result = s.doResolve(queryID, "_tor." + name, dns.TypeTXT, true)
			}

			if !onlyOnion {
				if result == StatusNxDomain {
					result = s.doResolve(queryID, name, dns.TypeA, false)
				}
				if result == StatusNxDomain {
					result = s.doResolve(queryID, name, dns.TypeAAAA, false)
				}
				if result == StatusNxDomain {
					result = s.doResolve(queryID, name, dns.TypeCNAME, false)
				}
			}
			if result == StatusNxDomain {
				fmt.Printf("RESOLVED %d %d \"%s is not registered\"\n", queryID, result, originalName)
			}
		} else if words[0] == "CANCEL" {
			if len(words) < 2 {
				continue
			}

			queryIDStr := words[1]
			queryID, err := strconv.Atoi(queryIDStr)
			if err != nil {
				continue
			}

			fmt.Printf("CANCELED %d\n", queryID)
		}
	}
}
