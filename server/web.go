package server

import "net/http"
import "html/template"
import "github.com/namecoin/ncdns/util"
import "github.com/namecoin/ncdns/ncdomain"
import "github.com/miekg/dns"
import "github.com/kr/pretty"
import "path/filepath"
import "time"
import "strings"
import "fmt"

var layoutTpl *template.Template
var mainPageTpl *template.Template
var lookupPageTpl *template.Template

func (s *Server) initTemplates() error {
	if lookupPageTpl != nil {
		return nil
	}

	var err error
	layoutTpl, err = template.ParseFiles(s.tplFilename("layout"))
	if err != nil {
		return err
	}

	mainPageTpl, err = deriveTemplate(s.tplFilename("main"))
	if err != nil {
		return err
	}

	lookupPageTpl, err = deriveTemplate(s.tplFilename("lookup"))
	return err
}

func deriveTemplate(filename string) (*template.Template, error) {
	cl, err := layoutTpl.Clone()
	if err != nil {
		return nil, err
	}
	return cl.ParseFiles(filename)
}

func (s *Server) tplFilename(filename string) string {
	td := filepath.Join(s.cfg.ConfigDir, "..", "tpl")
	if s.cfg.TplPath != "" {
		td = s.cfg.TplPath
	}

	return filepath.Join(td, s.cfg.TplSet, filename+".tpl")
}

type webServer struct {
	s  *Server
	sm *http.ServeMux
}

type layoutInfo struct {
	SelfName             string
	Time                 string
	CanonicalSuffix      string
	CanonicalNameservers []string
	Hostmaster           string
	CanonicalSuffixHTML  template.HTML
	TLD                  string
	HasDNSSEC            bool
}

func (ws *webServer) layoutInfo() *layoutInfo {
	csparts := strings.SplitN(ws.s.cfg.CanonicalSuffix, ".", 2)
	cshtml := `<span id="logo1">` + csparts[0] + `</span>`
	if len(csparts) > 1 {
		cshtml = `<span id="logo1">` + csparts[0] + `</span><span id="logo2">.</span><span id="logo3">` + csparts[1] + `</span>`
	}

	var tld string
	if len(csparts) > 1 {
		tld = "." + csparts[1]
	}

	li := &layoutInfo{
		SelfName:             ws.s.ServerName(),
		Time:                 time.Now().Format("2006-01-02 15:04:05"),
		CanonicalSuffix:      ws.s.cfg.CanonicalSuffix,
		CanonicalNameservers: ws.s.cfg.canonicalNameservers,
		Hostmaster:           ws.s.cfg.Hostmaster,
		CanonicalSuffixHTML:  template.HTML(cshtml),
		TLD:                  tld,
		HasDNSSEC:            ws.s.cfg.ZonePublicKey != "",
	}

	return li
}

func (ws *webServer) handleRoot(rw http.ResponseWriter, req *http.Request) {
	err := mainPageTpl.Execute(rw, ws.layoutInfo())
	log.Infoe(err, "tpl")
}

func (ws *webServer) handleLookup(rw http.ResponseWriter, req *http.Request) {
	info := struct {
		layoutInfo
		JSONMode       bool
		JSONValue      string
		Query          string
		Advanced       bool
		NamecoinName   string
		DomainName     string
		BareName       string
		NameParseError error
		ExistenceError error
		Expired        bool
		Value          string
		NCValue        *ncdomain.Value
		NCValueFmt     fmt.Formatter
		ParseErrors    []error
		ParseWarnings  []error
		RRs            []dns.RR
		RRError        error
		Valid          bool
	}{layoutInfo: *ws.layoutInfo()}

	defer func() {
		err := lookupPageTpl.Execute(rw, &info)
		log.Infoe(err, "lookup page tpl")
	}()

	q := req.FormValue("q")
	info.Query = q
	info.BareName, info.NamecoinName, info.NameParseError = util.ParseFuzzyDomainNameNC(q)
	if info.NameParseError != nil {
		return
	}

	info.Advanced = (req.FormValue("adv") != "")
	info.DomainName = info.BareName + ".bit."

	info.JSONValue = req.FormValue("value")
	info.Value = strings.Trim(info.JSONValue, " \t\r\n")
	if info.Value == "" {
		info.Value, info.ExistenceError = ws.s.namecoinConn.Query(info.NamecoinName)
		if info.ExistenceError != nil {
			return
		}
	} else {
		info.JSONMode = true
	}

	errorFunc := func(e error, isWarning bool) {
		if isWarning {
			info.ParseWarnings = append(info.ParseWarnings, e)
		} else {
			info.ParseErrors = append(info.ParseErrors, e)
		}
	}

	info.NCValue = ncdomain.ParseValue(info.NamecoinName, info.Value, ws.resolveFunc, errorFunc)
	if info.NCValue == nil {
		return
	}

	info.NCValueFmt = pretty.Formatter(info.NCValue)

	info.RRs, info.RRError = info.NCValue.RRsRecursive(nil, info.DomainName, "bit.")
	if len(info.ParseErrors) == 0 && info.RRError == nil {
		info.Valid = true
	}
}

func (ws *webServer) resolveFunc(name string) (string, error) {
	return ws.s.namecoinConn.Query(name)
}

func (ws *webServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline';")
	rw.Header().Set("X-Frame-Options", "DENY")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("Server", "ncdns")
	//req.Header.Set("Strict-Transport-Security", "max-age=259200")
	//req.Header.Set("X-Download-Options", "noopen")
	//req.Header.Set("X-XSS-Protection", "0")
	//req.Header.Set("X-Permitted-Cross-Domain-Policies", "none")
	clearAllCookies(rw, req)
	ws.sm.ServeHTTP(rw, req)
}

func clearAllCookies(rw http.ResponseWriter, req *http.Request) {
	for _, ck := range req.Cookies() {
		ck2 := http.Cookie{
			Name:   ck.Name,
			MaxAge: -1,
		}
		rw.Header().Add("Set-Cookie", ck2.String())
	}
}

func webStart(listenAddr string, server *Server) error {
	err := server.initTemplates()
	if err != nil {
		return err
	}

	ws := &webServer{
		s:  server,
		sm: http.NewServeMux(),
	}

	ws.sm.HandleFunc("/", ws.handleRoot)
	ws.sm.HandleFunc("/lookup", ws.handleLookup)

	s := http.Server{
		Addr:    listenAddr,
		Handler: ws,
	}

	go s.ListenAndServe()
	// TODO: error handling
	return nil
}
