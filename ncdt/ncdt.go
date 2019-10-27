package main

import "github.com/namecoin/ncdns/ncdomain"
import "github.com/namecoin/ncdns/namecoin"
import "flag"
import "fmt"
import "os"
import "strconv"
import "io/ioutil"
import "github.com/namecoin/btcd/rpcclient"
import "github.com/namecoin/ncdns/util"

var rpchost = flag.String("rpchost", "", "Namecoin RPC host:port")
var rpcuser = flag.String("rpcuser", "", "Namecoin RPC username")
var rpcpass = flag.String("rpcpass", "", "Namecoin RPC password")
var rpccookiepath = flag.String("rpccookiepath", "", "Namecoin RPC cookie path (used if password is unspecified)")
var conn *namecoin.Client

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: ncdt [options] <d/example> <JSON value> [<d/imported-example> <JSON value> ...]\n")
	fmt.Fprintf(os.Stderr, "Specify @filename for JSON value to read file, @N to read fd N (@0: stdin), @ to get via RPC\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  -rpchost=host:port     Namecoin RPC server address  } only required for RPC retrieval\n")
	fmt.Fprintf(os.Stderr, "  -rpcuser=username      Namecoin RPC username        }\n")
	fmt.Fprintf(os.Stderr, "  -rpcpass=password      Namecoin RPC password        }\n")
	fmt.Fprintf(os.Stderr, "  -rpccookiepath=path    Namecoin RPC cookie path     }\n")
	os.Exit(2)
}

func translateValue(k, v string) (string, error) {
	if len(v) == 0 || v[0] != '@' {
		return v, nil
	}

	v = v[1:]
	var f *os.File
	var err error
	if v[0] >= '0' && v[0] < '9' {
		var n uint64
		n, err = strconv.ParseUint(v, 10, 31)
		if err != nil {
			return "", err
		}

		f = os.NewFile(uintptr(n), "-")
	} else if len(v) == 1 {
		return conn.NameQuery(k, "")
	} else {
		f, err = os.Open(v)
	}

	if err != nil {
		return "", err
	}

	defer f.Close()

	contents, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}

	return string(contents), nil
}

func main() {
	flag.CommandLine.Usage = usage
	flag.Parse()
	args := flag.Args()
	names := map[string]string{}
	var primaryK, primaryV string

	if len(args)%2 != 0 || len(args) < 2 {
		usage()
	}

	// Connect to local namecoin core RPC server using HTTP POST mode.
	connCfg := &rpcclient.ConnConfig{
		Host:         *rpchost,
		User:         *rpcuser,
		Pass:         *rpcpass,
		CookiePath:   *rpccookiepath,
		HTTPPostMode: true, // Namecoin core only supports HTTP POST mode
		DisableTLS:   true, // Namecoin core does not provide TLS by default
	}

	var err error

	// Notice the notification parameter is nil since notifications are
	// not supported in HTTP POST mode.
	conn, err = namecoin.New(connCfg, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating RPC client: %v\n", err)
		os.Exit(1)
	}
	defer conn.Shutdown()

	for i := 0; i+1 < len(args); i += 2 {
		k := args[i]
		v := args[i+1]
		if _, ok := names[k]; ok {
			fmt.Fprintf(os.Stderr, "duplicate name specified: %s\n", k)
			os.Exit(1)
		}

		v, err = translateValue(k, v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to translate value: %v\n", err)
			os.Exit(1)
		}

		if i == 0 {
			primaryK, primaryV = k, v
		}

		names[k] = v
	}

	value := ncdomain.ParseValue(primaryK, primaryV, func(k string) (string, error) {
		v, ok := names[k]
		if !ok {
			return "", fmt.Errorf("reference to unknown name")
		}

		return v, nil
	}, func(err error, isWarning bool) {
		if isWarning {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
	})

	suffix, err := util.NamecoinKeyToBasename(primaryK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid key: %s\n", primaryK)
		os.Exit(1)
	}

	suffix += ".bit."

	rrs, err := value.RRsRecursive(nil, suffix, suffix)
	if err != nil {
		fmt.Printf("Error generating RRs: %v\n", err)
		os.Exit(1)
	}

	for _, rr := range rrs {
		fmt.Println(rr.String())
	}
}
