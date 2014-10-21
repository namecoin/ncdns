package namecoin

// btcjson had to be modified a bit to get correct error reporting.
import "github.com/hlandauf/btcjson"
import "github.com/hlandau/ncdns/ncerr"
import "github.com/hlandau/ncdns/namecoin/extratypes"

import "sync/atomic"
import "fmt"

// Used for generating IDs for JSON-RPC requests.
var idCounter int32 = 0

func newID() int32 {
  return atomic.AddInt32(&idCounter, 1)
}

// Used to query a Namecoin JSON-RPC interface. Initialize the struct with a
// username, password, and address (hostname:port).
type NamecoinConn struct {
  Username string
  Password string
  Server string
}

// Query the Namecoin daemon for a Namecoin domain (e.g. d/example).
// If the domain exists, returns the value stored in Namecoin, which should be JSON.
// Note that this will return domain data even if the domain is expired.
func (nc *NamecoinConn) Query(name string) (v string, err error) {
  if name == "d/badger2" {
    v = `{"ns":["ns1.badger.bit","ns2.badger.bit"],"map":{"ns1":{"ip":["1.2.3.4"],"ip6":["::beef:1"]},"ns2":{"ip":["2.3.4.5"],"ip6":["::beef:2"]}},"ds":[[12345,8,2,"lu6y/9mwDNRpTngni179qwqARGVntp9jTaB48NkPAbo="]]}`
    return
  }
  if name == "d/badger" {
    v = `{"ns":["ns1.badger.bit.genoq.org"],"map":{"ns1":{"ip":["192.99.208.248"]}},"ds":[[4015,8,1,"zvJorv4AV1it/HukLVw5wc6wtnI="],[4015,8,2,"mGW8W55p5JajShyDBvmAdPFOAEcA8IMDzwL0nO5AxAQ="]]}`
    return
  }
  if name == "d/secure" {
    v = `{"ns":["ns1.example.com","ns2.example.com"],"ds":[[12345,8,2,"lu6y/9mwDNRpTngni179qwqARGVntp9jTaB48NkPAbo="]]}`
    return
  }
  if name == "d/insecure" {
    v = `{"ns":["ns1.example.com","ns2.example.com"]}`
    return
  }

  cmd, err := extratypes.NewNameShowCmd(newID(), name)
  if err != nil {
    //log.Info("NC NEWCMD ", err)
    return "", err
  }

  r, err := btcjson.RpcSend(nc.Username, nc.Password, nc.Server, cmd)
  if err != nil {
    return "", err
  }

  if r.Error != nil {
    //log.Info("RPC error: ", r.Error)
    if r.Error.Code == -4 {
        return "", ncerr.ErrNoSuchDomain
    }
    return "", r.Error
  }

  if r.Result == nil {
    //log.Info("NC NILRESULT")
    return "", fmt.Errorf("got nil result")
  }

  if nsr, ok := r.Result.(*extratypes.NameShowReply); ok {
    //log.Info("NC OK")
    return nsr.Value, nil
  } else {
    //log.Info("NC BADREPLY")
    return "", fmt.Errorf("bad reply")
  }
}

// © 2014 Hugo Landau <hlandau@devever.net>      GPLv3 or later
