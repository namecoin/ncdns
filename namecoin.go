package main
import "github.com/hlandauf/btcjson"
import "encoding/json"
import "sync/atomic"
import "fmt"
//import "github.com/hlandau/degoutils/log"

var idCounter int32 = 0

func newID() int32 {
  return atomic.AddInt32(&idCounter, 1)
}

type NameShowCmd struct {
  id interface{}
  Name string `json:"name"`
}

func NewNameShowCmd(id interface{}, name string) (*NameShowCmd, error) {
  return &NameShowCmd {
    id: id,
    Name: name,
  }, nil
}

func (c *NameShowCmd) Id() interface{} {
  return c.id
}

func (c *NameShowCmd) Method() string {
  return "name_show"
}

func (c *NameShowCmd) MarshalJSON() ([]byte, error) {
  params := []interface{}{
    c.Name,
  }

  raw, err := btcjson.NewRawCmd(c.id, c.Method(), params)
  if err != nil {
    return nil, err
  }

  return json.Marshal(raw)
}

func (c *NameShowCmd) UnmarshalJSON(b []byte) error {
  // We don't need to implement this as we are only ever the client.
  panic("not implemented")
  return nil
}

type NameShowReply struct {
  Name      string `json:"name"`
  Value     string `json:"value"`
  ExpiresIn int    `json:"expires_in"`
}

func replyParser(m json.RawMessage) (interface{}, error) {
  nsr := &NameShowReply{}
  err := json.Unmarshal(m, nsr)
  if err != nil {
    return nil, err
  }

  return nsr, nil
}

func init() {
  btcjson.RegisterCustomCmd("name_show", nil, replyParser, "name_show <name>")
}

type NamecoinConn struct {
  Username string
  Password string
  Server string
}

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

  cmd, err := NewNameShowCmd(newID(), name)
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
        return "", ErrNoSuchDomain
    }
    return "", r.Error
  }

  if r.Result == nil {
    //log.Info("NC NILRESULT")
    return "", fmt.Errorf("got nil result")
  }

  if nsr, ok := r.Result.(*NameShowReply); ok {
    //log.Info("NC OK")
    return nsr.Value, nil
  } else {
    //log.Info("NC BADREPLY")
    return "", fmt.Errorf("bad reply")
  }
}

// © 2014 Hugo Landau <hlandau@devever.net>      GPLv3 or later
