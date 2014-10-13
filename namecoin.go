package main
import "github.com/conformal/btcjson"
import "encoding/json"
import "sync/atomic"
import "fmt"

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
  cmd, err := NewNameShowCmd(newID(), name)
  if err != nil {
    return "", err
  }

  r, err := btcjson.RpcSend(nc.Username, nc.Password, nc.Server, cmd)
  if err != nil {
    if e, ok := err.(*btcjson.Error); ok {
      if e.Code == -4 {
        return "", ErrNoSuchDomain
      }
    }
    return "", err
  }

  if r.Result == nil {
    return "", fmt.Errorf("got nil result")
  }

  if nsr, ok := r.Result.(*NameShowReply); ok {
    return nsr.Value, nil
  } else {
    return "", fmt.Errorf("bad reply")
  }
}
