// This package contains extensions to btcjson used by the namecoin package.
// It is not intended for public use.
package extratypes

import "github.com/hlandauf/btcjson"
import "encoding/json"

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

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
