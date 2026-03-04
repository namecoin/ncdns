package namecoin

import (
	"github.com/ybbus/jsonrpc/v3"
	"gopkg.in/hlandau/madns.v2/merr"

	ncbtcjson "github.com/JeremyRand/minincbtcjson"
	ncrpcclient "github.com/JeremyRand/minincrpcclient"
)

// Client represents an ncrpcclient.Client with an additional DNS-friendly
// convenience wrapper around NameShow.
type Client struct {
	*ncrpcclient.Client
}

func New(config *ncrpcclient.ConnConfig) (*Client, error) {
	ncClient, err := ncrpcclient.New(config)
	if err != nil {
		return nil, err
	}

	return &Client{ncClient}, nil
}

// NameQuery returns the value of a name.  If the name doesn't exist, the error
// returned will be merr.ErrNoSuchDomain.
func (c *Client) NameQuery(name string, streamIsolationID string) (string, error) {
	nameData, err := c.NameShow(name, &ncbtcjson.NameShowOptions{StreamID: streamIsolationID})
	if err != nil {
		if jerr, ok := err.(*jsonrpc.RPCError); ok {
			if jerr.Code == ncbtcjson.ErrRPCWallet {
				// ErrRPCWallet from name_show indicates that
				// the name does not exist.
				return "", merr.ErrNoSuchDomain
			}
		}

		// Some error besides NXDOMAIN happened; pass that error
		// through unaltered.
		return "", err
	}

	// TODO: check the "value_error" field for errors and report those to the caller.

	// We got the name data.  Return the value.
	return nameData.Value, nil
}
