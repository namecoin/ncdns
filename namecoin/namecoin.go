package namecoin

import (
	"github.com/btcsuite/btcd/btcjson"
	"github.com/namecoin/btcd/rpcclient"
	"gopkg.in/hlandau/madns.v2/merr"

	"github.com/namecoin/ncbtcjson"
	"github.com/namecoin/ncrpcclient"
)

// Client represents an ncrpcclient.Client with an additional DNS-friendly
// convenience wrapper around NameShow.
type Client struct {
	*ncrpcclient.Client
}

func New(config *rpcclient.ConnConfig, ntfnHandlers *rpcclient.NotificationHandlers) (*Client, error) {
	ncClient, err := ncrpcclient.New(config, ntfnHandlers)
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
		if jerr, ok := err.(*btcjson.RPCError); ok {
			if jerr.Code == btcjson.ErrRPCWallet {
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
