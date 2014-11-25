package namecoin

// btcjson had to be modified a bit to get correct error reporting.
import "github.com/hlandauf/btcjson"
import "github.com/hlandau/madns/merr"
import "github.com/hlandau/ncdns/namecoin/extratypes"

import "sync/atomic"
import "fmt"

// Used for generating IDs for JSON-RPC requests.
var idCounter int32

func newID() int32 {
	return atomic.AddInt32(&idCounter, 1)
}

// Used to query a Namecoin JSON-RPC interface. Initialize the struct with a
// username, password, and address (hostname:port).
type Conn struct {
	Username string
	Password string
	Server   string
}

// Query the Namecoin daemon for a Namecoin domain (e.g. d/example).
// If the domain exists, returns the value stored in Namecoin, which should be JSON.
// Note that this will return domain data even if the domain is expired.
func (nc *Conn) Query(name string) (v string, err error) {
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
			return "", merr.ErrNoSuchDomain
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
	}

	//log.Info("NC BADREPLY")
	return "", fmt.Errorf("bad reply")
}

var ErrSyncNoSuchBlock = fmt.Errorf("no block exists with given hash")

const rpcInvalidAddressOrKey = -5

func (nc *Conn) Sync(hash string, count int, wait bool) ([]extratypes.NameSyncEvent, error) {
	cmd, err := extratypes.NewNameSyncCmd(newID(), hash, count, wait)
	if err != nil {
		return nil, err
	}

	r, err := btcjson.RpcSend(nc.Username, nc.Password, nc.Server, cmd)
	if err != nil {
		return nil, err
	}

	if r.Error != nil {
		if r.Error.Code == rpcInvalidAddressOrKey {
			return nil, ErrSyncNoSuchBlock
		}
		return nil, r.Error
	}

	if r.Result == nil {
		return nil, fmt.Errorf("got nil result")
	}

	if nsr, ok := r.Result.(extratypes.NameSyncReply); ok {
		return []extratypes.NameSyncEvent(nsr), nil
	}

	return nil, fmt.Errorf("bad reply")
}

func (nc *Conn) CurHeight() (int, error) {
	cmd, err := btcjson.NewGetInfoCmd(newID())
	if err != nil {
		return 0, err
	}

	r, err := btcjson.RpcSend(nc.Username, nc.Password, nc.Server, cmd)
	if err != nil {
		return 0, err
	}

	if r.Error != nil {
		return 0, r.Error
	}

	if r.Result == nil {
		return 0, fmt.Errorf("got nil result")
	}

	if rep, ok := r.Result.(*btcjson.InfoResult); ok {
		return int(rep.Blocks), nil
	}

	return 0, fmt.Errorf("bad reply")
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
