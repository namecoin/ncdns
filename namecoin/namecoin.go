package namecoin

// btcjson had to be modified a bit to get correct error reporting.
import (
	extratypes "github.com/hlandau/ncbtcjsontypes"
	"github.com/hlandauf/btcjson"
	"gopkg.in/hlandau/madns.v1/merr"

	"expvar"
	"fmt"
	"sync/atomic"
)

var cQueryCalls = expvar.NewInt("ncdns.namecoin.numQueryCalls")
var cSyncCalls = expvar.NewInt("ncdns.namecoin.numSyncCalls")
var cFilterCalls = expvar.NewInt("ncdns.namecoin.numFilterCalls")
var cScanCalls = expvar.NewInt("ncdns.namecoin.numScanCalls")
var cCurHeightCalls = expvar.NewInt("ncdns.namecoin.numCurHeightCalls")

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

	// If set, this is called to obtain the username and password instead of
	// using the Username and Password fields.
	GetAuth func() (username, password string, err error)

	Server string
}

func (nc *Conn) getAuth() (username string, password string, err error) {
	if nc.GetAuth == nil {
		return nc.Username, nc.Password, nil
	}

	return nc.GetAuth()
}

func (nc *Conn) rpcSend(cmd btcjson.Cmd) (btcjson.Reply, error) {
	username, password, err := nc.getAuth()
	if err != nil {
		return btcjson.Reply{}, err
	}

	return btcjson.RpcSend(username, password, nc.Server, cmd)
}

// Query the Namecoin daemon for a Namecoin domain (e.g. d/example).
// If the domain exists, returns the value stored in Namecoin, which should be JSON.
// Note that this will return domain data even if the domain is expired.
func (nc *Conn) Query(name string) (v string, err error) {
	cQueryCalls.Add(1)

	cmd, err := extratypes.NewNameShowCmd(newID(), name)
	if err != nil {
		//log.Info("NC NEWCMD ", err)
		return "", err
	}

	r, err := nc.rpcSend(cmd)
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
	cSyncCalls.Add(1)

	cmd, err := extratypes.NewNameSyncCmd(newID(), hash, count, wait)
	if err != nil {
		return nil, err
	}

	r, err := nc.rpcSend(cmd)
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
	cCurHeightCalls.Add(1)

	cmd, err := btcjson.NewGetInfoCmd(newID())
	if err != nil {
		return 0, err
	}

	r, err := nc.rpcSend(cmd)
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

func (nc *Conn) Filter(regexp string, maxage, from, count int) (names []extratypes.NameFilterItem, err error) {
	cFilterCalls.Add(1)

	cmd, err := extratypes.NewNameFilterCmd(newID(), regexp, maxage, from, count)
	if err != nil {
		return nil, err
	}

	r, err := nc.rpcSend(cmd)
	if err != nil {
		return nil, err
	}

	if r.Error != nil {
		return nil, r.Error
	}

	if r.Result == nil {
		return nil, fmt.Errorf("got nil result")
	}

	if nsr, ok := r.Result.(extratypes.NameFilterReply); ok {
		return []extratypes.NameFilterItem(nsr), nil
	}

	return nil, fmt.Errorf("bad reply")
}

func (nc *Conn) Scan(from string, count int) (names []extratypes.NameFilterItem, err error) {
	cScanCalls.Add(1)

	cmd, err := extratypes.NewNameScanCmd(newID(), from, count)
	if err != nil {
		return nil, err
	}

	r, err := nc.rpcSend(cmd)
	if err != nil {
		return nil, err
	}

	if r.Error != nil {
		return nil, r.Error
	}

	if r.Result == nil {
		return nil, fmt.Errorf("got nil result")
	}

	if nsr, ok := r.Result.(extratypes.NameFilterReply); ok {
		return []extratypes.NameFilterItem(nsr), nil
	}

	return nil, fmt.Errorf("bad reply")
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
