#!/usr/bin/env bash
export HOME=~
set -euxo pipefail

# Adapted from Electrum-NMC.

AUTHMODE="$1"
shift

echo "Auth mode: '$AUTHMODE'"

if [[ "$AUTHMODE" == "pass" ]]
then
echo "Using password in namecoin.conf"
AUTHCONF="rpcuser=doggman
rpcpassword=donkey"
else
echo "Using cookie in namecoin.conf"
AUTHCONF="rpccookiefile=/tmp/namecoin.cookie"
fi

mkdir -p ~/.namecoin
cat > ~/.namecoin/namecoin.conf <<EOF
regtest=1
txindex=1
printtoconsole=1
$AUTHCONF
rpcallowip=127.0.0.1
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
fallbackfee=0.0002
[regtest]
rpcbind=0.0.0.0
rpcport=18554
EOF
rm -rf ~/.namecoin/regtest
namecoind -regtest &
sleep 6

if [[ "$AUTHMODE" != "pass" ]]
then
echo "Setting cookie permissions"
chmod 666 /tmp/namecoin.cookie
fi

if [[ "$AUTHMODE" == "unix" ]]
then
echo "Launching Unix to TCP proxy"
socat -d UNIX-LISTEN:/tmp/namecoin.sock,fork TCP:localhost:18554 &
sleep 6
chmod 666 /tmp/namecoin.sock
fi

namecoin-cli createwallet test_wallet
addr="$(namecoin-cli getnewaddress)"
namecoin-cli generatetoaddress 150 "$addr"
tail -f ~/.namecoin/regtest/debug.log
