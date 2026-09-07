#!/usr/bin/env bash
export HOME=~
set -eux pipefail

# Adapted from Electrum-NMC.

mkdir -p ~/.namecoin
cat > ~/.namecoin/namecoin.conf <<EOF
regtest=1
txindex=1
printtoconsole=1
rpcuser=doggman
rpcpassword=donkey
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
namecoin-cli createwallet test_wallet
addr="$(namecoin-cli getnewaddress)"
namecoin-cli generatetoaddress 150 "$addr"
tail -f ~/.namecoin/regtest/debug.log
