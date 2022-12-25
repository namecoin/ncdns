#!/usr/bin/env bash
export HOME=~
set -eu

# Adapted from Electrum-NMC.

bitcoin_cli="namecoin-cli -rpcuser=doggman -rpcpassword=donkey -rpcport=18554 -regtest"

function new_blocks()
{
    $bitcoin_cli generatetoaddress "$1" "$($bitcoin_cli getnewaddress)" > /dev/null
}

function assert_equal()
{
    err_msg="$3"

    if [[ "$1" != "$2" ]]; then
        echo "'$1' != '$2'"
        echo "$err_msg"
        return 1
    fi
}

function assert_raises_error()
{
    cmd=$1
    required_err=$2

    if observed_err=$($cmd 2>&1) ; then
        echo "Failed to raise error '$required_err'"
        return 1
    fi
    if [[ "$observed_err" != *"$required_err"* ]]; then
        echo "$observed_err"
        echo "Raised wrong error instead of '$required_err'"
        return 1
    fi
}

echo "Expire any existing names from previous functional test runs"
new_blocks 35

echo "Pre-register testls.bit"
$bitcoin_cli name_new 'd/testls'

echo "Wait for pre-registration to mature"
new_blocks 12

echo "Register testls.bit"
$bitcoin_cli name_firstupdate 'd/testls'

echo "Wait for registration to confirm"
new_blocks 1

echo "Update testls.bit"
$bitcoin_cli name_update 'd/testls' '{"ip":"107.152.38.155","map":{"*":{"tls":[[2,1,0,"MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADvxHcjwDYMNfUSTtSIn3VbBC1sOzh/1Fv5T0UzEuLWIE="]]},"sub1":{"map":{"sub2":{"map":{"sub3":{"ip":"107.152.38.155"}}}}},"_tor":{"txt":"dhflg7a7etr77hwt4eerwoovhg7b5bivt2jem4366dt4psgnl5diyiyd.onion"}}}'

echo "Wait for update to confirm"
new_blocks 1

echo "Query testls.bit via Core"
$bitcoin_cli name_show 'd/testls'

echo "Query testls.bit IPv4 Authoritative via dig"
dig_output=$(dig -p 5391 @127.0.0.1 A testls.bit)
echo "$dig_output"
echo "Checking response correctness"
echo "$dig_output" | grep "107.152.38.155"

echo "Query testls.bit TLS Authoritative via dig"
dig_output=$(dig -p 5391 @127.0.0.1 TLSA "*.testls.bit")
echo "$dig_output"
echo "Checking response correctness"
tlsa_hex="$(echo 'MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADvxHcjwDYMNfUSTtSIn3VbBC1sOzh/1Fv5T0UzEuLWIE=' | base64 --decode | xxd -u -ps -c 500)"
echo "$dig_output" | sed 's/ //g' | grep "$tlsa_hex"

echo "Query testls.bit IPv4 Recursive via dig"
dig_output=$(dig -p 53 @127.0.0.1 A testls.bit)
echo "$dig_output"
echo "Checking response correctness"
echo "$dig_output" | grep "107.152.38.155"

echo "Query testls.bit TLS Recursive via dig"
dig_output=$(dig -p 53 @127.0.0.1 TLSA "*.testls.bit")
echo "$dig_output"
echo "Checking response correctness"
tlsa_hex="$(echo 'MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADvxHcjwDYMNfUSTtSIn3VbBC1sOzh/1Fv5T0UzEuLWIE=' | base64 --decode | xxd -u -ps -c 500)"
echo "$dig_output" | sed 's/ //g' | grep "$tlsa_hex"

echo "Fetch testls.bit via curl"
curl --insecure https://testls.bit/ | grep -i "Cool or nah"
