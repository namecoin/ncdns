#!/bin/bash

set -eu -o pipefail
shopt -s failglob

cp -a $(go env GOROOT)/src/crypto/x509/* ./
rm ./x509_test.go
