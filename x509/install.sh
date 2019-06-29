#!/bin/bash

set -eu -o pipefail
shopt -s failglob

cp -a $(go env GOROOT)/src/crypto/x509/* ./
rm ./x509_test.go

# Stdlib x509 relies on "internal" packages in Go, which aren't importable
# outside of stdlib.  So we copy those packages and rename them.
OLD_INTERNAL_PATH=$(go env GOROOT)/src/internal/x/crypto/cryptobyte
NEW_INTERNAL_PATH=$(go env GOPATH)/src/github.com/namecoin/ncdns/x509/golang/x/crypto/cryptobyte
mkdir -p ${NEW_INTERNAL_PATH}/
cp -R ${OLD_INTERNAL_PATH}/* ${NEW_INTERNAL_PATH}/
OLD_PACKAGE='"internal/x/crypto/cryptobyte'
NEW_PACKAGE='"github.com/namecoin/ncdns/x509/golang/x/crypto/cryptobyte'
sed -i "s_${OLD_PACKAGE}_${NEW_PACKAGE}_g" ./*.go ${NEW_INTERNAL_PATH}/*.go
