#!/bin/sh
set -e
goroot="$(go env GOROOT)"
x509path=$goroot/src/crypto/x509
test -d $goroot
test -d $x509path
cp -av $x509path/* .
rm x509_test.go
sed -i.bak 's/golang_org/golang.org/g' x509.go
