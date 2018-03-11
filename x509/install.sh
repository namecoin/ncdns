#!/bin/bash

set -eu -o pipefail
shopt -s failglob

cp -a $(go env GOROOT)/src/crypto/x509/* ./
rm ./x509_test.go

# The following code is utterly horrifying.  I can't find a better way to do it.  :(
mkdir -p ${GOPATH}/src/vendor/golang.org/
cp -R $(go env GOROOT)/src/vendor/golang_org/* ${GOPATH}/src/vendor/golang.org/
# h/t to https://www.cyberciti.biz/faq/unix-linux-replace-string-words-in-many-files/
OLD_PACKAGE='"golang_org/x/crypto/cryptobyte'
OLD_PACKAGE="${OLD_PACKAGE//\//\\/}"
NEW_PACKAGE='"golang.org/x/crypto/cryptobyte'
NEW_PACKAGE="${NEW_PACKAGE//\//\\/}"
sed -i "s/${OLD_PACKAGE}/${NEW_PACKAGE}/g" ./*.go ${GOPATH}/src/vendor/golang.org/x/crypto/cryptobyte/*.go
