#!/usr/bin/env bash

set -euxo pipefail
shopt -s nullglob globstar

# set GOPATH if empty (travis sets it, but useful for humans)
if [ -z "$GOPATH" ]; then
GOPATH=$(go env GOPATH)
export GOPATH
fi

mkdir -p "$GOPATH"/src/github.com/"$CIRRUS_REPO_OWNER"
cp -av "$PWD" "$GOPATH"/src/github.com/"$CIRRUS_REPO_FULL_NAME"
cd "$GOPATH"/src/github.com/"$CIRRUS_REPO_FULL_NAME"
