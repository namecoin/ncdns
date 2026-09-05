#!/usr/bin/env bash

set -euxo pipefail

cp testdata/go.mod testdata/go.sum .

go mod download github.com/coreos/go-systemd/v22
systemd_path="$(go list -m -f '{{.Dir}}' github.com/coreos/go-systemd)"
go mod edit -replace "github.com/coreos/go-systemd=$systemd_path"

# Temporarily disabled because it's not supported in gccgo yet (was added in Go 1.23).
#go mod tidy -diff
go mod tidy
