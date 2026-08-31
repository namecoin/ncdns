#!/usr/bin/env bash

set -euxo pipefail

cp testdata/go.mod testdata/go.sum .

go mod download github.com/coreos/go-systemd/v22
systemd_path="$(go list -m -f '{{.Dir}}' github.com/coreos/go-systemd/v22)"
go mod edit -replace "github.com/coreos/go-systemd=$systemd_path"
go mod tidy -diff
