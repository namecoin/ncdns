#!/usr/bin/env bash

set -ex

# Make archives.
echo Archiving releases...
mkdir dist
pushd idist || exit 1
for x in *; do
  echo "$x"
  tar -caf "../dist/$(basename "$x").tar.gz" "$x"
done
popd || exit 1
