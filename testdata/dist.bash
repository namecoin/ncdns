#!/usr/bin/env bash

set -ex

# Make archives.
echo Archiving releases...
mkdir dist
pushd idist || exit 1
for x in *; do
  echo "$x"
  mkdir -p "$x/doc"
  cp -a "../README.md" "$x/"
  cp -a "../COPYING" "$x/"
  cp -a "../_doc/"* "$x/doc/"
  tar -caf "../dist/$(basename "$x").tar.gz" "$x"
done
popd || exit 1
