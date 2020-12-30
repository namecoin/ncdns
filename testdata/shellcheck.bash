#!/bin/bash

set -euo pipefail
shopt -s nullglob globstar

# Run shellcheck on all shell scripts
# The .travis directory is currently unused (relic from ncdns).  It will be
# re-introduced later.  For now, we don't try to lint it, since it's inactive.
ALL_SHELL="$(grep -r --files-with-matches --exclude-dir=.git --exclude-dir=.travis '#!.*/bin/.*sh' ./)"
for I in $ALL_SHELL
do
    shellcheck "${I}"
done
