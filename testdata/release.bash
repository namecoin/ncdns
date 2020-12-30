#!/usr/bin/env bash

set -ex

# Only upload version tags and master nightlies.
if ! [[ "$CIRRUS_TAG" =~ ^v[0-9] ]]; then
  if [[ "$CIRRUS_BRANCH" != "master" ]]; then
    echo Skipping release upload because this build is not for a release tag or a master nightly.
    exit 0
  fi

  RELEASES_NAME=$(date +%F)-$(echo "$CIRRUS_CHANGE_IN_REPO" | cut -c-8)
  export RELEASES_NAME
  git clone "https://NamecoinBot:$RELEASES_TOKEN@github.com/namecoin/nightly-${CIRRUS_REPO_NAME}.git"
  cd "nightly-${CIRRUS_REPO_NAME}"
  git config --local user.name "NamecoinBot"
  git config --local user.email "githubbot@namecoin.org"
  export CIRRUS_TAG=$RELEASES_NAME
  git tag "$CIRRUS_TAG"
  git push origin "$CIRRUS_TAG"
  cd ..
fi

if [[ "$GITHUB_TOKEN" == "" ]]; then
  echo "Please provide GitHub access token via GITHUB_TOKEN environment variable!"
  exit 1
fi

# Make archives.
bash ./testdata/dist.bash

pushd dist || exit 1

echo Uploading releases...
ghr -u "NamecoinBot" -r "nightly-${CIRRUS_REPO_NAME}" "$CIRRUS_TAG" "./"

popd || exit 1

echo Done
