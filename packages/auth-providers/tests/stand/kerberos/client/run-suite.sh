#!/usr/bin/env bash
# Runs the SPNego suite inside the stand's spnego-client container (compose
# service spnego-client; tests/stand/run.sh starts it). /repo is run.sh's
# export of the files git tracks of the two packages, mounted read-only — not
# the working tree. The two packages are copied into the container's own
# /work, installed there from the registry with install scripts off, the
# kerberos binding built from source (the one script allowScripts admits),
# both packages built, and the suite run. The host's node_modules are never
# read or written. Exits with the suite's code.
set -euo pipefail
REPO=/repo/packages
WORK=/work/packages
mkdir -p "$WORK"
for package in auth-providers auth-spnego-gssapi; do
  tar -C "$REPO" -cf - --exclude=node_modules --exclude=dist \
    --exclude=coverage --exclude='*.tsbuildinfo' "$package" | tar -C "$WORK" -xf -
done
# Biome in auth-providers reads the repository's ignore file (vcs.root ../..).
cp /repo/.gitignore /work/.gitignore

cd "$WORK/auth-providers"
npm ci --ignore-scripts
npm run build

cd "$WORK/auth-spnego-gssapi"
npm ci --ignore-scripts
# node-gyp builds against the image's own Node headers (/usr/local/include/
# node): nothing is downloaded but the registry's packages. Its log (info)
# shows the headers it used.
npm rebuild kerberos --build-from-source --nodedir=/usr/local \
  --foreground-scripts --loglevel=info
npm run build

# The suite's own ticket cache, in a temporary directory: the suite fills it
# with kinit; a case needing another Kerberos environment runs in a child
# process given that environment.
KRB5CCNAME="FILE:$(mktemp -d)/alice" STAND_KERBEROS=1 \
  npm test -- src/__tests__/stand
