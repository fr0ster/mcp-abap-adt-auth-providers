#!/usr/bin/env bash
# Runs the SPNego suite inside the stand's spnego-client container (compose
# service spnego-client; tests/stand/run.sh starts it). The repository is
# mounted read-only at /repo: the two packages are copied, without their
# node_modules and build output, into the container's own /work, installed
# there from the registry with install scripts off, the kerberos binding built
# from source (the one script allowScripts admits), both packages built, and
# the suite run. The host's node_modules are never read or written. Exits with
# the suite's code.
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
npm rebuild kerberos --build-from-source
npm run build

# The suite's own ticket cache, in a temporary directory: the suite fills it
# with kinit; a case needing another Kerberos environment runs in a child
# process given that environment.
KRB5CCNAME="FILE:$(mktemp -d)/alice" STAND_KERBEROS=1 \
  npm test -- src/__tests__/stand
