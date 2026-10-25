#!/usr/bin/env bash
# Stops and removes the stand, its keytab volume included (the KDC writes the
# keytabs afresh at every start). The images built from kerberos/ are kept,
# like the pulled ones.
set -euo pipefail
cd "$(dirname "$0")"
docker compose down --volumes
