#!/usr/bin/env bash
# Stops and removes the UAA stand. The generated keys stay for the next run.
set -euo pipefail
cd "$(dirname "$0")"
docker compose down
