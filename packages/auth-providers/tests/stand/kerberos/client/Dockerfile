# The container the SPNego suite runs in: Node with the MIT Kerberos client
# tools (kinit, klist) and headers (to build the kerberos binding from
# source). Nothing of the repository is baked in: compose mounts it read-only
# and run-suite.sh copies what it needs. Build context: tests/stand/kerberos.
FROM node:24.22.1-bookworm
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    krb5-user libkrb5-dev \
  && rm -rf /var/lib/apt/lists/*
