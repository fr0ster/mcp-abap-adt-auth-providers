# The stand's MIT krb5 KDC, realm STAND.TEST (see start.sh). Build context:
# tests/stand/kerberos.
FROM debian:bookworm-20261020-slim
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    krb5-kdc krb5-admin-server \
  && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
COPY alice.password /stand/alice.password
COPY kdc/start.sh /stand/start.sh
CMD ["sh", "/stand/start.sh"]
