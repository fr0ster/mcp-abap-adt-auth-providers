#!/bin/sh
# Starts the stand's KDC on a database made afresh at every start, so a
# restarted container holds exactly the fixtures below:
#
# - alice, whose password is the committed fixture alice.password;
# - HTTP/negotiate.stand.test@STAND.TEST (GSS name HTTP@negotiate.stand.test),
#   its keytab written to the keytab volume;
# - HTTP/stale.stand.test@STAND.TEST, whose keytab is exported and whose key is
#   then changed here (cpw -randkey) before any ticket exists: every ticket
#   for it is encrypted with a key the service's keytab does not hold, so the
#   service refuses it — a refused credential without touching the user.
#
# No keytab or key is committed; the master key is generated and never kept.
# /keytabs/ready tells the healthcheck the keytabs are final.
set -eu
rm -f /keytabs/ready /keytabs/negotiate.keytab /keytabs/stale.keytab
rm -rf /var/lib/krb5kdc
mkdir -p /var/lib/krb5kdc /etc/krb5kdc /keytabs
cat > /etc/krb5kdc/kdc.conf <<'CONF'
[kdcdefaults]
  kdc_ports = 88
  kdc_tcp_ports = 88
[realms]
  STAND.TEST = {
    database_name = /var/lib/krb5kdc/principal
    max_life = 10h
    max_renewable_life = 1d
  }
CONF
kdb5_util create -s -r STAND.TEST -P "$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')" >/dev/null
kadmin.local -q "addprinc -pw $(cat /stand/alice.password) alice@STAND.TEST" >/dev/null
kadmin.local -q "addprinc -randkey HTTP/negotiate.stand.test@STAND.TEST" >/dev/null
kadmin.local -q "ktadd -k /keytabs/negotiate.keytab HTTP/negotiate.stand.test@STAND.TEST" >/dev/null
kadmin.local -q "addprinc -randkey HTTP/stale.stand.test@STAND.TEST" >/dev/null
kadmin.local -q "ktadd -k /keytabs/stale.keytab HTTP/stale.stand.test@STAND.TEST" >/dev/null
kadmin.local -q "cpw -randkey HTTP/stale.stand.test@STAND.TEST" >/dev/null
# Apache's worker user reads the keytabs: throwaway keys of a throwaway realm.
chmod 644 /keytabs/negotiate.keytab /keytabs/stale.keytab
touch /keytabs/ready
exec krb5kdc -n
