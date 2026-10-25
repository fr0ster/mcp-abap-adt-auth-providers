# The stand's Negotiate-only service: Apache httpd with mod_auth_gssapi (see
# site.conf). Build context: tests/stand/kerberos.
FROM debian:bookworm-20261020-slim
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    apache2 libapache2-mod-auth-gssapi curl \
  && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
COPY negotiate/site.conf /etc/apache2/sites-available/000-default.conf
RUN a2enmod auth_gssapi headers rewrite >/dev/null \
  && echo 'negotiate' > /var/www/html/sap
CMD ["apachectl", "-D", "FOREGROUND"]
