# A stand for one question: does a domain client authenticate to this server by Kerberos?
#
# Everything a logon needs in one image - a KDC, the client tools and the server itself - so the
# three containers share a realm, a keytab and the krb5.conf that points at it.
FROM rust:1.99.1-slim-trixie AS build

WORKDIR /w
COPY . .
RUN cargo build --release -p minimal-smb-example --features krb5

FROM debian:trixie-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      krb5-kdc krb5-admin-server krb5-user samba-client \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /w/target/release/minimal-smb-example /usr/local/bin/smb-minimal

# The realm, the KDC and the client all read this. `smbhost` is the DNS name the client connects to,
# and the service principal is therefore `cifs/smbhost` - the name in the ticket has to match the name
# in the URL, or every ticket is for another service.
RUN printf '%s\n' \
  '[libdefaults]' \
  ' default_realm = EXAMPLE.COM' \
  ' dns_lookup_realm = false' \
  ' dns_lookup_kdc = false' \
  ' rdns = false' \
  ' udp_preference_limit = 1' \
  '' \
  '[realms]' \
  ' EXAMPLE.COM = {' \
  '  kdc = kdc.example.com:88' \
  '  admin_server = kdc.example.com' \
  ' }' \
  '' \
  '[domain_realm]' \
  ' .example.com = EXAMPLE.COM' \
  > /etc/krb5.conf

# The KDC reads its realm's configuration from here. Without it `krb5kdc` refuses to start with
# "cannot initialize realm EXAMPLE.COM", which reads like a database problem rather than a missing
# config file.
RUN mkdir -p /etc/krb5kdc && printf '%s\n' \
  '[kdcdefaults]' \
  ' kdc_ports = 88' \
  ' kdc_tcp_ports = 88' \
  '' \
  '[realms]' \
  ' EXAMPLE.COM = {' \
  '  database_name = /shared/kdc/principal' \
  '  acl_file = /etc/krb5kdc/kadm5.acl' \
  '  key_stash_file = /shared/kdc/.k5.EXAMPLE.COM' \
  '  max_life = 24h 0m 0s' \
  '  max_renewable_life = 7d 0h 0m 0s' \
  '  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal' \
  ' }' \
  > /etc/krb5kdc/kdc.conf \
 && printf '%s\n' '*/admin@EXAMPLE.COM *' > /etc/krb5kdc/kadm5.acl

COPY stand/stand.sh /usr/local/bin/stand.sh
RUN chmod +x /usr/local/bin/stand.sh

ENTRYPOINT ["/usr/local/bin/stand.sh"]
