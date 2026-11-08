#!/bin/sh
# One script, four roles, chosen by the first argument: the realm is created once, then the KDC and
# the server run, then a client logs on. Separate containers rather than one, so the logon is a real
# network exchange and not two processes agreeing with each other in one namespace.
set -eu

SHARED=/shared
KEYTAB="$SHARED/smb.keytab"

# The realm database lives on the shared volume, not in the image: `setup` runs in one container and
# `kdc` in another, and a database written into the first one disappears with it.
KDC_DB="$SHARED/kdc"

# One password for the stand, named once: `setup` writes it into the KDC and `client` presents it,
# and two different literals is a stand that fails at the logon with "password incorrect" - which
# reads like a Kerberos problem rather than a typo.
PASSWORD="${SMB_PASSWORD:-Passw0rd!}"

case "${1:-}" in
  setup)
    # The realm, once. `kdb5_util create` fails when a database already exists, and the volume keeps
    # it, so a re-run is not an error.
    mkdir -p "$KDC_DB"
    if [ ! -f "$KDC_DB/principal" ]; then
      kdb5_util create -s -P masterkey -r EXAMPLE.COM
    fi
    kadmin.local -q "addprinc -pw $PASSWORD alice" 2>/dev/null || true
    kadmin.local -q "addprinc -randkey cifs/smbhost" 2>/dev/null || true
    kadmin.local -q "ktadd -k $KEYTAB cifs/smbhost"
    # The keytab is a credential: readable by the server only.
    chmod 600 "$KEYTAB"
    echo "realm ready:"
    kadmin.local -q "listprincs"
    ;;

  kdc)
    exec krb5kdc -n
    ;;

  server)
    mkdir -p /srv/smb/public /srv/smb/media /srv/smb/home
    echo "hello from kerberised sysvol" > /srv/smb/public/readme.txt
    # 445 and not 4445: a real client goes to 445 by default, and a stand that only answers on a
    # private port tests the client's patience rather than the server's authentication.
    export SMB_LISTEN="0.0.0.0:445"
    export SMB_ROOT=/srv/smb
    export SMB_KEYTAB="$KEYTAB"
    export SMB_PASSWORD="$PASSWORD"
    export RUST_LOG="${RUST_LOG:-info}"
    exec /usr/local/bin/smb-minimal
    ;;

  client)
    # A real client: ticket from the KDC, then a logon the server has to accept by Kerberos alone.
    echo "$PASSWORD" | kinit alice
    klist
    echo "--- listing shares as alice"
    smbclient -k -L smbhost -m SMB3 -p 445 2>&1 || true
    echo "--- reading a file over the public share"
    smbclient -k "//smbhost/public" -m SMB3 -p 445 -c 'ls; get readme.txt /tmp/readme.txt' 2>&1 || true
    echo "--- what arrived"
    cat /tmp/readme.txt 2>/dev/null || echo "(no file)"
    ;;

  *)
    echo "usage: stand.sh setup|kdc|server|client" >&2
    exit 2
    ;;
esac
