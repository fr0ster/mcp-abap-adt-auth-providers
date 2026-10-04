# Shared by tests/xsuaa/*.sh. Sourced, not run. Bash 3.2-compatible.
#
# These scripts create and delete real resources in a BTP subaccount. Two
# rules keep them from touching anything else:
#   - they refuse to run unless `cf` targets exactly XSUAA_CF_API,
#     XSUAA_CF_ORG and XSUAA_CF_SPACE — no defaults;
#   - they touch only what they created. Every resource setup.sh creates is
#     recorded in $LEDGER with its immutable ID — the service instance GUID,
#     the x509 service key's GUID, the trust's id — and the ledger itself names the target it belongs to.
#     A resource is ours only if its name AND its current ID match a record,
#     checked right before it is reused, refreshed or deleted; a ledger from
#     another target is refused outright.
#
# Ledger format:   target <api>|<org>|<space>
#                  instance <name> <guid>
#                  key <name> <guid>        (a key of $INSTANCE)
#                  trust <origin> <id>

INSTANCE=auth-providers-bearer-test
API_INSTANCE=auth-providers-trust-test
KEY=key
# A second key of $INSTANCE, holding a client certificate instead of a secret.
X509_KEY=x509-key
ORIGIN=auth-providers-test-idp
LOCAL="$HERE/.local"
LEDGER="$LOCAL/owned"

guard_target() {
  if [ -z "${XSUAA_CF_API:-}" ] || [ -z "${XSUAA_CF_ORG:-}" ] || [ -z "${XSUAA_CF_SPACE:-}" ]; then
    echo "Set XSUAA_CF_API, XSUAA_CF_ORG and XSUAA_CF_SPACE to the Cloud Foundry" \
      "API, org and space to use." >&2
    exit 2
  fi
  target="$(cf target 2>/dev/null || true)"
  api="$(printf '%s\n' "$target" | sed -n 's/^API endpoint: *//p')"
  org="$(printf '%s\n' "$target" | sed -n 's/^org: *//p')"
  space="$(printf '%s\n' "$target" | sed -n 's/^space: *//p')"
  if [ "$api" != "$XSUAA_CF_API" ] || [ "$org" != "$XSUAA_CF_ORG" ] || [ "$space" != "$XSUAA_CF_SPACE" ]; then
    echo "Refusing: cf targets '$api' / '$org' / '$space'," \
      "not '$XSUAA_CF_API' / '$XSUAA_CF_ORG' / '$XSUAA_CF_SPACE'." >&2
    echo "Run: cf login -a $XSUAA_CF_API --sso -o $XSUAA_CF_ORG -s $XSUAA_CF_SPACE" >&2
    exit 2
  fi
  TARGET="$api|$org|$space"
}

# A ledger written for another target must never be acted on here.
guard_ledger() {
  if [ -f "$LEDGER" ]; then
    recorded="$(sed -n '1s/^target //p' "$LEDGER")"
    if [ "$recorded" != "$TARGET" ]; then
      echo "Refusing: $LEDGER records resources of '$recorded', not '$TARGET'." >&2
      echo "Switch cf back to that target to tear them down." >&2
      exit 2
    fi
  fi
}

start_ledger() {
  mkdir -p "$LOCAL"
  chmod 700 "$LOCAL"
  [ -f "$LEDGER" ] || printf 'target %s\n' "$TARGET" > "$LEDGER"
}

recorded_id() { # kind name
  [ -f "$LEDGER" ] || return 0
  awk -v k="$1" -v n="$2" '$1 == k && $2 == n { print $3 }' "$LEDGER"
}

own() { # kind name id
  disown "$1" "$2"
  printf '%s %s %s\n' "$1" "$2" "$3" >> "$LEDGER"
}

disown() { # kind name
  if [ -f "$LEDGER" ]; then
    awk -v k="$1" -v n="$2" '!($1 == k && $2 == n)' "$LEDGER" > "$LEDGER.tmp"
    mv "$LEDGER.tmp" "$LEDGER"
  fi
}

# Records other than the target line.
ledger_entries() {
  [ -f "$LEDGER" ] && sed -n '2,$p' "$LEDGER" || true
}

# Prints the instance's GUID, or nothing when cf confirms there is no such
# instance. Any other outcome — no session, no network, an API error — fails:
# `cf service` exits 1 for "not found" and for errors alike, so only its exact
# not-found message counts as absence. Callers must stop on that failure
# rather than read an empty result as "gone".
instance_guid() { # name
  if out="$(cf service "$1" --guid 2>&1)"; then
    if printf '%s\n' "$out" | grep -qE '^[0-9a-f-]{36}$'; then
      printf '%s\n' "$out" | grep -E '^[0-9a-f-]{36}$'
      return 0
    fi
  elif printf '%s\n' "$out" | grep -qxF "Service instance '$1' not found"; then
    return 0
  fi
  echo "could not look up service instance $1: $(printf '%s' "$out" | head -1)" >&2
  return 3
}

# Prints the GUID of the service key <key> of the instance <instance-guid>,
# or nothing when the Cloud Controller lists no such key. Asked through the v3
# API rather than `cf service-key --guid`, so absence is an empty list, not a
# message to match: any answer that is not a list — no session, no network,
# an API error — fails, and callers must stop rather than read it as "gone".
key_guid() { # instance-guid key
  out="$(cf curl "/v3/service_credential_bindings?type=key&service_instance_guids=$1&names=$2" 2>&1)" || {
    echo "could not look up service key $2: $(printf '%s' "$out" | head -1)" >&2
    return 3
  }
  printf '%s' "$out" | node -e '
    let raw = "";
    process.stdin.on("data", (c) => (raw += c)).on("end", () => {
      let body;
      try { body = JSON.parse(raw); } catch { body = undefined; }
      if (!body || !Array.isArray(body.resources)) {
        console.error(`could not look up service key ${process.argv[1]}: not a listing`);
        process.exit(3);
      }
      if (body.resources.length > 1) {
        console.error(`service key ${process.argv[1]}: ${body.resources.length} found, expected one`);
        process.exit(3);
      }
      if (body.resources.length === 1) console.log(body.resources[0].guid);
    });
  ' "$2"
}

# `cf service-key` prints a header before the JSON. The file is created
# readable by its owner only, before anything is written to it: the key holds
# a secret or a private key, and never reaches the terminal.
save_key() { # instance key file
  rm -f "$3"
  (umask 077 && cf service-key "$1" "$2" 2>/dev/null | sed -n '/^{/,$p' > "$3")
  [ -s "$3" ]
}
