# Shared by tests/xsuaa/*.sh. Sourced, not run. Bash 3.2-compatible.
#
# These scripts create and delete real resources in a BTP subaccount. Two
# rules keep them from touching anything else:
#   - they refuse to run unless `cf` targets exactly XSUAA_CF_API,
#     XSUAA_CF_ORG and XSUAA_CF_SPACE — no defaults;
#   - they touch only what they created. Every resource setup.sh creates is
#     recorded in $LEDGER with its immutable ID — the service instance GUID,
#     the trust's id — and the ledger itself names the target it belongs to.
#     A resource is ours only if its name AND its current ID match a record,
#     checked right before it is reused, refreshed or deleted; a ledger from
#     another target is refused outright.
#
# Ledger format:   target <api>|<org>|<space>
#                  instance <name> <guid>
#                  trust <origin> <id>

INSTANCE=auth-providers-bearer-test
API_INSTANCE=auth-providers-trust-test
KEY=key
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

# `cf service-key` prints a header before the JSON.
save_key() { # instance file
  cf service-key "$1" "$KEY" 2>/dev/null | sed -n '/^{/,$p' > "$2"
  chmod 600 "$2"
  [ -s "$2" ]
}
