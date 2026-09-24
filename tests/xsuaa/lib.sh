# Shared by tests/xsuaa/*.sh. Sourced, not run. Bash 3.2-compatible.
#
# These scripts create and delete real resources in a BTP subaccount. Two
# rules keep them from touching anything else:
#   - they refuse to run unless `cf` targets exactly XSUAA_CF_API,
#     XSUAA_CF_ORG and XSUAA_CF_SPACE — no defaults;
#   - they delete only what they created: every resource setup.sh creates is
#     recorded in $LOCAL/owned, a name that already exists without being
#     recorded there is refused, and teardown.sh deletes only recorded ones.

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
}

owns() { # entry
  [ -f "$LEDGER" ] && grep -qxF "$1" "$LEDGER"
}

own() { # entry
  mkdir -p "$LOCAL"
  owns "$1" || printf '%s\n' "$1" >> "$LEDGER"
}

disown() { # entry
  if [ -f "$LEDGER" ]; then
    grep -vxF "$1" "$LEDGER" > "$LEDGER.tmp" || true
    mv "$LEDGER.tmp" "$LEDGER"
  fi
}

service_exists() { # name
  cf service "$1" >/dev/null 2>&1
}

# `cf service-key` prints a header before the JSON.
save_key() { # instance file
  cf service-key "$1" "$KEY" 2>/dev/null | sed -n '/^{/,$p' > "$2"
  chmod 600 "$2"
  [ -s "$2" ]
}
