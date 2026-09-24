# Shared by tests/xsuaa/*.sh. Sourced, not run.
#
# These scripts create and delete real resources in a BTP subaccount. They
# refuse to run unless `cf` targets exactly the API and org named in
# XSUAA_CF_API and XSUAA_CF_ORG — there are no defaults, so a `cf` left
# pointing at another org cannot receive them.

INSTANCE=auth-providers-bearer-test
API_INSTANCE=auth-providers-trust-test
KEY=key
ORIGIN=auth-providers-test-idp
LOCAL="$HERE/.local"

guard_target() {
  if [ -z "${XSUAA_CF_API:-}" ] || [ -z "${XSUAA_CF_ORG:-}" ]; then
    echo "Set XSUAA_CF_API and XSUAA_CF_ORG to the Cloud Foundry API and org" \
      "to use, e.g. https://api.cf.us10-001.hana.ondemand.com and your trial org." >&2
    exit 2
  fi
  target="$(cf target 2>/dev/null || true)"
  api="$(printf '%s\n' "$target" | sed -n 's/^API endpoint: *//p')"
  org="$(printf '%s\n' "$target" | sed -n 's/^org: *//p')"
  if [ "$api" != "$XSUAA_CF_API" ] || [ "$org" != "$XSUAA_CF_ORG" ]; then
    echo "Refusing: cf targets '$api' / '$org', not '$XSUAA_CF_API' / '$XSUAA_CF_ORG'." >&2
    echo "Run: cf login -a $XSUAA_CF_API --sso -o $XSUAA_CF_ORG" >&2
    exit 2
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
