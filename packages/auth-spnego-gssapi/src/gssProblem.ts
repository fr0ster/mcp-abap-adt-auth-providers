import type { NegotiateSourceProblem } from '@mcp-abap-adt/interfaces-auth';

/**
 * What the `kerberos` binding's failure says, as a problem from the closed
 * list. The binding (7.0.0) exposes no status codes: its error is a plain
 * `Error` whose message is `<major>: <minor>` from `gss_display_status`
 * (MIT krb5, Heimdal) or `<SSPI call>: <FormatMessage text>` (Windows). So the
 * message is searched for fixed phrases with a plain, case-sensitive
 * `includes` — never a regex — and nothing of it leaves this function.
 *
 * The phrases come from the libraries' own error tables. Each is tagged:
 * Measured (seen in a run, with the date) or To measure — the MIT ones on the
 * Kerberos stand (Task C4), Heimdal on macOS and SSPI on Windows (whose texts
 * are localised) in CI or the second stage. Unmatched is `source-failed`.
 *
 * Order matters: the specific causes (the minor status) are read before the
 * general "no credentials" major status that may accompany them.
 */
const PHRASES: ReadonlyArray<
  readonly [NegotiateSourceProblem, readonly string[]]
> = [
  [
    'service-unknown',
    [
      'Server not found in Kerberos database', // KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN — To measure (stand)
      'The specified target is unknown or unreachable', // SEC_E_TARGET_UNKNOWN — To measure (Windows)
    ],
  ],
  [
    'kdc-unreachable',
    [
      'Cannot contact any KDC', // KRB5_KDC_UNREACH — To measure (stand)
      'Cannot find KDC for', // KRB5_REALM_UNKNOWN — To measure (stand)
      'unable to reach any KDC', // Heimdal — To measure (macOS)
      'No authority could be contacted for authentication', // SEC_E_NO_AUTHORITY — To measure (Windows)
    ],
  ],
  [
    'clock-skew',
    [
      'Clock skew too great', // KRB5KRB_AP_ERR_SKEW — To measure (stand)
      'The clocks on the client and server machines are skewed', // SEC_E_TIME_SKEW — To measure (Windows)
    ],
  ],
  [
    'no-credential',
    [
      'No Kerberos credentials available', // MIT minor, no ticket cache — Measured 2026-10-25 (MIT 1.20.1, Docker)
      'No credentials cache found', // KRB5_FCC_NOFILE — To measure (not seen in the Docker run)
      'No credentials were supplied', // GSS_S_NO_CRED — Measured 2026-10-25 (MIT 1.20.1, Docker)
      'Ticket expired', // KRB5KRB_AP_ERR_TKT_EXPIRED — To measure (stand)
      'The referenced credential has expired', // GSS_S_CREDENTIALS_EXPIRED — To measure (stand)
      'The referenced credentials have expired', // To measure (stand)
      'No credentials are available in the security package', // SEC_E_NO_CREDENTIALS — To measure (Windows)
      // Measured 2026-10-25, macOS arm64 GitHub runner, GSS.framework
      // (Heimdal), no ticket cache: the text received for `kerberos` with
      // KRB5CCNAME at an absent file ("pricipal" is Heimdal's own spelling).
      // Last in the table, so no more specific phrase is shadowed.
      'get-pricipal open(',
    ],
  ],
];

/** The binding's message, if it is a string; anything else reads as absent. */
function messageOf(thrown: unknown): string | undefined {
  if (thrown === null || typeof thrown !== 'object') return undefined;
  try {
    const message: unknown = (thrown as { message?: unknown }).message;
    return typeof message === 'string' ? message : undefined;
  } catch {
    return undefined;
  }
}

export function mapGssFailure(thrown: unknown): NegotiateSourceProblem {
  const message = messageOf(thrown);
  if (message === undefined || message === '') return 'source-failed';
  for (const [problem, phrases] of PHRASES)
    for (const phrase of phrases) if (message.includes(phrase)) return problem;
  return 'source-failed';
}
