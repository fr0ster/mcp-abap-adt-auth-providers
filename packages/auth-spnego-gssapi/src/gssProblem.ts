import type { NegotiateSourceProblem } from '@mcp-abap-adt/interfaces-auth';

/**
 * What the `kerberos` binding's failure says, as a problem from the closed
 * list. The binding (7.0.0) exposes no status codes: its error is a plain
 * `Error` whose message is `<major>: <minor>` from `gss_display_status`
 * (MIT krb5, Heimdal) or `<SSPI call>: <FormatMessage text>` (Windows). So the
 * message is searched for fixed phrases with a plain, case-sensitive
 * `includes` — never a regex — and nothing of it leaves this function.
 *
 * The phrases come from the libraries' own error tables; which ones a real
 * failure carries is measured on the Kerberos stand (MIT) and in the second
 * stage (macOS, Windows, whose SSPI texts are localised). Unmatched is
 * `source-failed`.
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
      'Server not found in Kerberos database', // KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN
      'The specified target is unknown or unreachable', // SEC_E_TARGET_UNKNOWN
    ],
  ],
  [
    'kdc-unreachable',
    [
      'Cannot contact any KDC', // KRB5_KDC_UNREACH
      'Cannot find KDC for', // KRB5_REALM_UNKNOWN
      'unable to reach any KDC', // Heimdal
      'No authority could be contacted for authentication', // SEC_E_NO_AUTHORITY
    ],
  ],
  [
    'clock-skew',
    [
      'Clock skew too great', // KRB5KRB_AP_ERR_SKEW
      'The clocks on the client and server machines are skewed', // SEC_E_TIME_SKEW
    ],
  ],
  [
    'no-credential',
    [
      'No Kerberos credentials available', // MIT minor, no ticket cache
      'No credentials cache found', // KRB5_FCC_NOFILE
      'No credentials were supplied', // GSS_S_NO_CRED
      'Ticket expired', // KRB5KRB_AP_ERR_TKT_EXPIRED
      'The referenced credential has expired', // GSS_S_CREDENTIALS_EXPIRED
      'The referenced credentials have expired',
      'No credentials are available in the security package', // SEC_E_NO_CREDENTIALS
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
