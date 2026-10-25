import type { NegotiateSourceProblem } from '@mcp-abap-adt/interfaces-auth';

/**
 * A phrase is a fixed text found anywhere, a fixed text the message ends
 * with, or a message that ends with `before`, a name, then `after` — for a
 * text that names a value (a principal), read by nothing. The name must be
 * non-empty and hold no space and no quote, and `before` is the last one
 * before it: a name of the user's choosing elsewhere in the message (an
 * unknown client is quoted, `Client '…'`) cannot complete the pattern.
 */
type Phrase =
  | string
  | { readonly endsWith: string }
  | { readonly endsWithName: readonly [before: string, after: string] };

/**
 * What the `kerberos` binding's failure says, as a problem from the closed
 * list. The binding (7.0.0) exposes no status codes: its error is a plain
 * `Error` with no enumerable property (measured 2026-10-25 on the stand),
 * whose message is `<major>: <minor>` from `gss_display_status` for MIT krb5
 * and Heimdal, or `<SSPI call>: <FormatMessage text>` on Windows. So the
 * message is searched for fixed phrases with a plain, case-sensitive
 * `includes` — never a regex — and nothing of it leaves this function.
 *
 * The phrases come from the libraries' own error tables. Each is tagged:
 * Measured (seen in a run, with the date) or To measure — the MIT ones on the
 * Kerberos stand (auth-providers' tests/stand/kerberos), Heimdal on macOS and
 * SSPI on Windows (whose texts are localised) in CI or the second stage.
 * Unmatched is `source-failed`.
 *
 * Order matters: the specific causes (the minor status) are read before the
 * general "no credentials" major status that may accompany them.
 */
const PHRASES: ReadonlyArray<
  readonly [NegotiateSourceProblem, readonly Phrase[]]
> = [
  [
    'service-unknown',
    [
      // KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN, as MIT's extended message names the
      // principal: "...information: Server HTTP/x@REALM not found in Kerberos
      // database". Measured 2026-10-25, MIT krb5 1.20.1, stand (spnego and
      // kerberos alike): the minor status is the end of the message, right
      // after the major text's "Minor code may provide more information: ".
      {
        endsWithName: [
          'Minor code may provide more information: Server ',
          ' not found in Kerberos database',
        ],
      },
      // the error table's own text (no principal) — To measure
      { endsWith: ': Server not found in Kerberos database' },
      'The specified target is unknown or unreachable', // SEC_E_TARGET_UNKNOWN — To measure (Windows)
    ],
  ],
  [
    'kdc-unreachable',
    [
      // KRB5_KDC_UNREACH: "...information: Cannot contact any KDC for realm
      // 'STAND.TEST'". Measured 2026-10-25, MIT krb5 1.20.1, stand: a cache
      // holding the TGT, a krb5.conf whose KDC nothing listens on (spnego and
      // kerberos alike).
      'Cannot contact any KDC',
      'Cannot find KDC for', // KRB5_REALM_UNKNOWN — To measure
      'unable to reach any KDC', // Heimdal — To measure (macOS)
      'No authority could be contacted for authentication', // SEC_E_NO_AUTHORITY — To measure (Windows)
    ],
  ],
  [
    'clock-skew',
    [
      'Clock skew too great', // KRB5KRB_AP_ERR_SKEW — To measure (one clock on the stand)
      'The clocks on the client and server machines are skewed', // SEC_E_TIME_SKEW — To measure (Windows)
    ],
  ],
  [
    'mechanism-unsupported',
    [
      // Measured 2026-10-25, macOS arm64 GitHub runner, GSS.framework
      // (Heimdal), no ticket cache — the text received for `spnego`.
      'unknown mech-code 0 for mech unknown',
    ],
  ],
  [
    'no-credential',
    [
      // MIT minor, no ticket: "No Kerberos credentials available (default
      // cache: FILE:...)" for a missing cache, "...: Bad format in
      // credentials cache (filename: ...)" for an empty file — kerberos.
      // Measured 2026-10-25, MIT krb5 1.20.1, Docker and the stand.
      'No Kerberos credentials available',
      'No credentials cache found', // KRB5_FCC_NOFILE — To measure (not seen: MIT 1.20.1 answers the text above for a missing cache)
      // GSS_S_NO_CRED, the major of both no-ticket answers; spnego's minor is
      // "SPNEGO cannot find mechanisms to negotiate", for a missing cache and
      // an empty one alike. Measured 2026-10-25, MIT krb5 1.20.1, Docker and
      // the stand.
      'No credentials were supplied',
      'Ticket expired', // KRB5KRB_AP_ERR_TKT_EXPIRED — To measure (not on the stand)
      'The referenced credential has expired', // GSS_S_CREDENTIALS_EXPIRED — To measure (not on the stand)
      'The referenced credentials have expired', // To measure (not on the stand)
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

/** A principal as MIT prints it: non-empty, no space, no quote. */
function isBareName(name: string): boolean {
  if (name === '') return false;
  for (const c of name) if (c === ' ' || c === "'" || c === '"') return false;
  return true;
}

/** Plain, case-sensitive string search; no regex. */
function says(message: string, phrase: Phrase): boolean {
  if (typeof phrase === 'string') return message.includes(phrase);
  if ('endsWith' in phrase) return message.endsWith(phrase.endsWith);
  const [before, after] = phrase.endsWithName;
  if (!message.endsWith(after)) return false;
  const rest = message.slice(0, message.length - after.length);
  const at = rest.lastIndexOf(before);
  return at >= 0 && isBareName(rest.slice(at + before.length));
}

export function mapGssFailure(thrown: unknown): NegotiateSourceProblem {
  const message = messageOf(thrown);
  if (message === undefined || message === '') return 'source-failed';
  for (const [problem, phrases] of PHRASES)
    for (const phrase of phrases) if (says(message, phrase)) return problem;
  return 'source-failed';
}
