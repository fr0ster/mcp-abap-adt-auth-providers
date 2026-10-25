import { describe, expect, it } from '@jest/globals';
import { mapGssFailure } from '../gssProblem';

// The shapes the binding builds (kerberos 7.0.0, src/unix/kerberos_gss.cc:
// `<major>: <minor>` from gss_display_status; src/win32/kerberos_sspi.cc:
// `<SSPI call>: <FormatMessage text>`), with the texts of MIT krb5 and of
// Windows. Which texts a real failure carries is measured on the Kerberos
// stand (Task C4) and, for Windows, in the second stage.
describe('mapGssFailure', () => {
  it.each([
    // Measured 2026-10-25, MIT krb5 1.20.1 (Debian bookworm), kerberos 7.0.0
    // built from source, KRB5CCNAME at a missing / an empty cache file.
    [
      'No credentials were supplied, or the credentials were unavailable or inaccessible: SPNEGO cannot find mechanisms to negotiate',
      'no-credential',
    ],
    [
      'No credentials were supplied, or the credentials were unavailable or inaccessible: No Kerberos credentials available: Bad format in credentials cache (filename: /tmp/tmp.R2paXGqd8U/empty)',
      'no-credential',
    ],
    // Measured 2026-10-25, macOS arm64 GitHub runner, GSS.framework (Heimdal),
    // no ticket cache: the raw text received for kerberos.
    [
      ' Miscellaneous failure (see text): get-pricipal open(/var/folders/n6/hn37q6pj7sj_9dmqqc2113800000gn/T/gssapi-no-ticket-8N5DhB/cc): No such file or directory',
      'no-credential',
    ],
    // Measured 2026-10-25 on the Kerberos stand, MIT krb5 1.20.1, kerberos
    // 7.0.0 built from source; the same text for spnego and kerberos.
    [
      'Unspecified GSS failure.  Minor code may provide more information: Server HTTP/unknown.stand.test@STAND.TEST not found in Kerberos database',
      'service-unknown',
    ],
    [
      "Unspecified GSS failure.  Minor code may provide more information: Cannot contact any KDC for realm 'STAND.TEST'",
      'kdc-unreachable',
    ],
    [
      'No credentials were supplied, or the credentials were unavailable or inaccessible: No Kerberos credentials available (default cache: FILE:/tmp/tmp.B3bQM7xkdR/missing)',
      'no-credential',
    ],
    // MIT krb5, no ticket cache / no ticket
    [
      'No credentials were supplied, or the credentials were unavailable or inaccessible: No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_1000)',
      'no-credential',
    ],
    [
      'No credentials were supplied, or the credentials were unavailable or inaccessible: No credentials cache found (filename: /tmp/x)',
      'no-credential',
    ],
    // MIT krb5, an expired ticket
    ['The referenced credential has expired: Ticket expired', 'no-credential'],
    ['The referenced credentials have expired: ', 'no-credential'],
    // Windows SSPI, SEC_E_NO_CREDENTIALS
    [
      'InitializeSecurityContext: No credentials are available in the security package\r\n',
      'no-credential',
    ],
    // service principal unknown to the KDC
    [
      'Unspecified GSS failure.  Minor code may provide more information: Server not found in Kerberos database',
      'service-unknown',
    ],
    [
      'InitializeSecurityContext: The specified target is unknown or unreachable\r\n',
      'service-unknown',
    ],
    // no KDC
    [
      "Unspecified GSS failure.  Minor code may provide more information: Cannot contact any KDC for realm 'EXAMPLE.COM'",
      'kdc-unreachable',
    ],
    [
      'Unspecified GSS failure.  Minor code may provide more information: Cannot find KDC for realm "EXAMPLE.COM"',
      'kdc-unreachable',
    ],
    [
      'Unspecified GSS failure.  Minor code may provide more information: unable to reach any KDC in realm EXAMPLE.COM',
      'kdc-unreachable',
    ],
    [
      'InitializeSecurityContext: No authority could be contacted for authentication.\r\n',
      'kdc-unreachable',
    ],
    // clock skew
    [
      'Unspecified GSS failure.  Minor code may provide more information: Clock skew too great',
      'clock-skew',
    ],
    [
      'InitializeSecurityContext: The clocks on the client and server machines are skewed.\r\n',
      'clock-skew',
    ],
  ])('%s → %s', (message, problem) => {
    expect(mapGssFailure(new Error(message))).toBe(problem);
  });

  it('reads the specific minor status before the general major one', () => {
    // A missing ticket for the service may come with GSS_S_NO_CRED's major
    // text while the minor names the real cause.
    expect(
      mapGssFailure(
        new Error(
          'No credentials were supplied, or the credentials were unavailable or inaccessible: Cannot contact any KDC for realm',
        ),
      ),
    ).toBe('kdc-unreachable');
  });

  it.each([
    ['an unmatched text', new Error('Ran out of memory encoding response')],
    ['an empty message', new Error('')],
    ['a primitive', 'No Kerberos credentials available'],
    ['undefined', undefined],
    ['null', null],
    ['a non-string message', { message: 42 }],
    [
      'a throwing message getter',
      Object.defineProperty({}, 'message', {
        get() {
          throw new Error('boom');
        },
      }),
    ],
    [
      'a throwing Proxy',
      new Proxy(
        {},
        {
          get() {
            throw new Error('boom');
          },
        },
      ),
    ],
  ])('anything else is source-failed: %s', (_label, thrown) => {
    expect(mapGssFailure(thrown)).toBe('source-failed');
  });

  it('maps the macOS SPNEGO no-ticket text to mechanism-unsupported', () => {
    // Measured 2026-10-25, macOS arm64 GitHub runner, GSS.framework (Heimdal),
    // no ticket cache, mechanism spnego — the text received.
    expect(
      mapGssFailure(
        new Error(
          ' An unsupported mechanism was requested: unknown mech-code 0 for mech unknown',
        ),
      ),
    ).toBe('mechanism-unsupported');
  });

  it('reads the macOS SPNEGO text only with its measured tail', () => {
    expect(
      mapGssFailure(new Error(' An unsupported mechanism was requested: ')),
    ).toBe('source-failed');
  });

  it('lets a specific cause win over the macOS no-ticket text', () => {
    expect(
      mapGssFailure(
        new Error(
          'Server not found in Kerberos database: get-pricipal open(/tmp/cc)',
        ),
      ),
    ).toBe('service-unknown');
  });

  it('reads an unknown client as no service problem', () => {
    // KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN names the client, not the service.
    expect(
      mapGssFailure(
        new Error(
          "Unspecified GSS failure.  Minor code may provide more information: Client 'bob@STAND.TEST' not found in Kerberos database",
        ),
      ),
    ).toBe('source-failed');
  });

  it('reads the two halves of the service-unknown text only in order', () => {
    expect(
      mapGssFailure(
        new Error('x not found in Kerberos database: Server HTTP/a@STAND.TEST'),
      ),
    ).toBe('source-failed');
    expect(
      mapGssFailure(new Error(': Server  not found in Kerberos database')),
    ).toBe('service-unknown');
  });

  it('never matches case-folded or partial phrases', () => {
    expect(mapGssFailure(new Error('clock skew too great'))).toBe(
      'source-failed',
    );
    expect(mapGssFailure(new Error('Server not found'))).toBe('source-failed');
  });
});
