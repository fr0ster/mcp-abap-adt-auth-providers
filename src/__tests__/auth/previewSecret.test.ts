/**
 * The preview (spec §6, "The preview"; H10): what the opt-in `authDebug`
 * line shows of a secret a server echoed — never more than 4 + 4 characters
 * of the recognised form, and only the length below 16 characters.
 * The redactor's single longest-first pass writes it in place of every
 * recognised form, and "recognition first" (spec §6) makes a wrapped base64
 * credential one span, previewed from the form it was recognised as.
 */

import { describe, expect, it } from '@jest/globals';
import { oauthErrorFields, previewSecret } from '../../auth/oauthErrorBody';

/** Every `<redacted, N chars>` preview of a text, with its shown characters. */
const PREVIEW = /(?:(\S{0,4})…(\S{0,4}) )?<redacted, (\d+) chars>/gu;

describe('previewSecret', () => {
  it.each([
    ['', '<redacted, 0 chars>'],
    ['a', '<redacted, 1 chars>'],
    ['abcdefghijklmno', '<redacted, 15 chars>'],
    ['abcdefghijklwxyz', 'abcd…wxyz <redacted, 16 chars>'],
    ['abcdefghijklmwxyz', 'abcd…wxyz <redacted, 17 chars>'],
  ])('%j → %j', (form, preview) => {
    expect(previewSecret(form)).toBe(preview);
  });

  it('a long JWT: its first and last four characters, its length', () => {
    const jwt = `eyJhbGciOiJSUzI1NiJ9.${'eyJzdWIiOiJ1c2VyIn0'.repeat(4)}.c2lnbmF0dXJl`;
    expect(previewSecret(jwt)).toBe(
      `eyJh…dXJl <redacted, ${jwt.length} chars>`,
    );
  });

  it('astral characters at the edges are whole characters, counted once each', () => {
    const form = `😀bcd${'x'.repeat(10)}wxy😀`;
    expect([...form]).toHaveLength(18);
    expect(previewSecret(form)).toBe('😀bcd…wxy😀 <redacted, 18 chars>');
    // No lone surrogate: the preview is well-formed text.
    expect(previewSecret(form)).not.toMatch(
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/,
    );
  });

  it('a form of 15 astral characters is the length only', () => {
    expect(previewSecret('😀'.repeat(15))).toBe('<redacted, 15 chars>');
  });
});

/** The description as the redactor leaves it. */
function described(text: string, secrets: readonly string[]): string {
  return oauthErrorFields({ error_description: text }, secrets)
    ?.error_description as string;
}

describe('the redactor writes previews', () => {
  const SECRET = 'S3cr3t-value-0123456789-ABCDEF';

  it('a secret as sent: its own preview, the server text kept', () => {
    expect(described(`bad secret ${SECRET} here`, [SECRET])).toBe(
      `bad secret ${previewSecret(SECRET)} here`,
    );
  });

  it('a secret echoed percent-escaped is previewed from the form it was recognised as', () => {
    const escaped = [...SECRET]
      .map((c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
      .join('');
    const out = described(`bad ${escaped} here`, [SECRET]);
    expect(out).toBe(`bad ${previewSecret(SECRET)} here`);
    expect(out).not.toContain('%');
  });

  it('a 15-character form shows its length only; a 16-character one its 4 + 4', () => {
    const fifteen = 'abcdefghijklmno';
    const sixteen = 'abcdefghijklwxyz';
    expect(described(`a ${fifteen} b`, [fifteen])).toBe(
      'a <redacted, 15 chars> b',
    );
    expect(described(`a ${sixteen} b`, [sixteen])).toBe(
      'a abcd…wxyz <redacted, 16 chars> b',
    );
  });

  it('two forms of one secret are previewed separately, each from its own characters', () => {
    const secret = 'se+cr%25et/x-long-enough-secret';
    const decoded = 'se cr%et/x-long-enough-secret';
    const out = described(`sent ${secret} read ${decoded}`, [secret]);
    expect(out).toBe(
      `sent ${previewSecret(secret)} read ${previewSecret(decoded)}`,
    );
    expect(previewSecret(secret)).not.toBe(previewSecret(decoded));
  });

  it('a JWT the server put in its text is previewed', () => {
    const jwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.signature-part';
    expect(described(`token ${jwt} refused`, [])).toBe(
      `token ${previewSecret(jwt)} refused`,
    );
  });

  it('a JWT beside a secret is still one JWT: the base64 pass leaves no fragments for the JWT pass', () => {
    const jwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.signature-part';
    expect(described(`x ${SECRET} token ${jwt} refused`, [SECRET])).toBe(
      `x ${previewSecret(SECRET)} token ${previewSecret(jwt)} refused`,
    );
  });

  it('the registered error is kept verbatim', () => {
    expect(
      oauthErrorFields({ error: 'invalid_grant' }, ['invalid_grant'])?.error,
    ).toBe('invalid_grant');
  });

  it('a preview is never rescanned: a short secret inside the marker words stays', () => {
    // `ed` and `chars` are in every marker.
    const out = described(`x ${SECRET} y ed`, [SECRET, 'ed', 'chars']);
    expect(out).toBe(`x ${previewSecret(SECRET)} y ${previewSecret('ed')}`);
  });
});

/**
 * Review fix 1: an echo escaped again at any depth is still the secret, and
 * anything no pattern foresees fails closed — the piece of server text that
 * decodes to hold a known secret becomes its length alone.
 */
describe('escaped at any depth', () => {
  const SECRET = 'se+cr%25et/x-0123456789-depth';
  const deeper = (value: string, times: number): string => {
    let out = value;
    for (let i = 0; i < times; i++) out = encodeURIComponent(out);
    return out;
  };

  it.each([1, 2, 3, 5])(
    'escaped %i time(s): one preview of the secret',
    (times) => {
      const echoed = deeper(SECRET, times);
      expect(described(`a ${echoed} b`, [SECRET])).toBe(
        `a ${previewSecret(SECRET)} b`,
      );
    },
  );

  it('an escaping no pattern foresees (`%%32B` for `+`) fails closed: the piece by its length only', () => {
    const odd = `x=${SECRET.replace('+', '%%32B')}`;
    expect(described(`a ${odd} b`, [SECRET])).toBe(
      `<redacted, ${[...`a ${odd} b`].length} chars>`,
    );
  });

  it('a UTF-8 secret escaped oddly fails closed too', () => {
    const secret = 'пароль-секрет+0123456789';
    const odd = encodeURIComponent(secret).replace('%2B', '%%32B');
    expect(described(`a ${odd} b`, [secret])).toMatch(
      /^<redacted, \d+ chars>$/,
    );
  });

  it('text that decodes to no secret is kept', () => {
    expect(described('a %%32B plain b', [SECRET])).toBe('a %%32B plain b');
  });
});

/**
 * Recognition first (spec §6): a Basic credential echoed wrapped — by CRLF,
 * LF, a tab or spaces, as themselves or escaped — is one span, previewed
 * from the credential it was recognised as; no run of the credential longer
 * than 4 characters is left anywhere.
 */
describe('a whitespace-wrapped Basic credential is one preview', () => {
  const ID = 'client:with:colons';
  const SECRET =
    'se+cr%25et/x-0123456789-wrapped-secret-that-is-long-enough-to-wrap';
  const CREDENTIAL = Buffer.from(`${ID}:${SECRET}`).toString('base64');
  const SECRETS = [CREDENTIAL, `${SECRET}`];

  const wrap = (text: string, width: number, breaker: string): string =>
    (text.match(new RegExp(`.{1,${width}}`, 'g')) ?? []).join(breaker);

  /** The line as a reader decoding escapes and dropping whitespace sees it. */
  const flattened = (text: string): string =>
    decodeURIComponent(text.replace(/%(?![0-9A-Fa-f]{2})/g, '%25')).replace(
      /\s+/g,
      '',
    );

  const longestRunOf = (text: string, of: string): number => {
    let best = 0;
    for (let i = 0; i < of.length; i++) {
      for (let j = i + best + 1; j <= of.length; j++) {
        if (text.includes(of.slice(i, j))) best = j - i;
        else break;
      }
    }
    return best;
  };

  it.each([
    ['unpadded', (c: string) => c.replace(/=+$/, '')],
    [
      'URL-safe, unpadded',
      (c: string) =>
        c.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'),
    ],
  ])(
    '%s and wrapped inside a sentence: the whole credential is one preview, no piece of it left',
    (_name, variant) => {
      // Not the form as sent: the first pass does not know it; the base64 pass
      // recognises it by its canonical form.
      expect(CREDENTIAL.endsWith('=')).toBe(true);
      for (const width of [8, 76]) {
        const echoed = wrap(variant(CREDENTIAL), width, '\r\n');
        const out = described(`header was Basic ${echoed} end`, SECRETS);
        expect(out).toBe(`header was Basic ${previewSecret(CREDENTIAL)} end`);
        expect(longestRunOf(flattened(out), CREDENTIAL)).toBeLessThanOrEqual(4);
      }
    },
  );

  describe.each([
    ['CRLF', '\r\n'],
    ['LF', '\n'],
    ['a tab', '\t'],
    ['spaces', ' '],
    ['%0D%0A', '%0D%0A'],
    ['%0A', '%0A'],
    ['%09', '%09'],
    ['%20', '%20'],
  ])('wrapped with %s', (_name, breaker) => {
    it.each([76, 4])('at width %i', (width) => {
      const echoed = `Basic ${wrap(CREDENTIAL, width, breaker)}`;
      const out = described(`header was ${echoed} end`, SECRETS);
      expect(out).toBe(`header was Basic ${previewSecret(CREDENTIAL)} end`);
      const flat = flattened(out);
      expect(longestRunOf(flat, CREDENTIAL)).toBeLessThanOrEqual(4);
      expect(longestRunOf(flat, SECRET)).toBeLessThanOrEqual(4);
      for (const match of out.matchAll(PREVIEW)) {
        expect(Number(match[3])).toBe(CREDENTIAL.length);
      }
    });
  });
});

/**
 * Review fix round 2, finding 1: a secret that is not base64 — a client
 * secret, a JWT, a password, an assertion — wrapped by the server (CR, LF,
 * a space, a tab, raw or escaped, an escape split by the wrap) is caught by
 * the fail-closed net: the piece holding it becomes its length only.
 */
describe('a non-base64 secret wrapped by the server', () => {
  const CLIENT_SECRET = 'se+cr%25et/x-0123456789-client';
  const JWT = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlLXg';
  const PASSWORD = 'pw+7%/Qz-pass';
  const ASSERTION = 'PHNhbWw+QXNzZXJ0aW9uPg==/assertion+payload';
  const BASIC = Buffer.from(`client:id:${CLIENT_SECRET}`).toString('base64');
  const SECRETS = [CLIENT_SECRET, JWT, PASSWORD, ASSERTION, BASIC];

  const wrap = (text: string, width: number, breaker: string): string =>
    (text.match(new RegExp(`.{1,${width}}`, 'g')) ?? []).join(breaker);

  const unescaped = (text: string): string => {
    let out = text;
    for (let i = 0; i < 8; i++) {
      out = out.replace(/%([0-9A-Fa-f]{2})/g, (_e, hex: string) =>
        String.fromCharCode(Number.parseInt(hex, 16)),
      );
    }
    return out;
  };
  const longestRunOf = (text: string, of: string): number => {
    let best = 0;
    for (let i = 0; i + best < of.length; i++) {
      while (i + best < of.length && text.includes(of.slice(i, i + best + 1)))
        best++;
    }
    return best;
  };

  const ECHOES: [string, (secret: string) => string][] = [
    ['as sent', (s) => s],
    ['escaped once', (s) => encodeURIComponent(s)],
    ['escaped twice', (s) => encodeURIComponent(encodeURIComponent(s))],
  ];

  describe.each([
    ['the client secret', CLIENT_SECRET],
    ['a JWT', JWT],
    ['a password', PASSWORD],
    ['an assertion', ASSERTION],
    ['a Basic credential', BASIC],
  ])('%s', (_name, secret) => {
    it.each(
      ECHOES.flatMap(([how, echo]) =>
        [3, 5, 8, 76].flatMap((width) =>
          ['\r\n', '\n', ' ', '\t', '%0D%0A', '%20'].map(
            (breaker) =>
              [
                `${how}, width ${width}, ${JSON.stringify(breaker)}`,
                echo,
                width,
                breaker,
              ] as const,
          ),
        ),
      ),
    )('%s: nothing of it is left', (_label, echo, width, breaker) => {
      const echoed = wrap(echo(secret), width, breaker);
      const out = described(`server said ${echoed} end`, SECRETS);
      const flat = unescaped(out).replace(/\s+/g, '');
      expect(longestRunOf(flat, secret)).toBeLessThanOrEqual(4);
    });
  });

  it('the examples of the review: an escape split by the wrap', () => {
    for (const [echoed, secret] of [
      ['se%2Bcr\r\n%2525et\r\n/x-0123456789-client', CLIENT_SECRET],
      [`${JWT.slice(0, 7)}\r\n${JWT.slice(7)}`, JWT],
      ['pw%2B7%\r\n2FQz-pass', 'pw+7/Qz-pass'],
    ] as const) {
      const out = described(`a ${echoed} b`, [...SECRETS, 'pw+7/Qz-pass']);
      expect(out).toMatch(/^<redacted, \d+ chars>$/);
      expect(longestRunOf(unescaped(out), secret)).toBeLessThanOrEqual(4);
    }
  });
});

/**
 * Review fix round 2, finding 2: decoding an escape at any depth is one
 * step per escape — a 1 MB adversarial `%2525…2541` chain redacts quickly.
 * A measured bound in the test, no timer in the code; nothing is cut before
 * redaction.
 */
describe('decoding cost', () => {
  it.each([
    ['one chain', `%${'25'.repeat(500_000)}41`],
    ['many chains', `%${'25'.repeat(1_000)}41 `.repeat(500)],
    ['nested escapes of escapes', '%%32B'.repeat(200_000)],
    ['nested escapes broken by spaces', '%%32B '.repeat(170_000)],
  ])('%s of about 1 MB redacts in well under 2 s', (_name, text) => {
    const started = performance.now();
    oauthErrorFields({ error_description: text }, [
      'se+cr%25et/x-0123456789-client',
    ]);
    expect(performance.now() - started).toBeLessThan(2_000);
  });
});
