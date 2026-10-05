/**
 * A server may echo a secret in any representation equivalent to the one
 * sent: base64 without its padding, with other padding, in the URL-safe
 * alphabet; percent escapes in lower or mixed case; a space as `+` or `%20`.
 * Against a real socket, through every token site, without a strategy and with
 * each secret strategy, no surface may hold anything from which a secret is
 * recovered.
 *
 * The oracle (`recoverable`) is written independently of the redaction: it
 * decodes every substring of every surface — percent-decoding, form-decoding
 * and base64 from every start offset in both alphabets — and looks for each
 * secret the request carried.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { inspect } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import type { IClientAuthentication } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { exchangeCodeForToken } from '../../auth/browserAuth';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import {
  exchangeAuthorizationCode,
  initiateDeviceAuthorization,
  passwordGrant,
  pollDeviceTokens,
  refreshOidcToken,
  tokenExchange,
} from '../../auth/oidcToken';
import { exchangePasscode } from '../../auth/passcodeAuth';
import {
  exchangeSamlAssertion,
  refreshSamlBearerToken,
} from '../../auth/saml2TokenExchange';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import type { TokenRequestAuth } from '../../auth/tokenRequest';
import {
  clientSecretBasic,
  clientSecretPost,
} from '../../clientAuthentication';

// ---------------------------------------------------------------- the oracle

/** Percent-decoding, any case, byte by byte; `plus` also reads `+` as a space. */
function percentDecoded(text: string, plus: boolean): string {
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    const hex = text.slice(i + 1, i + 3);
    if (ch === '%' && /^[0-9a-fA-F]{2}$/.test(hex)) {
      bytes.push(Number.parseInt(hex, 16));
      i += 2;
    } else if (plus && ch === '+') {
      bytes.push(0x20);
    } else {
      bytes.push(...Buffer.from(ch, 'utf8'));
    }
  }
  return Buffer.from(bytes).toString('latin1');
}

const BASE64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** A base64 decoder of its own: either alphabet, padding ignored, from char 0. */
function base64Decoded(text: string): string {
  let bits = 0;
  let count = 0;
  let out = '';
  for (const raw of text) {
    const ch = raw === '-' ? '+' : raw === '_' ? '/' : raw === ' ' ? '+' : raw;
    const value = BASE64_ALPHABET.indexOf(ch);
    if (value < 0) break;
    bits = (bits << 6) | value;
    count += 6;
    if (count >= 8) {
      count -= 8;
      out += String.fromCharCode((bits >> count) & 0xff);
    }
  }
  return out;
}

/** Every reading of a text a recipient could make. */
function readings(text: string): string[] {
  const decoded = [
    text,
    percentDecoded(text, false),
    percentDecoded(text, true),
  ];
  const out = [...decoded];
  for (const candidate of decoded) {
    for (const run of candidate.match(/[A-Za-z0-9+/_\- =]{2,}/g) ?? []) {
      const bare = run.replace(/=/g, '');
      for (let start = 0; start < bare.length; start++) {
        const d = base64Decoded(bare.slice(start));
        out.push(d, percentDecoded(d, false), percentDecoded(d, true));
      }
    }
  }
  return out;
}

/** The secrets that can be read back from the text. */
function recovered(text: string, secrets: readonly string[]): string[] {
  const all = readings(text);
  return secrets.filter((secret) => {
    const target = Buffer.from(secret, 'utf8').toString('latin1');
    return all.some((reading) => reading.includes(target));
  });
}
const recoverable = (text: string, secret: string): boolean =>
  recovered(text, [secret]).length > 0;

describe('the oracle', () => {
  it('reads back what the redaction must remove (it is not blind)', () => {
    const b64 = Buffer.from('id:se cr/t?').toString('base64');
    expect(recoverable(`x ${b64.replace(/=+$/, '')} y`, 'se cr/t?')).toBe(true);
    expect(recoverable(`x${b64.replace(/\+/g, '-')}`, 'se cr/t?')).toBe(true);
    expect(recoverable('a se%20cr%2ft%3F b', 'se cr/t?')).toBe(true);
    expect(recoverable('se+cr%2Ft%3f', 'se cr/t?')).toBe(true);
    expect(recoverable('nothing <redacted> here', 'se cr/t?')).toBe(false);
  });
});

// ---------------------------------------------------------------- the server

/** Percent-encodes every byte outside the unreserved set, in a given case. */
function percent(value: string, upper: (i: number) => boolean): string {
  let i = 0;
  return [...Buffer.from(value, 'utf8')]
    .map((byte) => {
      const ch = String.fromCharCode(byte);
      if (/[A-Za-z0-9\-._~]/.test(ch)) return ch;
      const hex = byte.toString(16).padStart(2, '0');
      return `%${upper(i++) ? hex.toUpperCase() : hex.toLowerCase()}`;
    })
    .join('');
}
const lower = () => false;
const mixed = (i: number) => i % 2 === 1;

/** Every equivalent representation the server echoes of one value. */
function variants(value: string): string[] {
  return [
    percent(value, lower),
    percent(value, mixed),
    percent(value, lower).replace(/%20/g, '+'),
    value.replace(/ /g, '%20'),
  ];
}

/** And of a base64 credential. */
function base64Variants(credential: string): string[] {
  const bare = credential.replace(/=+$/, '');
  return [
    bare,
    `${bare}=`,
    `${bare}==`,
    bare.replace(/\+/g, '-').replace(/\//g, '_'),
    percent(credential, lower),
    percent(credential, mixed),
    bare.replace(/\+/g, ' '),
    Buffer.from(credential, 'base64').toString('utf8'),
  ];
}

const SECRET_PARAMETERS = [
  'client_secret',
  'refresh_token',
  'code',
  'code_verifier',
  'password',
  'passcode',
  'assertion',
  'device_code',
  'subject_token',
];

let status = 400;
const echoing = createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on('data', (chunk: Buffer) => chunks.push(chunk));
  req.on('end', () => {
    const body = new URLSearchParams(Buffer.concat(chunks).toString());
    const echoes: string[] = [];
    const basic = /^Basic\s+(\S+)$/i.exec(req.headers.authorization ?? '')?.[1];
    if (basic) echoes.push(...base64Variants(basic));
    for (const name of SECRET_PARAMETERS) {
      for (const value of body.getAll(name)) {
        echoes.push(
          ...variants(value),
          Buffer.from(value).toString('base64').replace(/=+$/, ''),
          Buffer.from(value).toString('base64url'),
        );
      }
    }
    const echo = echoes.join(' | ');
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        ...(status === 200 ? {} : { error: 'invalid_client' }),
        error_description: `refused: ${echo}`,
        error_uri: `https://idp.example/err?echo=${echo}`,
      }),
    );
  });
});
let base = '';
beforeAll(async () => {
  base = `http://127.0.0.1:${await new Promise<number>((resolve) => {
    echoing.listen(0, '127.0.0.1', () =>
      resolve((echoing.address() as AddressInfo).port),
    );
  })}`;
});
afterAll(
  () =>
    new Promise<void>((resolve) => (echoing as Server).close(() => resolve())),
);

// ---------------------------------------------------------------- the sites

const GRANT = {
  refresh: 'refresh/Tok+en 01=x',
  code: 'auth-code/9+x y?z',
  verifier: 'verifier/+value 22~',
  password: 'pass word/+1?q',
  passcode: 'Pass/code+7 x&y',
  assertion: 'ASSERTION/+value 1=',
  device: 'device/+code 1#',
  subject: 'subject/+token 1;',
};

interface Credential {
  readonly id: string;
  readonly secret: string;
}
const CREDENTIALS: Credential[] = [
  { id: 'client', secret: 's3cr3t>?~valueX' }, // base64 ends '=='
  { id: 'my:client', secret: 'se+cr%25et/x' }, // ':' in the id
  { id: 'cid', secret: 'pa ss/wd?ok!!' }, // base64 ends '='
  { id: 'cid', secret: 'pa ss/wd?ok' }, // base64 unpadded
];

type Path = {
  readonly label: string;
  readonly auth: (c: Credential) => IClientAuthentication | undefined;
};
const PATHS: Path[] = [
  { label: 'without a strategy', auth: () => undefined },
  {
    label: "clientSecretBasic 'raw'",
    auth: (c) => clientSecretBasic(c.secret, { encoding: 'raw' }),
  },
  {
    label: "clientSecretBasic 'form'",
    auth: (c) => clientSecretBasic(c.secret, { encoding: 'form' }),
  },
  { label: 'clientSecretPost', auth: (c) => clientSecretPost(c.secret) },
];

type Run = (
  c: Credential,
  auth: TokenRequestAuth | undefined,
  logger: ILogger,
) => Promise<unknown>;

/** The configured secret: only without a strategy (beside one it is refused). */
const own = (c: Credential, auth: TokenRequestAuth | undefined) =>
  auth ? undefined : c.secret;

const SITES: [string, Run][] = [
  [
    'UAA authorization code',
    (c, auth, logger) =>
      exchangeCodeForToken(
        {
          uaaUrl: base,
          uaaClientId: c.id,
          uaaClientSecret: own(c, auth),
        } as Parameters<typeof exchangeCodeForToken>[0],
        GRANT.code,
        'http://localhost:61001/callback',
        logger,
        auth,
      ),
  ],
  [
    'UAA refresh',
    (c, auth) => refreshJwtToken(GRANT.refresh, base, c.id, own(c, auth), auth),
  ],
  [
    'UAA passcode',
    (c, auth, logger) =>
      exchangePasscode(base, c.id, own(c, auth), GRANT.passcode, logger, auth),
  ],
  [
    'client credentials',
    (c, auth) => getTokenWithClientCredentials(base, c.id, own(c, auth), auth),
  ],
  [
    'SAML bearer exchange',
    (c, auth, logger) =>
      exchangeSamlAssertion(
        GRANT.assertion,
        `${base}/token`,
        c.id,
        own(c, auth),
        logger,
        auth,
      ),
  ],
  [
    'SAML bearer refresh',
    (c, auth, logger) =>
      refreshSamlBearerToken(
        GRANT.refresh,
        `${base}/token`,
        c.id,
        own(c, auth),
        logger,
        auth,
      ),
  ],
  [
    'OIDC authorization code',
    (c, auth, logger) =>
      exchangeAuthorizationCode(
        `${base}/token`,
        c.id,
        own(c, auth),
        GRANT.code,
        'http://localhost:61001/callback',
        GRANT.verifier,
        logger,
        auth,
      ),
  ],
  [
    'OIDC refresh',
    (c, auth, logger) =>
      refreshOidcToken(
        `${base}/token`,
        c.id,
        own(c, auth),
        GRANT.refresh,
        logger,
        auth,
      ),
  ],
  [
    'OIDC token exchange',
    (c, auth, logger) =>
      tokenExchange(
        `${base}/token`,
        c.id,
        own(c, auth),
        GRANT.subject,
        'urn:ietf:params:oauth:token-type:access_token',
        undefined,
        undefined,
        undefined,
        undefined,
        logger,
        auth,
      ),
  ],
  [
    'OIDC device initiation',
    (c, auth, logger) =>
      initiateDeviceAuthorization(
        `${base}/device`,
        c.id,
        'openid',
        logger,
        auth,
      ),
  ],
  [
    'OIDC device poll',
    (c, auth, logger) =>
      pollDeviceTokens(
        `${base}/token`,
        c.id,
        own(c, auth),
        GRANT.device,
        0,
        logger,
        auth,
      ),
  ],
  [
    'OIDC password grant',
    (c, auth, logger) =>
      passwordGrant(
        `${base}/token`,
        c.id,
        own(c, auth),
        'user',
        GRANT.password,
        undefined,
        logger,
        auth,
      ),
  ],
];

function recordingLogger(): { logger: ILogger; text: () => string } {
  const lines: string[] = [];
  const record =
    (level: string) =>
    (...args: unknown[]) => {
      lines.push(
        `${level} ${args.map((a) => (typeof a === 'string' ? a : inspect(a, { depth: null }))).join(' ')}`,
      );
    };
  return {
    logger: {
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
      debug: record('debug'),
    } as ILogger,
    text: () => lines.join('\n'),
  };
}

function surfaces(error: unknown, logs: string): Record<string, string> {
  const e = error as {
    message?: unknown;
    response?: { data?: unknown };
    cause?: unknown;
  };
  return {
    message: String(e?.message),
    String: String(error),
    inspect: inspect(error, { depth: null }),
    JSON: JSON.stringify(error) ?? '',
    'response.data': JSON.stringify(e?.response?.data) ?? '',
    cause: inspect(e?.cause, { depth: null }),
    logs,
  };
}

const CASES = PATHS.flatMap((path) =>
  CREDENTIALS.flatMap((c) =>
    // Raw Basic cannot carry an id with ':' — refused before anything is sent.
    path.label.includes("'raw'") && c.id.includes(':')
      ? []
      : SITES.map(
          ([site, run]) =>
            [
              `${site}, ${path.label}, id ${c.id} / ${c.secret}`,
              run,
              path,
              c,
            ] as const,
        ),
  ),
);

describe.each([400, 500, 200])(
  'a %i echoing every secret in equivalent forms',
  (code) => {
    it.each(CASES)('%s: nothing recoverable', async (_label, run, path, c) => {
      status = code;
      const strategy = path.auth(c);
      const auth = strategy ? { strategy } : undefined;
      const { logger, text } = recordingLogger();
      let thrown: unknown;
      const failed = expect(
        run(c, auth, logger).catch((error: unknown) => {
          thrown = error;
          throw error;
        }),
      ).rejects.toBeDefined();
      await failed;
      const secrets = [c.secret, ...Object.values(GRANT)];
      for (const [where, rendered] of Object.entries(
        surfaces(thrown, text()),
      )) {
        const found = recovered(rendered, secrets);
        expect({ where, found }).toEqual({ where, found: [] });
      }
    });
  },
);
