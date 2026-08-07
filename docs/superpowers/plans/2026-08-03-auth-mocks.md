# Auth Mocks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `@mcp-abap-adt/auth-mocks` — protocol-faithful mock authorization servers (UAA/OAuth2, OIDC, SAML IdP) so the authorization flows of this package family can be tested deterministically, without a live system, a profile, or a human.

**Architecture:** Three mocks over one shared `node:http` server core that binds an ephemeral port and journals every request. A fake browser (`visit`) follows redirects and submits SAML's auto-submitting form, wired into the provider through the `openUrl` seam that already exists. Mocks are strict by default: they refuse what a real server would refuse, so a failure surfaces as the server's answer rather than as our own assertion.

**Tech Stack:** TypeScript, Node ≥18, `node:http`, Jest with ts-jest, Biome. `xml-crypto` for XML-DSig, `@xmldom/xmldom` for the DOM, `node-forge` for certificate generation, `@node-saml/node-saml` as an independent verifier in tests only.

**Spec:** `docs/superpowers/specs/2026-08-02-auth-mocks-design.md` in `mcp-abap-adt-auth-providers`. Read it before Task 1 — every design decision below is justified there.

**Status:** approved after three review rounds, not implemented.

## Global Constraints

- **The package imports nothing from `@mcp-abap-adt/*`.** It speaks HTTP, OAuth2 and SAML. A mock that knows our types will eventually agree with our mistakes instead of catching them. This is checked by a test, not by discipline.
- **Strict by default.** Every rule below is a refusal the mock performs, and every refusal gets its own test. A mock that is wrong leniently produces a green suite and false confidence — worse than having none.
- **The mock's own tests are written from the protocol**, never from how our providers happen to behave.
- **Every credential a mock issues is bound to the client it was issued to**, and the binding is checked when the credential is redeemed. Authenticating the caller answers "do I know you"; it does not answer "is this yours". Both mocks that issue codes and refresh tokens enforce this, and each has its own refusal test.
- Access tokens are syntactically valid JWTs — three dot-separated parts, base64url payload with `exp` and `iat`. `BaseTokenProvider.parseExpirationFromJWT` requires exactly that and yields `undefined` otherwise. The signature segment is not verified by anything in this family and need not be cryptographically meaningful.
- OAuth errors follow RFC 6749 §5.2: HTTP 400 with JSON `{error, error_description}`; `invalid_client` is **401 with a matching `WWW-Authenticate` header when the client authenticated through the `Authorization` header, 400 otherwise**.
- Node ≥18.2.0, `"type"` unset (CommonJS), `main: dist/index.js`, `types: dist/index.d.ts` — matching the sibling packages.
- `npm run lint:check`, `npm run build` and `npm test` must pass before every commit.
- The agent never runs `npm publish`, never merges a PR, and never creates a tag before a merge exists.
- Repo: `/home/okyslytsia/prj/mcp-abap-adt-auth-mocks`, work on branch `feat/initial-implementation` inside a worktree at `.worktrees/initial`.

## A limitation to record before starting

The spec asks that a signed assertion be verified "against an external tool, not against a verifier we also wrote". That is only partly achievable here. `xmlsec1` is not installed on this machine, and `openssl` cannot verify XML-DSig. The verifier this plan uses, `@node-saml/node-saml`, is not ours and independently implements much of SAML profile validation — signature presence and validity, `Conditions` timestamps, `Audience`, `Issuer`, `InResponseTo` — but it shares `xml-crypto` underneath for the cryptography itself.

Two further gaps, both established by reading the library rather than by guessing:

- It validates neither `Destination` nor `SubjectConfirmationData@Recipient`. Those two corruption variants therefore get no independent judgement; Task 10 asserts them structurally and says so.
- It has no assertion-ID replay cache, because replay detection belongs to the relying party. Task 10 verifies the property that makes replay dangerous — the replayed assertion is individually valid — rather than pretending an off-the-shelf verifier catches it.

So: most of profile validation is independently checked; the canonicalisation and signature maths are not, and two fields plus replay are ours to check. Whether our C14N matches a real identity provider stays a question only live testing answers. Task 8 states all of this in the package README so nobody later mistakes the test suite for proof.

## File Structure

```
mcp-abap-adt-auth-mocks/
├── package.json, tsconfig.json, jest.config.js, biome.json
├── README.md, CHANGELOG.md, LICENSE
└── src/
    ├── index.ts        # the only public surface
    ├── server.ts       # ephemeral bind, graceful close, request journal
    ├── jwt.ts          # mint a syntactically valid JWT with given iat/exp
    ├── oauthErrors.ts  # RFC 6749 §5.2 error responses, incl. the 401/400 rule
    ├── clientAuth.ts   # client_secret_basic / client_secret_post / public
    ├── clients.ts      # the client registry and the two binding refusals
    ├── uaa.ts          # /oauth/authorize, /oauth/token (code, refresh, bearer)
    ├── oidc.ts         # discovery, /authorize (PKCE demanded), /token
    ├── signing.ts      # per-instance self-signed cert, XML-DSig
    ├── saml.ts         # AuthnRequest → auto-submitting form; corruption variants
    └── browser.ts      # visit(url) — follows redirects, submits forms
```

`jwt.ts`, `oauthErrors.ts`, `clientAuth.ts` and `clients.ts` are separate because both `uaa.ts` and `oidc.ts` need them identically, and because each is a rule from the spec that deserves its own tests rather than being buried in a route handler.

`clients.ts` in particular exists so the client-binding rule has exactly one implementation. An earlier draft told the OIDC mock to copy the registry and both refusals out of `uaa.ts`; the owner ruled against it. Two copies of a security check drift, and the check that "cannot be optional" is precisely the one that must not exist twice.

---

### Task 1: Repository and skeleton

**Files:**
- Create: `package.json`, `tsconfig.json`, `jest.config.js`, `biome.json`, `.gitignore`, `README.md`, `CHANGELOG.md`, `LICENSE`
- Test: `src/__tests__/skeleton.test.ts`

**Interfaces:**
- Produces: a repository where `npm run lint:check && npm run build && npm test` all pass.

- [ ] **Step 1: Create the repository**

The owner has approved a separate repository: this is purely a developer tool
and does not belong inside a package it exists to test.

```bash
cd /home/okyslytsia/prj
gh repo create fr0ster/mcp-abap-adt-auth-mocks --private --clone \
  --description "Mock authorization servers (UAA/OAuth2, OIDC, SAML IdP) for testing @mcp-abap-adt packages"
```

If the repository already exists, clone it instead and skip creation.

- [ ] **Step 2: Create the worktree**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-auth-mocks
printf '\n# Git worktrees\n.worktrees/\n\n# Build output\ndist/\nnode_modules/\n' >> .gitignore
git add .gitignore && git commit -m "chore: ignore worktrees, dist and node_modules"
git worktree add .worktrees/initial -b feat/initial-implementation
```

All later work happens in `.worktrees/initial`.

- [ ] **Step 3: Write `package.json`**

```json
{
  "name": "@mcp-abap-adt/auth-mocks",
  "version": "0.1.0",
  "description": "Protocol-faithful mock authorization servers (UAA/OAuth2, OIDC, SAML IdP) for testing @mcp-abap-adt packages",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": ["dist", "README.md", "CHANGELOG.md", "LICENSE"],
  "engines": { "node": ">=18.2.0" },
  "scripts": {
    "clean": "rm -rf dist tsconfig.tsbuildinfo",
    "lint": "npx biome check --write src",
    "lint:check": "npx biome check src",
    "build": "npm run --silent clean && npx biome check src --diagnostic-level=error && npx tsc -p tsconfig.json",
    "build:fast": "npx tsc -p tsconfig.json",
    "test:check": "npx tsc --noEmit",
    "test": "jest"
  },
  "dependencies": {
    "@xmldom/xmldom": "^0.9.10",
    "node-forge": "^1.4.0",
    "xml-crypto": "^6.1.2"
  },
  "devDependencies": {
    "@biomejs/biome": "^2.3.14",
    "@jest/globals": "^30.2.0",
    "@node-saml/node-saml": "^5.1.0",
    "@types/jest": "^30.0.0",
    "@types/node": "^25.2.3",
    "@types/node-forge": "^1.3.11",
    "jest": "^30.2.0",
    "ts-jest": "^29.2.5",
    "typescript": "^5.9.2"
  },
  "publishConfig": { "access": "public" },
  "license": "MIT"
}
```

Note `xml-crypto`, `@xmldom/xmldom` and `node-forge` are **dependencies**, not dev: consumers run this code in their tests. `@node-saml/node-saml` is a devDependency — it verifies our output in *our* tests and must not become a consumer's problem.

- [ ] **Step 4: Write `tsconfig.json`, `jest.config.js`, `biome.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "declaration": true,
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "src/__tests__"]
}
```

```js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: { esModuleInterop: true } }],
  },
  maxWorkers: 1,
  testTimeout: 15000,
};
```

Copy `biome.json` from `/home/okyslytsia/prj/mcp-abap-adt-auth-providers/biome.json` unchanged, so formatting matches the family.

- [ ] **Step 5: Write the failing test**

`src/__tests__/skeleton.test.ts`:

```ts
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import * as mocks from '../index';

/** Every .ts file under src, so the constraint is checked against the code. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(full);
    return entry.name.endsWith('.ts') ? [full] : [];
  });
}

describe('package skeleton', () => {
  it('exports something', () => {
    expect(Object.keys(mocks).length).toBeGreaterThan(0);
  });

  // The package must never depend on the packages it exists to test: a mock
  // that knows our types will eventually agree with our mistakes. Both groups
  // are checked, not just runtime — a devDependency would let a test import our
  // types just as effectively.
  it('declares no @mcp-abap-adt dependency, in either group', () => {
    const pkg = require('../../package.json');
    const declared = [
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
    ];
    expect(declared.filter((d) => d.startsWith('@mcp-abap-adt/'))).toEqual([]);
  });

  // package.json is the weaker half of the rule: a file can import a package
  // that was never declared, and the constraint breaks while the manifest stays
  // clean. So read the imports.
  it('imports nothing from @mcp-abap-adt in any source file', () => {
    const offenders = sourceFiles(join(__dirname, '..')).filter((file) =>
      /from\s+['"]@mcp-abap-adt\/|require\(\s*['"]@mcp-abap-adt\//.test(
        readFileSync(file, 'utf8'),
      ),
    );
    expect(offenders).toEqual([]);
  });
});
```

**Prove the import test is load-bearing before moving on.** Add
`import type { ILogger } from '@mcp-abap-adt/interfaces';` to `src/index.ts`,
run the suite, watch *that* test go red while the manifest test stays green,
then revert. A constraint test that cannot fail is decoration.

- [ ] **Step 6: Run it to verify it fails**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-auth-mocks/.worktrees/initial
npm install && npm test
```

Expected: FAIL — `Cannot find module '../index'`.

- [ ] **Step 7: Create `src/index.ts` with a placeholder export**

```ts
/**
 * Mock authorization servers for testing.
 *
 * Everything here starts and stops inside a test. Nothing in this package is
 * meant to run in production, and nothing in it imports the packages it exists
 * to test.
 */

/** Replaced as the mocks land; keeps the module non-empty until then. */
export const AUTH_MOCKS_VERSION = '0.1.0';
```

- [ ] **Step 8: Verify and commit**

```bash
npm run lint:check && npm run build && npm test
git add -A && git commit -m "chore: package skeleton"
```

Expected: all green, both tests pass.

---

### Task 2: The server core and its journal

**Files:**
- Create: `src/server.ts`
- Test: `src/__tests__/server.test.ts`

**Interfaces:**
- Produces:
  - `interface RecordedRequest { method: string; path: string; query: Record<string, string>; headers: Record<string, string>; body: Record<string, string>; raw: string }`
  - `interface MockHandle { url: string; port: number; requests: RecordedRequest[]; close(): Promise<void> }`
  - `startServer(routes: RouteTable): Promise<MockHandle>` where `type RouteTable = Record<string, (req: RecordedRequest, res: http.ServerResponse) => void>` keyed by `"GET /path"`.

The journal is not a convenience. Without it a test can only assert the outcome; with it the test asserts what the client *sent* — which is where every defect in the previous arc lived.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from '@jest/globals';
import { startServer } from '../server';

describe('server core', () => {
  it('binds an ephemeral port and reports its own url', async () => {
    const s = await startServer({ 'GET /ping': (_req, res) => res.end('pong') });
    try {
      expect(s.port).toBeGreaterThan(0);
      expect(s.url).toBe(`http://127.0.0.1:${s.port}`);
      const body = await (await fetch(`${s.url}/ping`)).text();
      expect(body).toBe('pong');
    } finally {
      await s.close();
    }
  });

  it('journals query, headers and form body of every request', async () => {
    const s = await startServer({ 'POST /echo': (_req, res) => res.end('ok') });
    try {
      await fetch(`${s.url}/echo?a=1`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=authorization_code&code=xyz',
      });
      expect(s.requests).toHaveLength(1);
      const r = s.requests[0];
      expect(r.method).toBe('POST');
      expect(r.path).toBe('/echo');
      expect(r.query.a).toBe('1');
      expect(r.body.grant_type).toBe('authorization_code');
      expect(r.body.code).toBe('xyz');
    } finally {
      await s.close();
    }
  });

  it('answers 404 for an unrouted path and still journals it', async () => {
    const s = await startServer({});
    try {
      const res = await fetch(`${s.url}/nope`);
      expect(res.status).toBe(404);
      expect(s.requests[0].path).toBe('/nope');
    } finally {
      await s.close();
    }
  });

  it('releases the port when closed', async () => {
    const s = await startServer({});
    const port = s.port;
    await s.close();
    // Binding the same port must now succeed.
    const again = await startServer({}, port);
    expect(again.port).toBe(port);
    await again.close();
  });

  // This package exists to be fed malformed protocol input, so a throw inside a
  // handler is expected traffic. Uncaught it becomes an unhandled rejection and
  // a client waiting for a response that never comes — a hanging test instead
  // of a failing one, which is the worst thing a harness can do.
  it('answers 500 when a route handler throws, rather than hanging', async () => {
    const s = await startServer({
      'GET /boom': () => {
        throw new Error('handler exploded');
      },
      'GET /boom-async': async () => {
        throw new Error('async handler exploded');
      },
    });
    try {
      const sync = await fetch(`${s.url}/boom`);
      expect(sync.status).toBe(500);
      expect((await sync.json()).error).toBe('mock_failure');

      // The async case is the one that slips through a bare `void (async …)()`.
      const asynchronous = await fetch(`${s.url}/boom-async`);
      expect(asynchronous.status).toBe(500);
    } finally {
      await s.close();
    }
  }, 10000);
});
```

**Prove this one is load-bearing, carefully.** Drop the `await` before
`handler(recorded, res)` and rerun: `/boom-async` must fail or time out while
`/boom` stays green. That asymmetry is the whole point — the synchronous case
passes under a broken implementation, so only the async case guards the rule.
Restore the `await` afterwards.

- [ ] **Step 2: Run it to verify it fails**

```bash
npm test -- src/__tests__/server.test.ts
```

Expected: FAIL — `Cannot find module '../server'`.

- [ ] **Step 3: Implement `src/server.ts`**

```ts
/**
 * The shared core every mock is built on.
 *
 * Binds an ephemeral port, records every request it receives, and releases the
 * socket when closed. Routes are keyed `"METHOD /path"`; anything unmatched is
 * a journalled 404, because a test that mistypes a path should see that rather
 * than a hang.
 */

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';

export interface RecordedRequest {
  method: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  /** Parsed form body; empty for requests without one. */
  body: Record<string, string>;
  /** The body exactly as it arrived, for assertions parsing would lose. */
  raw: string;
}

// `void`, not `void | Promise<void>`: TypeScript's return-type exemption — the
// one that lets `(_req, res) => res.end('pong')` satisfy a void-returning
// signature — applies only when the target is exactly `void`. Against the union
// that same handler fails with TS2322, because `ServerResponse` is assignable to
// neither member. Plain `void` still admits an async handler, and the `await`
// below still awaits it: the annotation is erased at runtime.
export type RouteHandler = (
  req: RecordedRequest,
  res: http.ServerResponse,
) => void;

export type RouteTable = Record<string, RouteHandler>;

export interface MockHandle {
  url: string;
  port: number;
  /** Every request this mock received, oldest first. */
  requests: RecordedRequest[];
  close(): Promise<void>;
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => {
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

export async function startServer(
  routes: RouteTable,
  port = 0,
): Promise<MockHandle> {
  const requests: RecordedRequest[] = [];
  const sockets = new Set<import('node:net').Socket>();

  const server = http.createServer((req, res) => {
    void (async () => {
      const raw = await readBody(req);
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const query: Record<string, string> = {};
      url.searchParams.forEach((v, k) => {
        query[k] = v;
      });
      const body: Record<string, string> = {};
      if (raw && /application\/x-www-form-urlencoded/.test(req.headers['content-type'] ?? '')) {
        new URLSearchParams(raw).forEach((v, k) => {
          body[k] = v;
        });
      }
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : (v ?? '');
      }

      const recorded: RecordedRequest = {
        method: req.method ?? 'GET',
        path: url.pathname,
        query,
        headers,
        body,
        raw,
      };
      requests.push(recorded);

      const handler = routes[`${recorded.method} ${recorded.path}`];
      if (!handler) {
        res.statusCode = 404;
        res.end('no such route');
        return;
      }
      // Awaited, not just called: an async handler's rejection is a separate
      // promise, and discarding it would slip straight past the catch below.
      // The declared return type says `void`; the await still works, because
      // it acts on the value returned at runtime, not on its annotation.
      await handler(recorded, res);
    })().catch((error: unknown) => {
      // This package exists to be fed malformed protocol input, so a throw
      // anywhere above is expected traffic, not an impossible state. Left
      // uncaught it becomes an unhandled rejection *and* a client that waits
      // for a response that will never come — a test that hangs instead of
      // failing, which is the worst outcome a test harness can produce.
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
      }
      if (!res.writableEnded) {
        res.end(JSON.stringify({ error: 'mock_failure', detail: String(error) }));
      }
    });
  });

  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  const bound = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${bound}`,
    port: bound,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/server.test.ts
```

Expected: PASS, five cases.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build
git add src/server.ts src/__tests__/server.test.ts
git commit -m "feat: server core with an ephemeral port and a request journal"
```

---

### Task 3: JWTs, OAuth errors and client authentication

**Files:**
- Create: `src/jwt.ts`, `src/oauthErrors.ts`, `src/clientAuth.ts`
- Test: `src/__tests__/jwt.test.ts`, `src/__tests__/oauthErrors.test.ts`, `src/__tests__/clientAuth.test.ts`

**Interfaces:**
- Produces:
  - `mintJwt(opts: { expiresInSeconds: number; claims?: Record<string, unknown> }): string`
  - `sendOAuthError(res, error: string, description: string, opts?: { usedAuthorizationHeader?: boolean }): void`
  - `readClientAuth(req: RecordedRequest): { clientId?: string; clientSecret?: string; usedAuthorizationHeader: boolean; conflict: boolean }`

These three are separate files because `uaa.ts` and `oidc.ts` need them identically, and each encodes a rule from the spec that deserves its own tests rather than being buried in a route.

- [ ] **Step 1: Write the failing tests**

`src/__tests__/jwt.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { mintJwt } from '../jwt';

describe('mintJwt', () => {
  // BaseTokenProvider.parseExpirationFromJWT splits on '.', requires exactly
  // three parts and reads `exp`. Anything else yields undefined expiry, and a
  // provider handed such a token has no basis to consider it fresh.
  it('produces three dot-separated parts', () => {
    expect(mintJwt({ expiresInSeconds: 60 }).split('.')).toHaveLength(3);
  });

  it('carries exp and iat the way a provider reads them', () => {
    const before = Math.floor(Date.now() / 1000);
    const token = mintJwt({ expiresInSeconds: 3600 });
    const claims = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
    );
    expect(claims.iat).toBeGreaterThanOrEqual(before);
    expect(claims.exp - claims.iat).toBe(3600);
  });

  it('can mint an already-expired token', () => {
    const token = mintJwt({ expiresInSeconds: -1 });
    const claims = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
    );
    expect(claims.exp).toBeLessThan(Math.floor(Date.now() / 1000));
  });

  it('merges extra claims', () => {
    const token = mintJwt({ expiresInSeconds: 60, claims: { sub: 'u1' } });
    const claims = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
    );
    expect(claims.sub).toBe('u1');
  });
});
```

`src/__tests__/clientAuth.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { readClientAuth } from '../clientAuth';
import type { RecordedRequest } from '../server';

const base: RecordedRequest = {
  method: 'POST', path: '/oauth/token', query: {}, headers: {}, body: {}, raw: '',
};

describe('readClientAuth', () => {
  // UAA sends credentials only as Basic and puts no client_id in the body;
  // OIDC puts client_id in the body. A mock assuming either shape would
  // reject one of the family's own clients.
  it('reads client_secret_basic', () => {
    const basic = Buffer.from('cid:secret').toString('base64');
    const r = readClientAuth({ ...base, headers: { authorization: `Basic ${basic}` } });
    expect(r).toMatchObject({ clientId: 'cid', clientSecret: 'secret', usedAuthorizationHeader: true, conflict: false });
  });

  it('reads client_secret_post', () => {
    const r = readClientAuth({ ...base, body: { client_id: 'cid', client_secret: 'secret' } });
    expect(r).toMatchObject({ clientId: 'cid', clientSecret: 'secret', usedAuthorizationHeader: false, conflict: false });
  });

  it('reads a public client — id in the body, no secret', () => {
    const r = readClientAuth({ ...base, body: { client_id: 'cid' } });
    expect(r).toMatchObject({ clientId: 'cid', clientSecret: undefined, conflict: false });
  });

  it('flags a conflict when Basic and body disagree', () => {
    const basic = Buffer.from('cid:secret').toString('base64');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${basic}` },
      body: { client_id: 'other' },
    });
    expect(r.conflict).toBe(true);
  });

  it('does not flag a conflict when Basic and body agree', () => {
    const basic = Buffer.from('cid:secret').toString('base64');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${basic}` },
      body: { client_id: 'cid' },
    });
    expect(r.conflict).toBe(false);
  });
});
```

`src/__tests__/oauthErrors.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { startServer } from '../server';
import { sendOAuthError } from '../oauthErrors';

describe('sendOAuthError', () => {
  it('answers 400 with an RFC 6749 body', async () => {
    const s = await startServer({
      'GET /e': (_r, res) => sendOAuthError(res, 'invalid_grant', 'bad code'),
    });
    try {
      const res = await fetch(`${s.url}/e`);
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({
        error: 'invalid_grant',
        error_description: 'bad code',
      });
    } finally {
      await s.close();
    }
  });

  // RFC 6749 §5.2: 401 with WWW-Authenticate only when the client tried to
  // authenticate through the Authorization header; 400 otherwise. A mock that
  // always answered 401 would enshrine behaviour the RFC does not require.
  it('answers 401 with WWW-Authenticate for invalid_client via the header', async () => {
    const s = await startServer({
      'GET /e': (_r, res) =>
        sendOAuthError(res, 'invalid_client', 'nope', { usedAuthorizationHeader: true }),
    });
    try {
      const res = await fetch(`${s.url}/e`);
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toMatch(/^Basic/);
    } finally {
      await s.close();
    }
  });

  // Without this case the rule is only half protected: drop the
  // `error === 'invalid_client'` conjunct and every other test still passes,
  // because none of them pairs a different error with the header.
  it('answers 400 for another error that did arrive via the header', async () => {
    const s = await startServer({
      'GET /e': (_r, res) =>
        sendOAuthError(res, 'invalid_grant', 'unknown code', {
          usedAuthorizationHeader: true,
        }),
    });
    try {
      const res = await fetch(`${s.url}/e`);
      expect(res.status).toBe(400);
      expect(res.headers.get('www-authenticate')).toBeNull();
    } finally {
      await s.close();
    }
  });

  it('answers 400 for invalid_client sent in the body', async () => {
    const s = await startServer({
      'GET /e': (_r, res) =>
        sendOAuthError(res, 'invalid_client', 'nope', { usedAuthorizationHeader: false }),
    });
    try {
      expect((await fetch(`${s.url}/e`)).status).toBe(400);
    } finally {
      await s.close();
    }
  });
});
```

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/jwt.test.ts src/__tests__/clientAuth.test.ts src/__tests__/oauthErrors.test.ts
```

Expected: FAIL — all three modules missing.

- [ ] **Step 3: Implement the three modules**

`src/jwt.ts`:

```ts
/**
 * Mints syntactically valid JWTs.
 *
 * Nothing in the family verifies the signature — providers only parse the
 * payload for `exp` — so the signature segment is deliberately not
 * cryptographically meaningful. What matters is the shape: three parts, and a
 * base64url payload carrying `exp` and `iat`.
 */

function b64url(value: object): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

export function mintJwt(opts: {
  expiresInSeconds: number;
  claims?: Record<string, unknown>;
}): string {
  const iat = Math.floor(Date.now() / 1000);
  const header = b64url({ alg: 'RS256', typ: 'JWT' });
  const payload = b64url({
    iat,
    exp: iat + opts.expiresInSeconds,
    ...opts.claims,
  });
  return `${header}.${payload}.mock-signature-not-verified`;
}
```

`src/oauthErrors.ts`:

```ts
/**
 * RFC 6749 §5.2 error responses.
 *
 * `invalid_client` is the one case with a conditional status: 401 with a
 * matching `WWW-Authenticate` when the client authenticated through the
 * `Authorization` header, 400 otherwise. Always answering 401 would enshrine
 * behaviour the specification does not require.
 */

import type * as http from 'node:http';

export function sendOAuthError(
  res: http.ServerResponse,
  error: string,
  description: string,
  opts: { usedAuthorizationHeader?: boolean } = {},
): void {
  const viaHeader = opts.usedAuthorizationHeader === true;
  res.statusCode = error === 'invalid_client' && viaHeader ? 401 : 400;
  if (res.statusCode === 401) {
    res.setHeader('WWW-Authenticate', 'Basic realm="mock"');
  }
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ error, error_description: description }));
}
```

`src/clientAuth.ts`:

```ts
/**
 * The three client authentication methods a real token endpoint accepts.
 *
 * They are not interchangeable in practice: UAA sends only HTTP Basic and puts
 * no `client_id` in the body, while OIDC puts `client_id` in the body. A mock
 * that assumed one shape would reject a real client.
 */

import type { RecordedRequest } from './server';

export interface ClientAuth {
  clientId?: string;
  clientSecret?: string;
  /** True when credentials arrived in the Authorization header. */
  usedAuthorizationHeader: boolean;
  /** True when header and body both carry a client_id and they disagree. */
  conflict: boolean;
}

export function readClientAuth(req: RecordedRequest): ClientAuth {
  const header = req.headers.authorization ?? '';
  let basicId: string | undefined;
  let basicSecret: string | undefined;

  if (header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    if (sep >= 0) {
      basicId = decoded.slice(0, sep);
      basicSecret = decoded.slice(sep + 1);
    }
  }

  const bodyId = req.body.client_id;
  const bodySecret = req.body.client_secret;

  return {
    clientId: basicId ?? bodyId,
    clientSecret: basicSecret ?? bodySecret,
    usedAuthorizationHeader: basicId !== undefined,
    conflict: basicId !== undefined && bodyId !== undefined && basicId !== bodyId,
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/jwt.test.ts src/__tests__/clientAuth.test.ts src/__tests__/oauthErrors.test.ts
```

Expected: PASS, thirteen cases.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build
git add src/jwt.ts src/oauthErrors.ts src/clientAuth.ts src/__tests__/
git commit -m "feat: JWT minting, RFC 6749 errors and client authentication"
```

---

### Task 4: The UAA mock — authorization code

**Files:**
- Create: `src/clients.ts`, `src/uaa.ts`
- Test: `src/__tests__/uaa.test.ts`

**Interfaces:**
- Consumes: `startServer`, `MockHandle`, `RecordedRequest` (Task 2); `mintJwt`, `sendOAuthError`, `readClientAuth` (Task 3).
- Produces, from `src/clients.ts` — the single implementation of the binding rule, used by Task 7 too:
  - `interface UaaClient { clientId: string; clientSecret: string }`
  - `interface ClientRegistryOptions { clients?: UaaClient[]; clientId?: string; clientSecret?: string }`
  - `interface ClientRegistry { all: UaaClient[]; find(clientId: string | undefined): UaaClient | undefined }`
  - `createClientRegistry(options?: ClientRegistryOptions): ClientRegistry`
  - `authenticateClient(req, res, registry, requireSecret): { auth, client } | null`
  - `refusedUnregisteredClient(res, registry, clientId): boolean`
  - `refusedForeignCredential(res, credential, issuedTo, authenticatedAs): boolean`
- Produces, from `src/uaa.ts`:
  - `interface UaaOptions { clients?: UaaClient[]; clientId?: string; clientSecret?: string; codeLifetimeMs?: number; accessTokenLifetimeSeconds?: number; authorize?: 'allow' | 'deny'; requireClientSecret?: boolean }`
  - `interface MockUaa extends MockHandle { }`
  - `startMockUaa(options?: UaaOptions): Promise<MockUaa>`

Defaults: one registered client `mock-client` / `mock-secret`, `codeLifetimeMs: 2000` (short, so an expiry test need not wait), `accessTokenLifetimeSeconds: 3600`, `authorize: 'allow'`, `requireClientSecret: true`.

**Why a registry and not a single client.** An authorization code belongs to the
client it was issued to; a server that forgets this lets any client it knows
redeem any code it issued. Proving the refusal needs two registered clients, so
the mock keeps a list. `clientId`/`clientSecret` remain as shorthand for the
common single-client case and are ignored when `clients` is given.

**Why it lives in its own file.** Task 7's OIDC mock enforces the same rule. One
implementation, imported twice — a security check that exists in two copies
drifts, and this one is the check the plan calls non-optional.

Write `src/clients.ts` first:

```ts
/**
 * The client registry, and the two refusals that keep a credential with the
 * client it was issued to.
 *
 * Both mocks import this. Authenticating a caller answers "do I know you";
 * these answer "is this yours", which is a different question and the one a
 * forgetful server gets wrong.
 */

import type * as http from 'node:http';
import { type ClientAuth, readClientAuth } from './clientAuth';
import { sendOAuthError } from './oauthErrors';
import type { RecordedRequest } from './server';

export interface UaaClient {
  clientId: string;
  clientSecret: string;
}

export interface ClientRegistryOptions {
  /** Registered clients. A test proving a code cannot cross a boundary uses two. */
  clients?: UaaClient[];
  /** Shorthand for a single registered client. Ignored when `clients` is given. */
  clientId?: string;
  clientSecret?: string;
}

export interface ClientRegistry {
  /** Registered clients, in declaration order. */
  all: UaaClient[];
  find(clientId: string | undefined): UaaClient | undefined;
}

export function createClientRegistry(options: ClientRegistryOptions = {}): ClientRegistry {
  const all = options.clients ?? [
    {
      clientId: options.clientId ?? 'mock-client',
      clientSecret: options.clientSecret ?? 'mock-secret',
    },
  ];
  return {
    all,
    find: (clientId) => all.find((c) => c.clientId === clientId),
  };
}

/**
 * RFC 6749 §4.1.2.1: an unregistered client means the redirect_uri it supplied
 * cannot be trusted either, so this error is answered directly and never
 * redirected — redirecting it would hand an attacker a redirector.
 *
 * Returns true when it answered, meaning the caller must stop.
 */
export function refusedUnregisteredClient(
  res: http.ServerResponse,
  registry: ClientRegistry,
  clientId: string | undefined,
): boolean {
  if (clientId && registry.find(clientId)) return false;
  sendOAuthError(res, 'invalid_request', 'client_id is missing or not registered');
  return true;
}

/**
 * Authenticates the caller against the registry: reads the credentials, rejects
 * a header/body disagreement, and checks the secret.
 *
 * Returns null when it has already answered, meaning the caller must stop.
 * Otherwise returns both the registered client and the credentials as read —
 * callers need the latter to ask the separate question `refusedForeignCredential`
 * answers.
 *
 * This lives here for the same reason the refusals do: both mocks need it
 * identically, and a security check kept in two copies drifts. Harden the secret
 * comparison once and both mocks get it.
 */
export function authenticateClient(
  req: RecordedRequest,
  res: http.ServerResponse,
  registry: ClientRegistry,
  requireSecret: boolean,
): { auth: ClientAuth; client: UaaClient } | null {
  const auth = readClientAuth(req);
  if (auth.conflict) {
    sendOAuthError(res, 'invalid_client', 'header and body disagree', {
      usedAuthorizationHeader: auth.usedAuthorizationHeader,
    });
    return null;
  }
  const client = registry.find(auth.clientId);
  if (!client || (requireSecret && auth.clientSecret !== client.clientSecret)) {
    sendOAuthError(res, 'invalid_client', 'unknown client', {
      usedAuthorizationHeader: auth.usedAuthorizationHeader,
    });
    return null;
  }
  return { auth, client };
}

/**
 * A credential belongs to the client it was issued to.
 *
 * Takes the credential's name so a code and a refresh token can share one
 * implementation while still saying which one was presented. They are the same
 * rule: a refresh token carries the authorization a code carried, so it crosses
 * a client boundary just as badly.
 *
 * Returns true when it answered, meaning the caller must stop.
 */
export function refusedForeignCredential(
  res: http.ServerResponse,
  credential: 'code' | 'refresh token',
  issuedTo: string,
  authenticatedAs: string | undefined,
): boolean {
  if (issuedTo === authenticatedAs) return false;
  sendOAuthError(
    res,
    'invalid_grant',
    `the ${credential} was issued to a different client`,
  );
  return true;
}
```

- [ ] **Step 1: Write the failing tests**

```ts
import { describe, expect, it } from '@jest/globals';
import { startMockUaa } from '../uaa';

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

/** Drives /authorize the way a browser would, returning the code it lands with. */
async function getCode(
  url: string,
  redirectUri: string,
  clientId = 'mock-client',
): Promise<string> {
  const res = await fetch(
    `${url}/oauth/authorize?client_id=${encodeURIComponent(clientId)}` +
      `&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}`,
    { redirect: 'manual' },
  );
  const location = res.headers.get('location') ?? '';
  return new URL(location).searchParams.get('code') ?? '';
}

describe('mock UAA', () => {
  it('redirects to the redirect_uri with a code', async () => {
    const uaa = await startMockUaa();
    try {
      const code = await getCode(uaa.url, 'http://localhost:61001/callback');
      expect(code).toBeTruthy();
    } finally {
      await uaa.close();
    }
  });

  it('exchanges the code for a JWT access token and a refresh token', async () => {
    const uaa = await startMockUaa();
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri);
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.access_token.split('.')).toHaveLength(3);
      expect(json.refresh_token).toBeTruthy();
    } finally {
      await uaa.close();
    }
  });

  // This is the refusal the previous arc had to guard by hand, twice.
  it('refuses a redirect_uri that differs from the authorize request', async () => {
    const uaa = await startMockUaa();
    try {
      const code = await getCode(uaa.url, 'http://localhost:61001/callback');
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:3001/callback',
        }).toString(),
      });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe('invalid_grant');
    } finally {
      await uaa.close();
    }
  });

  it('refuses a code used twice', async () => {
    const uaa = await startMockUaa();
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri);
      const exchange = () =>
        fetch(`${uaa.url}/oauth/token`, {
          method: 'POST',
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            authorization: basic('mock-client', 'mock-secret'),
          },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
          }).toString(),
        });
      expect((await exchange()).status).toBe(200);
      const second = await exchange();
      expect(second.status).toBe(400);
      expect((await second.json()).error).toBe('invalid_grant');
    } finally {
      await uaa.close();
    }
  });

  it('refuses an expired code', async () => {
    const uaa = await startMockUaa({ codeLifetimeMs: 50 });
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri);
      await new Promise((r) => setTimeout(r, 120));
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      expect((await res.json()).error).toBe('invalid_grant');
    } finally {
      await uaa.close();
    }
  });

  it('answers 401 with WWW-Authenticate when Basic credentials are wrong', async () => {
    const uaa = await startMockUaa();
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri);
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'wrong'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toBeTruthy();
      expect((await res.json()).error).toBe('invalid_client');
    } finally {
      await uaa.close();
    }
  });

  it('redirects with error=access_denied when told to deny', async () => {
    const uaa = await startMockUaa({ authorize: 'deny' });
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client&response_type=code&redirect_uri=${encodeURIComponent('http://localhost:61001/callback')}`,
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('error')).toBe('access_denied');
      expect(location.searchParams.get('code')).toBeNull();
    } finally {
      await uaa.close();
    }
  });

  it('journals what the client sent', async () => {
    const uaa = await startMockUaa();
    try {
      await getCode(uaa.url, 'http://localhost:49999/callback');
      const authorize = uaa.requests.find((r) => r.path === '/oauth/authorize');
      expect(authorize?.query.redirect_uri).toBe('http://localhost:49999/callback');
    } finally {
      await uaa.close();
    }
  });

  it('refuses a code it never issued', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'never-issued',
          redirect_uri: 'http://localhost:61001/callback',
        }).toString(),
      });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe('invalid_grant');
    } finally {
      await uaa.close();
    }
  });

  // The wrong-secret case exercises only the secret comparison. This one
  // exercises the other half: a client_id the registry has never heard of.
  it('refuses an entirely unknown client at the token endpoint', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('nobody', 'whatever'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'irrelevant',
          redirect_uri: 'http://localhost:61001/callback',
        }).toString(),
      });
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toMatch(/^Basic/);
      expect((await res.json()).error).toBe('invalid_client');
    } finally {
      await uaa.close();
    }
  });

  // The registry lookup and the secret comparison are two questions, and every
  // case above answers both at once: an unknown client that also presents a
  // wrong secret is refused by the comparison, whatever the lookup does. With
  // `requireClientSecret: false` the comparison is skipped, so the lookup is
  // the only thing left — and this is the only case that proves it works.
  it('refuses an unregistered client even when no secret is required', async () => {
    const uaa = await startMockUaa({ requireClientSecret: false });
    try {
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('nobody', ''),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'irrelevant',
          redirect_uri: 'http://localhost:61001/callback',
        }).toString(),
      });
      expect(res.status).toBe(401);
      expect((await res.json()).error).toBe('invalid_client');
    } finally {
      await uaa.close();
    }
  });

  // A code belongs to the client it was issued to. A server that only checks
  // "is this a client I know" lets one client redeem another's consent.
  it('refuses a code issued to a different client', async () => {
    const uaa = await startMockUaa({
      clients: [
        { clientId: 'first-client', clientSecret: 'first-secret' },
        { clientId: 'second-client', clientSecret: 'second-secret' },
      ],
    });
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri, 'first-client');
      expect(code).toBeTruthy();

      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('second-client', 'second-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toBe('invalid_grant');
      expect(json.error_description).toMatch(/different client/i);
    } finally {
      await uaa.close();
    }
  });

  it('refuses an unregistered client_id without redirecting to it', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=nobody&response_type=code` +
          `&redirect_uri=${encodeURIComponent('http://localhost:61001/callback')}`,
        { redirect: 'manual' },
      );
      expect(res.status).toBe(400);
      expect(res.headers.get('location')).toBeNull();
      expect((await res.json()).error).toBe('invalid_request');
    } finally {
      await uaa.close();
    }
  });
});
```

**Prove the binding test is load-bearing.** Delete the `issued.clientId !==
auth.clientId` branch you are about to write, run the suite, and watch the
first of these two go red. If it stays green the mock is not enforcing what the
test claims — find out why before continuing.

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/uaa.test.ts
```

Expected: FAIL — `Cannot find module '../uaa'`.

- [ ] **Step 3: Implement `src/uaa.ts`**

```ts
/**
 * A mock UAA authorization server.
 *
 * Strict by default: it refuses what a real server refuses, so a client's
 * mistake surfaces as this server's answer rather than as an assertion written
 * by the same person who wrote the mistake.
 */

import { randomUUID } from 'node:crypto';
import {
  authenticateClient,
  type ClientRegistryOptions,
  createClientRegistry,
  refusedForeignCredential,
  refusedUnregisteredClient,
} from './clients';
import { mintJwt } from './jwt';
import { sendOAuthError } from './oauthErrors';
import { type MockHandle, startServer } from './server';

export interface UaaOptions extends ClientRegistryOptions {
  /** Short by default so an expiry test does not have to wait. */
  codeLifetimeMs?: number;
  accessTokenLifetimeSeconds?: number;
  authorize?: 'allow' | 'deny';
  requireClientSecret?: boolean;
}

export type MockUaa = MockHandle;

interface IssuedCode {
  redirectUri: string;
  clientId: string;
  issuedAt: number;
  used: boolean;
}

export async function startMockUaa(options: UaaOptions = {}): Promise<MockUaa> {
  const registry = createClientRegistry(options);
  const codeLifetimeMs = options.codeLifetimeMs ?? 2000;
  const accessLifetime = options.accessTokenLifetimeSeconds ?? 3600;
  const requireSecret = options.requireClientSecret !== false;
  const denies = options.authorize === 'deny';

  const codes = new Map<string, IssuedCode>();

  return startServer({
    'GET /oauth/authorize': (req, res) => {
      const redirectUri = req.query.redirect_uri;
      if (!redirectUri) {
        sendOAuthError(res, 'invalid_request', 'redirect_uri is required');
        return;
      }
      const requestedClientId = req.query.client_id;
      if (refusedUnregisteredClient(res, registry, requestedClientId)) return;
      const target = new URL(redirectUri);
      if (denies) {
        target.searchParams.set('error', 'access_denied');
        target.searchParams.set('error_description', 'the mock was told to deny');
      } else {
        const code = randomUUID();
        codes.set(code, {
          redirectUri,
          // Non-null: refusedUnregisteredClient returned false, so it is set.
          clientId: requestedClientId as string,
          issuedAt: Date.now(),
          used: false,
        });
        target.searchParams.set('code', code);
      }
      if (req.query.state) target.searchParams.set('state', req.query.state);
      res.statusCode = 302;
      res.setHeader('Location', target.toString());
      res.end();
    },

    'POST /oauth/token': (req, res) => {
      const authenticated = authenticateClient(req, res, registry, requireSecret);
      if (!authenticated) return;
      const { auth, client } = authenticated;

      if (req.body.grant_type !== 'authorization_code') {
        sendOAuthError(res, 'unsupported_grant_type', String(req.body.grant_type));
        return;
      }

      const issued = codes.get(req.body.code ?? '');
      if (!issued) {
        sendOAuthError(res, 'invalid_grant', 'unknown code');
        return;
      }
      // Without this, a server that knows two clients lets either redeem the
      // other's code and the identity in the token bears no relation to consent.
      if (refusedForeignCredential(res, 'code', issued.clientId, auth.clientId)) return;
      if (issued.used) {
        sendOAuthError(res, 'invalid_grant', 'code already used');
        return;
      }
      if (Date.now() - issued.issuedAt > codeLifetimeMs) {
        sendOAuthError(res, 'invalid_grant', 'code expired');
        return;
      }
      if (issued.redirectUri !== req.body.redirect_uri) {
        sendOAuthError(
          res,
          'invalid_grant',
          `redirect_uri does not match the authorization request (${issued.redirectUri})`,
        );
        return;
      }

      issued.used = true;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          access_token: mintJwt({ expiresInSeconds: accessLifetime }),
          // client.clientId, not auth.clientId: the guard above narrowed
          // `client` to non-undefined, and registry.find matched it on exactly
          // that value. Same string, proven rather than asserted.
          refresh_token: issueRefreshToken(client.clientId),
          token_type: 'bearer',
          expires_in: accessLifetime,
        }),
      );
    },
  });
}
```

`issueRefreshToken` arrives in Task 5, which owns the refresh grant. Until then
define it beside the code store as a one-liner so this task compiles and its
tests pass:

```ts
  // Task 5 replaces this with one that registers the token against its client.
  const issueRefreshToken = (_clientId: string): string => `refresh-${randomUUID()}`;
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/uaa.test.ts
```

Expected: PASS, thirteen cases.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build
git add src/clients.ts src/uaa.ts src/__tests__/uaa.test.ts
git commit -m "feat: mock UAA authorization code flow, strict by default"
```

---

### Task 5: Refresh and the SAML bearer grant

**Files:**
- Modify: `src/uaa.ts`
- Test: `src/__tests__/uaaGrants.test.ts`

**Interfaces:**
- Produces: `UaaOptions` gains `rotateRefreshTokens?: boolean` (default `true`), `failRefresh?: boolean` (default `false`), `samlBearer?: 'strict' | 'lenient' | 'off'` (default `'strict'`). `MockUaa` gains `mintExpiredAccessWithValidRefresh(clientId?: string): { accessToken: string; refreshToken: string }`, defaulting to the first registered client. Refresh tokens are bound to their client exactly as codes are.

The minting helper exists so a test wanting the refresh path neither hand-crafts a JWT nor runs a full code flow and waits.

`samlBearer: 'strict'` enforces RFC 7522 §2.1 — the `assertion` parameter must be a base64url-encoded `Assertion`. `exchangeSamlAssertion` in `auth-providers` forwards the whole base64 `samlp:Response`, so strict mode will refuse it. **That is a finding about the client, not a defect in this mock**, and it belongs to issue #19's cycle. `'lenient'` accepts what the client currently sends so the discovery does not block anything.

- [ ] **Step 1: Write the failing tests**

```ts
import { describe, expect, it } from '@jest/globals';
import { startMockUaa } from '../uaa';

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

const post = (url: string, body: Record<string, string>) =>
  fetch(`${url}/oauth/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: basic('mock-client', 'mock-secret'),
    },
    body: new URLSearchParams(body).toString(),
  });

describe('refresh grant', () => {
  it('mints a consistent expired-access + valid-refresh pair', async () => {
    const uaa = await startMockUaa();
    try {
      const pair = uaa.mintExpiredAccessWithValidRefresh();
      const claims = JSON.parse(
        Buffer.from(pair.accessToken.split('.')[1], 'base64url').toString('utf8'),
      );
      expect(claims.exp).toBeLessThan(Math.floor(Date.now() / 1000));

      const res = await post(uaa.url, {
        grant_type: 'refresh_token',
        refresh_token: pair.refreshToken,
      });
      expect(res.status).toBe(200);
      expect((await res.json()).access_token.split('.')).toHaveLength(3);
    } finally {
      await uaa.close();
    }
  });

  it('rotates the refresh token and refuses the superseded one', async () => {
    const uaa = await startMockUaa({ rotateRefreshTokens: true });
    try {
      const pair = uaa.mintExpiredAccessWithValidRefresh();
      const first = await (
        await post(uaa.url, { grant_type: 'refresh_token', refresh_token: pair.refreshToken })
      ).json();
      expect(first.refresh_token).not.toBe(pair.refreshToken);

      const reuse = await post(uaa.url, {
        grant_type: 'refresh_token',
        refresh_token: pair.refreshToken,
      });
      expect(reuse.status).toBe(400);
      const body = await reuse.json();
      expect(body.error).toBe('invalid_grant');
      // Reuse, not merely unknown. Without this assertion the superseded set
      // could be deleted — the rotation already removes the old token, so the
      // request would be refused as "unknown" and the test would stay green,
      // losing the distinction a real server draws between a token that never
      // existed and one that was rotated away.
      expect(body.error_description).toMatch(/rotation/i);
    } finally {
      await uaa.close();
    }
  });

  // A refresh token carries the same authorization a code does, so it crosses a
  // client boundary just as badly. Without this case the binding check on the
  // refresh path can be deleted and every other test stays green.
  it('refuses a refresh token presented by a different client', async () => {
    const uaa = await startMockUaa({
      clients: [
        { clientId: 'first-client', clientSecret: 'first-secret' },
        { clientId: 'second-client', clientSecret: 'second-secret' },
      ],
    });
    try {
      const pair = uaa.mintExpiredAccessWithValidRefresh('first-client');
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('second-client', 'second-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: pair.refreshToken,
        }).toString(),
      });
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toBe('invalid_grant');
      expect(json.error_description).toMatch(/different client/i);
    } finally {
      await uaa.close();
    }
  });

  it('keeps the refresh token when rotation is off', async () => {
    const uaa = await startMockUaa({ rotateRefreshTokens: false });
    try {
      const pair = uaa.mintExpiredAccessWithValidRefresh();
      const body = await (
        await post(uaa.url, { grant_type: 'refresh_token', refresh_token: pair.refreshToken })
      ).json();
      expect(body.refresh_token).toBe(pair.refreshToken);
    } finally {
      await uaa.close();
    }
  });

  it('refuses an unknown refresh token', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await post(uaa.url, {
        grant_type: 'refresh_token',
        refresh_token: 'never-issued',
      });
      expect((await res.json()).error).toBe('invalid_grant');
    } finally {
      await uaa.close();
    }
  });

  it('fails every refresh when told to', async () => {
    const uaa = await startMockUaa({ failRefresh: true });
    try {
      const pair = uaa.mintExpiredAccessWithValidRefresh();
      const res = await post(uaa.url, {
        grant_type: 'refresh_token',
        refresh_token: pair.refreshToken,
      });
      expect(res.status).toBe(400);
    } finally {
      await uaa.close();
    }
  });
});

describe('SAML bearer grant', () => {
  const GRANT = 'urn:ietf:params:oauth:grant-type:saml2-bearer';
  const assertionXml =
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">' +
    '<saml:Issuer>mock-idp</saml:Issuer></saml:Assertion>';

  // A realistic Response *contains* an Assertion. A check that merely looks for
  // the substring "Assertion" anywhere passes this and proves nothing — which
  // is why the fixture is not an empty element.
  const responseXml =
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">' +
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    '<saml:Assertion ID="_a1"><saml:Issuer>mock-idp</saml:Issuer></saml:Assertion>' +
    '</samlp:Response>';

  it('accepts a base64url Assertion in strict mode', async () => {
    const uaa = await startMockUaa({ samlBearer: 'strict' });
    try {
      const res = await post(uaa.url, {
        grant_type: GRANT,
        assertion: Buffer.from(assertionXml, 'utf8').toString('base64url'),
      });
      expect(res.status).toBe(200);
      expect((await res.json()).access_token.split('.')).toHaveLength(3);
    } finally {
      await uaa.close();
    }
  });

  // What auth-providers sends today: a whole base64 samlp:Response, with an
  // Assertion nested inside it. Both of RFC 7522's requirements are violated at
  // once, and the encoding check is the one that fires — plain base64 of this
  // fixture carries `+` and padding. The next case isolates the other check.
  it('refuses a base64 samlp:Response in strict mode', async () => {
    const uaa = await startMockUaa({ samlBearer: 'strict' });
    try {
      const res = await post(uaa.url, {
        grant_type: GRANT,
        assertion: Buffer.from(responseXml, 'utf8').toString('base64'),
      });
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toBe('invalid_grant');
      expect(json.error_description).toMatch(/base64url/);
    } finally {
      await uaa.close();
    }
  });

  // And the mirror image: the content is a perfectly good Assertion and only
  // the encoding is wrong. Without this case the base64url check can be deleted
  // and every other bearer test stays green, because the document-element check
  // catches all of them.
  it('refuses a well-formed Assertion that is base64 rather than base64url', async () => {
    const uaa = await startMockUaa({ samlBearer: 'strict' });
    try {
      const encoded = Buffer.from(assertionXml, 'utf8').toString('base64');
      expect(encoded).not.toMatch(/^[A-Za-z0-9_-]+$/);
      const res = await post(uaa.url, { grant_type: GRANT, assertion: encoded });
      expect(res.status).toBe(400);
      expect((await res.json()).error_description).toMatch(/base64url/);
    } finally {
      await uaa.close();
    }
  });

  // The encoding check alone cannot carry this. Here the encoding is beyond
  // reproach — Node's base64url is unpadded and uses no + or / — so the refusal
  // can only come from asking what the document element is.
  it('refuses a Response that is correctly base64url-encoded', async () => {
    const uaa = await startMockUaa({ samlBearer: 'strict' });
    try {
      const encoded = Buffer.from(responseXml, 'utf8').toString('base64url');
      expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
      const res = await post(uaa.url, { grant_type: GRANT, assertion: encoded });
      expect(res.status).toBe(400);
      expect((await res.json()).error_description).toMatch(/Response/);
    } finally {
      await uaa.close();
    }
  });

  it('refuses something that is not XML at all', async () => {
    const uaa = await startMockUaa({ samlBearer: 'strict' });
    try {
      const res = await post(uaa.url, {
        grant_type: GRANT,
        assertion: Buffer.from('not xml', 'utf8').toString('base64url'),
      });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe('invalid_grant');
    } finally {
      await uaa.close();
    }
  });

  it('accepts the same thing in lenient mode', async () => {
    const uaa = await startMockUaa({ samlBearer: 'lenient' });
    try {
      const res = await post(uaa.url, {
        grant_type: GRANT,
        assertion: Buffer.from(responseXml, 'utf8').toString('base64'),
      });
      expect(res.status).toBe(200);
    } finally {
      await uaa.close();
    }
  });
});
```

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/uaaGrants.test.ts
```

Expected: FAIL — the options and the helper do not exist.

- [ ] **Step 3: Extend `src/uaa.ts`**

Add to `UaaOptions`:

```ts
  /** Both behaviours exist in the wild; a client must survive either. */
  rotateRefreshTokens?: boolean;
  failRefresh?: boolean;
  /** 'strict' enforces RFC 7522 §2.1: a base64url-encoded Assertion. */
  samlBearer?: 'strict' | 'lenient' | 'off';
```

Extend the return type:

```ts
export interface MockUaa extends MockHandle {
  /**
   * An access token already expired alongside a refresh token still valid.
   * Without this a refresh test must hand-craft a JWT or run a code flow and
   * wait — the first is duplication, the second is slow.
   */
  mintExpiredAccessWithValidRefresh(clientId?: string): {
    accessToken: string;
    refreshToken: string;
  };
}
```

Inside `startMockUaa`, replace Task 4's placeholder `issueRefreshToken` with one
that remembers **which client** the token was issued to — a refresh token carries
the same authorization a code did, so it crosses a client boundary just as badly:

```ts
  /** refresh token → the client it belongs to */
  const refreshTokens = new Map<string, string>();
  const supersededRefreshTokens = new Set<string>();

  const issueRefreshToken = (clientId: string): string => {
    const token = `refresh-${randomUUID()}`;
    refreshTokens.set(token, clientId);
    return token;
  };
```

Add these branches to `POST /oauth/token`, before the `unsupported_grant_type` fallback:

```ts
      if (req.body.grant_type === 'refresh_token') {
        const presented = req.body.refresh_token ?? '';
        if (failRefresh) {
          sendOAuthError(res, 'invalid_grant', 'the mock was told to fail every refresh');
          return;
        }
        if (supersededRefreshTokens.has(presented)) {
          sendOAuthError(res, 'invalid_grant', 'refresh token already used (rotation)');
          return;
        }
        const owner = refreshTokens.get(presented);
        if (owner === undefined) {
          sendOAuthError(res, 'invalid_grant', 'unknown refresh token');
          return;
        }
        // The same guard the code exchange uses. Writing this check a second
        // time by hand is how the two copies come to disagree.
        if (refusedForeignCredential(res, 'refresh token', owner, auth.clientId)) return;
        let next = presented;
        if (rotate) {
          refreshTokens.delete(presented);
          supersededRefreshTokens.add(presented);
          next = issueRefreshToken(owner);
        }
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            access_token: mintJwt({ expiresInSeconds: accessLifetime }),
            refresh_token: next,
            token_type: 'bearer',
            expires_in: accessLifetime,
          }),
        );
        return;
      }

      if (req.body.grant_type === 'urn:ietf:params:oauth:grant-type:saml2-bearer') {
        if (samlBearer === 'off') {
          sendOAuthError(res, 'unsupported_grant_type', 'saml bearer disabled');
          return;
        }
        const raw = req.body.assertion ?? '';
        if (!raw) {
          sendOAuthError(res, 'invalid_grant', 'assertion is required');
          return;
        }
        if (samlBearer === 'strict') {
          const problem = rejectNonAssertion(raw);
          if (problem) {
            sendOAuthError(res, 'invalid_grant', problem);
            return;
          }
        }
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            access_token: mintJwt({ expiresInSeconds: accessLifetime }),
            token_type: 'bearer',
            expires_in: accessLifetime,
          }),
        );
        return;
      }
```

RFC 7522 §2.1 asks for two separate things, and each needs its own check.
Put this above `startMockUaa`:

```ts
import { DOMParser } from '@xmldom/xmldom';

const SAML_ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
/** base64url: no + or /, and padding is not part of the alphabet. */
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * Returns a reason to refuse, or null to accept.
 *
 * The encoding check cannot stand alone — a base64 string may contain no `+`
 * or `/` by chance — and the content check cannot stand alone either, because
 * a `samlp:Response` contains an `Assertion`. So the content check asks what
 * the *document element* is, not what appears somewhere inside it.
 */
function rejectNonAssertion(raw: string): string | null {
  if (!BASE64URL.test(raw)) {
    return 'RFC 7522 §2.1 requires base64url encoding without padding';
  }

  try {
    const decoded = Buffer.from(raw, 'base64url').toString('utf8');
    const root = new DOMParser().parseFromString(decoded, 'text/xml').documentElement;
    if (!root) return 'the assertion parameter did not decode to XML';
    if (root.localName === 'Assertion' && root.namespaceURI === SAML_ASSERTION_NS) {
      return null;
    }
    return `RFC 7522 §2.1 requires a single Assertion as the document element, not a ${root.localName}`;
  } catch {
    return 'the assertion parameter did not decode to XML';
  }
}
```

`@xmldom/xmldom` is already a dependency for Task 8. On malformed input its
parser reports through a warning handler and may still return a document, so the
`root.localName` test — not the absence of a throw — is what decides.

Implement the mint helper by minting an expired JWT and registering a refresh token:

```ts
  const handle = await startServer({ /* routes above */ });
  return {
    ...handle,
    mintExpiredAccessWithValidRefresh(clientId = registry.all[0].clientId) {
      return {
        accessToken: mintJwt({ expiresInSeconds: -60 }),
        refreshToken: issueRefreshToken(clientId),
      };
    },
  };
```

- [ ] **Step 4: Run the whole suite to verify it passes**

```bash
npm test
```

Expected: PASS, including Task 4's cases unchanged.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build
git add src/uaa.ts src/__tests__/uaaGrants.test.ts
git commit -m "feat: refresh rotation, reuse detection and the SAML bearer grant"
```

---

### Task 6: The fake browser

**Files:**
- Create: `src/browser.ts`
- Test: `src/__tests__/browser.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks — deliberately, so it stays a browser rather than a mock-aware helper.
- Produces: `visit(url: string): Promise<{ finalUrl: string; status: number; body: string }>`

`visit` is what makes the design work: it plugs into `browserCallbackStrategy({ openUrl: visit })`, so the provider's own orchestration runs exactly as in production and only the browser is HTTP instead of Chrome. It follows redirects, and when it receives an HTML form with `method="post"` it submits it — which is how a SAML assertion reaches the ACS.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from '@jest/globals';
import { startServer } from '../server';
import { visit } from '../browser';

describe('visit', () => {
  it('follows a redirect chain to its end', async () => {
    const s = await startServer({
      'GET /a': (_r, res) => {
        res.statusCode = 302;
        res.setHeader('Location', '/b');
        res.end();
      },
      'GET /b': (_r, res) => res.end('arrived'),
    });
    try {
      const result = await visit(`${s.url}/a`);
      expect(result.body).toBe('arrived');
      expect(result.finalUrl).toBe(`${s.url}/b`);
    } finally {
      await s.close();
    }
  });

  it('submits an auto-submitting form, carrying every field', async () => {
    let received: Record<string, string> = {};
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs">
             <input type="hidden" name="SAMLResponse" value="PHNhbWw+"/>
             <input type="hidden" name="RelayState" value="rs-123"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (req, res) => {
        received = req.body;
        res.end('consumed');
      },
    });
    try {
      const result = await visit(`${s.url}/idp`);
      expect(received.SAMLResponse).toBe('PHNhbWw+');
      expect(received.RelayState).toBe('rs-123');
      expect(result.body).toBe('consumed');
    } finally {
      await s.close();
    }
  });

  // A real browser decodes attribute entities before submitting. One that does
  // not would hand the client a value no real flow could produce, and a bug in
  // the client's handling of & or a quote would never be reached.
  it('decodes HTML entities in form values and in the action', async () => {
    let received: Record<string, string> = {};
    let query: Record<string, string> = {};
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs?a=1&amp;b=2">
             <input type="hidden" name="RelayState" value="a&amp;b&quot;c&lt;d"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (req, res) => {
        received = req.body;
        query = req.query;
        res.end('ok');
      },
    });
    try {
      await visit(`${s.url}/idp`);
      expect(received.RelayState).toBe('a&b"c<d');
      // Decoded once, not twice: the action carried one & and still does.
      expect(query).toEqual({ a: '1', b: '2' });
    } finally {
      await s.close();
    }
  });

  // The ordering inside decodeEntities is a rule, so it needs a case that
  // breaks when the order changes. `&amp;lt;` is text the server chose to send:
  // decoding `&amp;` first turns it into `<`, a string the server never sent.
  // Nothing above distinguishes the two orders — none of those values is
  // double-escaped.
  it('decodes each entity once, so &amp;lt; stays literal text', async () => {
    let received: Record<string, string> = {};
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs">
             <input type="hidden" name="RelayState" value="&amp;lt;tag&amp;gt;"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (req, res) => {
        received = req.body;
        res.end('ok');
      },
    });
    try {
      await visit(`${s.url}/idp`);
      expect(received.RelayState).toBe('&lt;tag&gt;');
    } finally {
      await s.close();
    }
  });

  // Three rules the code performs that nothing above would notice losing.
  it('decodes numeric character references, decimal and hex', async () => {
    let received: Record<string, string> = {};
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs">
             <input type="hidden" name="RelayState" value="&#65;&#x42;&#39;&#x27;"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (req, res) => {
        received = req.body;
        res.end('ok');
      },
    });
    try {
      await visit(`${s.url}/idp`);
      expect(received.RelayState).toBe("AB''");
    } finally {
      await s.close();
    }
  });

  it('stops at a 3xx that carries no Location', async () => {
    const s = await startServer({
      'GET /dead-end': (_r, res) => {
        res.statusCode = 302;
        res.end('nowhere to go');
      },
    });
    try {
      const result = await visit(`${s.url}/dead-end`);
      expect(result.status).toBe(302);
      expect(result.finalUrl).toBe(`${s.url}/dead-end`);
      expect(result.body).toBe('nowhere to go');
    } finally {
      await s.close();
    }
  });

  // An ACS commonly redirects once it has consumed the assertion. A browser
  // follows; so must this one, and finalUrl must name where it ended up rather
  // than the form's action.
  it('keeps following after the form POST, and reports where it landed', async () => {
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs">
             <input type="hidden" name="SAMLResponse" value="PHNhbWw+"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (_r, res) => {
        res.statusCode = 303;
        res.setHeader('Location', '/done');
        res.end();
      },
      'GET /done': (_r, res) => res.end('landed'),
    });
    try {
      const result = await visit(`${s.url}/idp`);
      expect(result.body).toBe('landed');
      expect(result.finalUrl).toBe(`${s.url}/done`);
      expect(result.status).toBe(200);
    } finally {
      await s.close();
    }
  });

  it('stops rather than looping forever on a redirect cycle', async () => {
    const s = await startServer({
      'GET /loop': (_r, res) => {
        res.statusCode = 302;
        res.setHeader('Location', '/loop');
        res.end();
      },
    });
    try {
      await expect(visit(`${s.url}/loop`)).rejects.toThrow(/too many redirects/i);
    } finally {
      await s.close();
    }
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
npm test -- src/__tests__/browser.test.ts
```

Expected: FAIL — `Cannot find module '../browser'`.

- [ ] **Step 3: Implement `src/browser.ts`**

```ts
/**
 * A browser, reduced to what an authorization flow needs from one.
 *
 * It follows redirects and submits auto-submitting forms — the two things a
 * real browser does during an OAuth redirect or a SAML HTTP-POST binding. It is
 * wired in through `openUrl`, so the code under test runs its own orchestration
 * and only the browser is replaced.
 */

const MAX_REDIRECTS = 10;

export interface VisitResult {
  finalUrl: string;
  status: number;
  body: string;
}

/**
 * Reverses HTML attribute escaping.
 *
 * A real browser does this, so a browser that does not is not testing the
 * client — it is testing a value the client would never have seen. `&amp;`
 * must be last: decoding it first would turn `&amp;lt;` into `<`.
 */
function decodeEntities(value: string): string {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;|&#x0*27;/gi, "'")
    .replace(/&#(\d+);/g, (_m, d) => String.fromCodePoint(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_m, h) => String.fromCodePoint(Number.parseInt(h, 16)))
    .replace(/&amp;/g, '&');
}

/** Extracts a form's action and its hidden inputs, if the page is one. */
function parseForm(
  html: string,
  base: string,
): { action: string; fields: Record<string, string> } | null {
  const form = /<form[^>]*method=["']post["'][^>]*>([\s\S]*?)<\/form>/i.exec(html);
  if (!form) return null;
  const actionMatch = /action=["']([^"']*)["']/i.exec(form[0]);
  const action = new URL(decodeEntities(actionMatch?.[1] ?? ''), base).toString();
  const fields: Record<string, string> = {};
  const input = /<input[^>]*>/gi;
  let m: RegExpExecArray | null = input.exec(form[1]);
  while (m) {
    const name = /name=["']([^"']+)["']/i.exec(m[0])?.[1];
    const value = /value=["']([^"']*)["']/i.exec(m[0])?.[1] ?? '';
    if (name) fields[name] = decodeEntities(value);
    m = input.exec(form[1]);
  }
  return { action, fields };
}

export async function visit(url: string): Promise<VisitResult> {
  let current = url;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const res = await fetch(current, { redirect: 'manual' });

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location) {
        return { finalUrl: current, status: res.status, body: await res.text() };
      }
      current = new URL(location, current).toString();
      continue;
    }

    const body = await res.text();
    const form = parseForm(body, current);
    if (form) {
      const posted = await fetch(form.action, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(form.fields).toString(),
        // Manual, like every other fetch here. Left to its default the POST
        // would follow a redirect on its own, outside the hop cap, and
        // `finalUrl` below would still name the pre-redirect action.
        redirect: 'manual',
      });
      if (posted.status >= 300 && posted.status < 400) {
        const location = posted.headers.get('location');
        if (location) {
          // A browser keeps going after the POST, and an ACS commonly
          // redirects once it has consumed the assertion. Rejoin the loop so
          // the hop cap and finalUrl stay honest — the next hop is a GET,
          // which is what a browser issues after a 302 or 303.
          current = new URL(location, form.action).toString();
          continue;
        }
      }
      return {
        finalUrl: form.action,
        status: posted.status,
        body: await posted.text(),
      };
    }

    return { finalUrl: current, status: res.status, body };
  }

  throw new Error(`Too many redirects starting from ${url}`);
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/browser.test.ts
```

Expected: PASS, eight cases.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build
git add src/browser.ts src/__tests__/browser.test.ts
git commit -m "feat: a fake browser that follows redirects and submits forms"
```

---

### Task 7: The OIDC mock

**Files:**
- Create: `src/oidc.ts`
- Test: `src/__tests__/oidc.test.ts`

**Interfaces:**
- Consumes: `startServer`, `mintJwt`, `sendOAuthError`, `readClientAuth`, and from `src/clients.ts` (Task 4): `createClientRegistry`, `authenticateClient`, `refusedUnregisteredClient`, `refusedForeignCredential`, `ClientRegistryOptions`.
- Produces:
  - `interface OidcOptions extends UaaOptions { state?: 'mirror' | 'wrongState' | 'missingState' }`
  - `startMockOidc(options?: OidcOptions): Promise<MockHandle>` serving `/.well-known/openid-configuration`, `/authorize`, `/token`.

Two rules distinguish it from the UAA mock:

**PKCE is demanded at both ends.** `/authorize` refuses a request with no `code_challenge`, no `code_challenge_method`, or a method other than `S256`. Verifying a challenge only when one happens to arrive would let a non-PKCE request through while still satisfying the exchange rule — a strict mock that tolerates the weaker flow is not strict.

**`state` is mirrored, never judged.** Validating `state` is the client's duty, and a mock that checked it would be doing the client's job while hiding whether the client does it. `OidcBrowserProvider` sends no `state` today, so a test written against this mock is what makes that visible.

**The code is bound to its client, by the same code as Task 4.** `OidcOptions extends UaaOptions`, so it inherits the registry options, and the enforcement is imported from `src/clients.ts` — `createClientRegistry`, `authenticateClient`, `refusedUnregisteredClient`, `refusedForeignCredential`. Do not reimplement any of the four. This rule is the one most easily lost in translation, and a second copy of a security check is how the two mocks come to disagree about it.

- [ ] **Step 1: Write the failing tests**

```ts
import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from '@jest/globals';
import { startMockOidc } from '../oidc';

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function authorizeUrl(base: string, params: Record<string, string>) {
  return `${base}/authorize?${new URLSearchParams({
    client_id: 'mock-client',
    response_type: 'code',
    redirect_uri: 'http://localhost:61001/callback',
    ...params,
  }).toString()}`;
}

describe('mock OIDC', () => {
  it('serves a discovery document naming its own endpoints', async () => {
    const oidc = await startMockOidc();
    try {
      const doc = await (
        await fetch(`${oidc.url}/.well-known/openid-configuration`)
      ).json();
      expect(doc.authorization_endpoint).toBe(`${oidc.url}/authorize`);
      expect(doc.token_endpoint).toBe(`${oidc.url}/token`);
    } finally {
      await oidc.close();
    }
  });

  // RFC 6749 §4.1.2.1 draws the line at trust: once client_id and redirect_uri
  // check out, the error belongs at the callback. That is the path the client
  // actually walks, and reproducing it is most of why this mock exists — a
  // direct 400 would leave the client's error handling untested.
  it('reports a missing code_challenge at the callback, not in the response', async () => {
    const oidc = await startMockOidc();
    try {
      const res = await fetch(authorizeUrl(oidc.url, { state: 'st-42' }), {
        redirect: 'manual',
      });
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.origin + location.pathname).toBe('http://localhost:61001/callback');
      expect(location.searchParams.get('error')).toBe('invalid_request');
      // Not /code_challenge/: that substring also appears in the S256 branch's
      // message ("unsupported code_challenge_method: undefined"), so the
      // presence check could be deleted with this case still green.
      expect(location.searchParams.get('error_description')).toMatch(/PKCE is required/);
      // State is mirrored on the error path too — a client that validates it
      // must be able to, or it cannot safely match the error to its request.
      expect(location.searchParams.get('state')).toBe('st-42');
      expect(location.searchParams.get('code')).toBeNull();
    } finally {
      await oidc.close();
    }
  });

  it('reports a code_challenge_method other than S256 at the callback', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'plain',
        }),
        { redirect: 'manual' },
      );
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('error')).toBe('invalid_request');
      expect(location.searchParams.get('error_description')).toMatch(/plain/);
      expect(location.searchParams.get('code')).toBeNull();
    } finally {
      await oidc.close();
    }
  });

  it('exchanges a code when the verifier matches the challenge', async () => {
    const oidc = await startMockOidc();
    try {
      const { verifier, challenge } = pkce();
      const redirected = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      const code = new URL(redirected.headers.get('location') ?? '').searchParams.get('code');
      const res = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code ?? '',
          redirect_uri: 'http://localhost:61001/callback',
          code_verifier: verifier,
          client_id: 'mock-client',
        }).toString(),
      });
      expect(res.status).toBe(200);
    } finally {
      await oidc.close();
    }
  });

  it('refuses a verifier that does not derive the challenge', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const other = pkce();
      const redirected = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      const code = new URL(redirected.headers.get('location') ?? '').searchParams.get('code');
      const res = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code ?? '',
          redirect_uri: 'http://localhost:61001/callback',
          code_verifier: other.verifier,
          client_id: 'mock-client',
        }).toString(),
      });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe('invalid_grant');
    } finally {
      await oidc.close();
    }
  });

  it('mirrors state back unchanged', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'st-42',
        }),
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('state')).toBe('st-42');
    } finally {
      await oidc.close();
    }
  });

  it('returns a different state when asked for wrongState', async () => {
    const oidc = await startMockOidc({ state: 'wrongState' });
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'st-42',
        }),
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('state')).not.toBe('st-42');
      expect(location.searchParams.get('state')).toBeTruthy();
    } finally {
      await oidc.close();
    }
  });

  it('omits state entirely when asked for missingState', async () => {
    const oidc = await startMockOidc({ state: 'missingState' });
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'st-42',
        }),
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('state')).toBeNull();
    } finally {
      await oidc.close();
    }
  });

  // The same rule as Task 4, restated here because "model it on uaa.ts" is
  // exactly the kind of instruction that loses a check in translation.
  it('refuses a code issued to a different client', async () => {
    const oidc = await startMockOidc({
      clients: [
        { clientId: 'first-client', clientSecret: 'first-secret' },
        { clientId: 'second-client', clientSecret: 'second-secret' },
      ],
    });
    try {
      const { verifier, challenge } = pkce();
      const redirectUri = 'http://localhost:61001/callback';
      const res = await fetch(
        `${oidc.url}/authorize?${new URLSearchParams({
          client_id: 'first-client',
          response_type: 'code',
          redirect_uri: redirectUri,
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }).toString()}`,
        { redirect: 'manual' },
      );
      const code = new URL(res.headers.get('location') ?? '').searchParams.get('code');
      expect(code).toBeTruthy();

      const exchange = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('second-client', 'second-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code ?? '',
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }).toString(),
      });
      expect(exchange.status).toBe(400);
      expect((await exchange.json()).error).toBe('invalid_grant');
    } finally {
      await oidc.close();
    }
  });

  // The first trust-boundary refusal: with no redirect_uri there is nowhere to
  // send an error to, so it can only be answered here.
  it('refuses an authorize request with no redirect_uri at all', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        `${oidc.url}/authorize?${new URLSearchParams({
          client_id: 'mock-client',
          response_type: 'code',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }).toString()}`,
        { redirect: 'manual' },
      );
      expect(res.status).toBe(400);
      expect(res.headers.get('location')).toBeNull();
      expect((await res.json()).error).toBe('invalid_request');
    } finally {
      await oidc.close();
    }
  });

  // The other side of the same rule: an unregistered client means the
  // redirect_uri it supplied cannot be trusted either, so this error must NOT
  // travel to the callback — sending it there would hand an attacker a
  // redirector. Contrast with the two PKCE cases above.
  it('refuses an unregistered client_id without redirecting to it', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          client_id: 'nobody',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      expect(res.status).toBe(400);
      expect(res.headers.get('location')).toBeNull();
      expect((await res.json()).error).toBe('invalid_request');
    } finally {
      await oidc.close();
    }
  });
});
```

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/oidc.test.ts
```

Expected: FAIL — `Cannot find module '../oidc'`.

- [ ] **Step 3: Implement `src/oidc.ts`**

Model it on `src/uaa.ts`: same code store, same error helper — but **import** every client check from `src/clients.ts` rather than restating it. `createClientRegistry(options)` builds the registry, `refusedUnregisteredClient` guards `/authorize`, `authenticateClient` opens `/token`, and `refusedForeignCredential` guards the code it redeems. None of the four is optional here, and none should exist twice. Client authentication in particular reads as boilerplate worth copying; it is a security check, and a copied security check is one that will eventually disagree with its twin. The differences are the three routes, the PKCE demand at `/authorize`, the `S256` comparison at `/token`, and the `state` handling:

```ts
import { createHash, randomUUID } from 'node:crypto';
```

**`/authorize` has two error paths, and which one applies is a question about
trust, not about severity.** RFC 6749 §4.1.2.1: a missing or unregistered
`client_id`, or a missing `redirect_uri`, means the redirect target itself
cannot be trusted — those errors are answered directly and never redirected.
Every error after that point is reported *at the callback*, because that is the
path a real client walks, and reproducing it is most of why this mock exists.

So the route runs the Task 4 client checks first, then defines a redirecting
error helper, then demands PKCE through it:

```ts
      const redirectUri = req.query.redirect_uri;
      if (!redirectUri) {
        sendOAuthError(res, 'invalid_request', 'redirect_uri is required');
        return;
      }
      const requestedClientId = req.query.client_id;
      if (refusedUnregisteredClient(res, registry, requestedClientId)) return;

      const target = new URL(redirectUri);
      // Past this line the redirect_uri is trusted, so errors go to it.
      const redirectError = (description: string): void => {
        target.searchParams.set('error', 'invalid_request');
        target.searchParams.set('error_description', description);
        applyState(target, req.query.state);
        res.statusCode = 302;
        res.setHeader('Location', target.toString());
        res.end();
      };

      const challenge = req.query.code_challenge;
      const method = req.query.code_challenge_method;
      if (!challenge || !method) {
        redirectError('PKCE is required: code_challenge and code_challenge_method');
        return;
      }
      if (method !== 'S256') {
        redirectError(`unsupported code_challenge_method: ${method}`);
        return;
      }
```

Store `challenge` alongside the code. At `/token`, after the redirect_uri check:

```ts
      // The binding check comes first, exactly as in uaa.ts, and by the same
      // function — a code redeemed by the wrong client is refused before its
      // verifier is even considered.
      if (refusedForeignCredential(res, 'code', issued.clientId, auth.clientId)) return;

      const verifier = req.body.code_verifier ?? '';
      const derived = createHash('sha256').update(verifier).digest('base64url');
      if (derived !== issued.challenge) {
        sendOAuthError(res, 'invalid_grant', 'code_verifier does not derive code_challenge');
        return;
      }
```

`state` is handled by one helper used by **both** the success redirect and
`redirectError`, so the error path is not a place where a rule quietly differs.
Define it beside the registry:

```ts
  /**
   * Mirrored, never judged: validating state is the client's duty, and a mock
   * that checked it would hide whether the client does. The corruption modes
   * exist to test that the client notices.
   */
  const applyState = (target: URL, incoming: string | undefined): void => {
    if (incoming === undefined) return;
    if (stateMode === 'mirror') target.searchParams.set('state', incoming);
    else if (stateMode === 'wrongState') target.searchParams.set('state', `not-${incoming}`);
    // 'missingState' sets nothing
  };
```

And the discovery document:

```ts
    'GET /.well-known/openid-configuration': (_req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          issuer: baseUrl,
          authorization_endpoint: `${baseUrl}/authorize`,
          token_endpoint: `${baseUrl}/token`,
          code_challenge_methods_supported: ['S256'],
          response_types_supported: ['code'],
        }),
      );
    },
```

`baseUrl` is not known until the server binds, so start the server first with a mutable holder and fill it in from the returned handle before returning.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/oidc.test.ts
```

Expected: PASS, eleven cases.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build
git add src/oidc.ts src/__tests__/oidc.test.ts
git commit -m "feat: mock OIDC provider demanding PKCE and mirroring state"
```

---

### Task 8: Signing

**Files:**
- Create: `src/signing.ts`
- Test: `src/__tests__/signing.test.ts`
- Modify: `README.md`

**Interfaces:**
- Produces:
  - `generateKeyMaterial(): { privateKeyPem: string; certificatePem: string }`
  - `signXml(xml: string, key: { privateKeyPem: string; certificatePem: string }, opts?: { referenceXPath?: string }): string`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from '@jest/globals';
import { SignedXml } from 'xml-crypto';
import { DOMParser } from '@xmldom/xmldom';
import { generateKeyMaterial, signXml } from '../signing';

const ASSERTION = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml:Issuer>mock-idp</saml:Issuer></saml:Assertion>`;

describe('signing', () => {
  it('generates a usable key pair and certificate', () => {
    const key = generateKeyMaterial();
    expect(key.privateKeyPem).toContain('BEGIN');
    expect(key.certificatePem).toContain('BEGIN CERTIFICATE');
  });

  it('produces a signature that verifies against its own certificate', () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION, key);
    const doc = new DOMParser().parseFromString(signed, 'text/xml');
    const signature = doc.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Signature',
    )[0];

    const verifier = new SignedXml({ publicCert: key.certificatePem });
    verifier.loadSignature(signature as unknown as Node);
    expect(verifier.checkSignature(signed)).toBe(true);
  });

  it('fails verification when the content is altered after signing', () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION, key).replace('mock-idp', 'other-idp');
    const doc = new DOMParser().parseFromString(signed, 'text/xml');
    const signature = doc.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Signature',
    )[0];

    const verifier = new SignedXml({ publicCert: key.certificatePem });
    verifier.loadSignature(signature as unknown as Node);
    expect(verifier.checkSignature(signed)).toBe(false);
  });

  it('fails verification against a different certificate', () => {
    const key = generateKeyMaterial();
    const other = generateKeyMaterial();
    const signed = signXml(ASSERTION, key);
    const doc = new DOMParser().parseFromString(signed, 'text/xml');
    const signature = doc.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Signature',
    )[0];

    const verifier = new SignedXml({ publicCert: other.certificatePem });
    verifier.loadSignature(signature as unknown as Node);
    expect(verifier.checkSignature(signed)).toBe(false);
  });

  // `referenceXPath` is part of signXml's public signature but none of the
  // cases above ever pass it, so a bug that silently ignored the option
  // (always signing the default Assertion match) would go unnoticed. This
  // proves the option actually narrows what gets signed: altering content
  // outside the referenced element leaves the signature valid; altering the
  // referenced element itself invalidates it.
  it('signs only the element selected by a custom referenceXPath', () => {
    const key = generateKeyMaterial();
    const doc = `<Root xmlns="urn:test" ID="_root"><A ID="_a">alpha</A><B ID="_b">beta</B></Root>`;
    const signed = signXml(doc, key, {
      referenceXPath: "//*[local-name(.)='B']",
    });

    const verify = (xml: string): boolean => {
      const parsed = new DOMParser().parseFromString(xml, 'text/xml');
      const signature = parsed.getElementsByTagNameNS(
        'http://www.w3.org/2000/09/xmldsig#',
        'Signature',
      )[0];
      const verifier = new SignedXml({ publicCert: key.certificatePem });
      verifier.loadSignature(signature as unknown as Node);
      return verifier.checkSignature(xml);
    };

    expect(verify(signed)).toBe(true);
    expect(verify(signed.replace('alpha', 'ALPHA-CHANGED'))).toBe(true);
    expect(verify(signed.replace('beta', 'BETA-CHANGED'))).toBe(false);
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
npm test -- src/__tests__/signing.test.ts
```

Expected: FAIL — `Cannot find module '../signing'`.

- [ ] **Step 3: Implement `src/signing.ts`**

```ts
/**
 * Key material and XML-DSig for the SAML IdP.
 *
 * A fresh self-signed certificate per mock instance, held in memory. No key
 * material lives in the repository, and nothing here is meant to be secure —
 * it exists so that a signature can be produced and then verified.
 */

import forge from 'node-forge';
import { SignedXml } from 'xml-crypto';

export interface KeyMaterial {
  privateKeyPem: string;
  certificatePem: string;
}

export function generateKeyMaterial(): KeyMaterial {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 24 * 3600 * 1000);
  const attrs = [{ name: 'commonName', value: 'mock-idp' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
    certificatePem: forge.pki.certificateToPem(cert),
  };
}

export function signXml(
  xml: string,
  key: KeyMaterial,
  opts: { referenceXPath?: string } = {},
): string {
  const sig = new SignedXml({
    privateKey: key.privateKeyPem,
    publicCert: key.certificatePem,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath: opts.referenceXPath ?? "//*[local-name(.)='Assertion']",
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
  });
  sig.computeSignature(xml);
  return sig.getSignedXml();
}
```

If `xml-crypto@6`'s constructor or `addReference` signature differs from the above, follow the version actually installed rather than this snippet — check `node_modules/xml-crypto/lib/*.d.ts` — and note the deviation in your report.

Two such deviations are already known from implementing this task, so expect them: `Node` must be imported from `@xmldom/xmldom` rather than taken as a DOM global, because the project has no `dom` lib; and `xml-crypto@6.1.2`'s `checkSignature` **throws** rather than returning `false` when the signature value itself fails against an unrelated certificate — it returns `false` only for a reference-digest mismatch. The wrong-key case therefore asserts `expect(() => …).toThrow(/invalid signature/)`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/signing.test.ts
```

Expected: PASS, five cases.

- [ ] **Step 5: Record the verification limitation in the README**

Add a section saying plainly what the suite does and does not establish:

- The package's own tests verify a signature with `xml-crypto` — the same library that produced it.
- `@node-saml/node-saml` independently checks signature validity, `Conditions` timestamps, `Audience`, `Issuer` and `InResponseTo`, but shares `xml-crypto` underneath for the cryptography.
- It checks **neither `Destination` nor `SubjectConfirmationData@Recipient`**, so those two variants have no independent judge here.
- It has no assertion-ID replay cache; replay detection belongs to the relying party.
- Canonicalisation matching a real identity provider is therefore **not** proven by this suite, and live testing remains necessary.

Someone reading a green suite must not conclude otherwise.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build
git add src/signing.ts src/__tests__/signing.test.ts README.md
git commit -m "feat: per-instance key material and XML-DSig signing"
```

---

### Task 9: The SAML IdP

**Files:**
- Create: `src/saml.ts`
- Test: `src/__tests__/saml.test.ts`

**Interfaces:**
- Consumes: `startServer`, `generateKeyMaterial`, `signXml`, `visit`.
- Produces:
  - `type SamlVariant = 'valid' | 'unsigned' | 'wrongKey' | 'tamperedAfterSign' | 'statusFailure' | 'expired' | 'notYetValid' | 'wrongAudience' | 'wrongInResponseTo' | 'wrongDestination' | 'wrongRecipient' | 'wrongIssuer'`
  - `interface SamlOptions { variant?: SamlVariant; audience?: string; issuer?: string }`
  - `interface MockSamlIdp extends MockHandle { certificatePem: string; setVariant(v: SamlVariant): void; lastAssertionId(): string | undefined; repeatLastAssertion(): void }`
  - `startMockSamlIdp(options?: SamlOptions): Promise<MockSamlIdp>`

Defaults: `variant: 'valid'`, `issuer: 'mock-idp'`, `audience: 'mock-sp'`. Task 10
configures an independent verifier with exactly those two names, so changing
either here means changing it there.

**Two things the implementation must get right, both settled during spec review:**

The IdP **returns an HTML auto-submitting form** targeting the ACS; it does not POST there itself. `visit()` performs the POST. If the IdP posted server-side, `openUrl` would never be called and the seam this package exists to exercise would go untested.

`RelayState` comes from the **HTTP query string**, not from inside the inflated `SAMLRequest` — under the Redirect binding it travels as its own parameter alongside `SAMLRequest`. It is carried through the form and posted back unchanged.

**Replay is a sequence, not a variant.** A replayed assertion is, in isolation, perfectly valid — that is why replay is dangerous, and why no off-the-shelf verifier rejects one. `repeatLastAssertion()` makes the next response reuse the previous assertion's `ID`, so Task 10 can show the sequence: two deliveries, one assertion ID, both individually acceptable. Detecting it needs a relying party that remembers, which is issue #19's work — this mock's duty is to produce the sequence, not to judge it.

- [ ] **Step 1: Write the failing tests**

```ts
import { deflateRawSync } from 'node:zlib';
import { describe, expect, it } from '@jest/globals';
import { startServer } from '../server';
import { startMockSamlIdp } from '../saml';
import { visit } from '../browser';

function authnRequest(acsUrl: string, id = '_req1'): string {
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `ID="${id}" Version="2.0" AssertionConsumerServiceURL="${acsUrl}"/>`;
  return deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');
}

/** An ACS that records what the browser posts to it. */
async function startAcs() {
  const received: Record<string, string>[] = [];
  const server = await startServer({
    'POST /callback': (req, res) => {
      received.push(req.body);
      res.end('ok');
    },
  });
  return { ...server, received };
}

describe('mock SAML IdP', () => {
  it('returns an auto-submitting form rather than posting to the ACS itself', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      const url = `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
        authnRequest(`${acs.url}/callback`),
      )}`;
      const page = await (await fetch(url)).text();
      expect(page).toMatch(/<form[^>]+method=["']post["']/i);
      expect(page).toContain(`${acs.url}/callback`);
      // Nothing reached the ACS: delivery is the browser's job.
      expect(acs.received).toHaveLength(0);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('delivers the assertion when a browser submits the form', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(`${acs.url}/callback`))}`,
      );
      expect(acs.received).toHaveLength(1);
      expect(acs.received[0].SAMLResponse).toBeTruthy();
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('carries RelayState from the query string through the form', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
          authnRequest(`${acs.url}/callback`),
        )}&RelayState=${encodeURIComponent('rs-abc')}`,
      );
      expect(acs.received[0].RelayState).toBe('rs-abc');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('signs the assertion by default and exposes its certificate', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      expect(idp.certificatePem).toContain('BEGIN CERTIFICATE');
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(`${acs.url}/callback`))}`,
      );
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString('utf8');
      expect(xml).toContain('Signature');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('omits the signature for the unsigned variant', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'unsigned' });
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(`${acs.url}/callback`))}`,
      );
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString('utf8');
      expect(xml).not.toContain('Signature');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('names a different ACS for the wrongDestination variant', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'wrongDestination' });
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(`${acs.url}/callback`))}`,
      );
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString('utf8');
      const destination = /Destination="([^"]+)"/.exec(xml)?.[1];
      expect(destination).toBeTruthy();
      expect(destination).not.toBe(`${acs.url}/callback`);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('echoes InResponseTo by default and breaks it on demand', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
          authnRequest(`${acs.url}/callback`, '_req42'),
        )}`,
      );
      let xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString('utf8');
      expect(xml).toContain('InResponseTo="_req42"');

      idp.setVariant('wrongInResponseTo');
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
          authnRequest(`${acs.url}/callback`, '_req42'),
        )}`,
      );
      xml = Buffer.from(acs.received[1].SAMLResponse, 'base64').toString('utf8');
      expect(xml).not.toContain('InResponseTo="_req42"');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  // RelayState is opaque data the client chose, and an ACS URL routinely
  // carries a query string. If either is dropped into the form unescaped, the
  // value is corrupted or the markup is — and every test above would still be
  // green, because none of them uses a character that matters.
  it('carries reserved characters through the form unharmed', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    const relayState = 'a&b"c<d>e\'f';
    try {
      const acsUrl = `${acs.url}/callback?tenant=one&flow=saml`;
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(acsUrl))}` +
          `&RelayState=${encodeURIComponent(relayState)}`,
      );
      expect(acs.received).toHaveLength(1);
      expect(acs.received[0].RelayState).toBe(relayState);
      // The response still decodes, so the SAMLResponse survived escaping too.
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString('utf8');
      expect(xml).toContain('Assertion');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  // Empty and absent are different messages. `RelayState=` is a value the
  // client chose to send; omitting the parameter is not. Replace the
  // `=== undefined` check with a truthy one and every other case stays green.
  it('carries an empty RelayState, and omits the field when there was none', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      const request = encodeURIComponent(authnRequest(`${acs.url}/callback`));

      await visit(`${idp.url}/sso?SAMLRequest=${request}&RelayState=`);
      expect(acs.received).toHaveLength(1);
      expect(acs.received[0].RelayState).toBe('');

      const without = await (await fetch(`${idp.url}/sso?SAMLRequest=${request}`)).text();
      expect(without).not.toContain('name="RelayState"');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  // Replay is a sequence: the same assertion, delivered twice. In isolation the
  // second delivery is valid, which is exactly why a verifier must remember.
  it('repeats a previous assertion ID on demand', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      const url = `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
        authnRequest(`${acs.url}/callback`),
      )}`;
      await visit(url);
      const firstId = idp.lastAssertionId();
      expect(firstId).toBeTruthy();

      idp.repeatLastAssertion();
      await visit(url);
      const secondXml = Buffer.from(acs.received[1].SAMLResponse, 'base64').toString('utf8');
      expect(secondXml).toContain(`ID="${firstId}"`);
    } finally {
      await idp.close();
      await acs.close();
    }
  });
});
```

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/saml.test.ts
```

Expected: FAIL — `Cannot find module '../saml'`.

- [ ] **Step 3: Implement `src/saml.ts`**

Structure:

1. `GET /sso` reads `SAMLRequest` from the query, `inflateRawSync`s it, and pulls `AssertionConsumerServiceURL` and `ID` out with a regex — the request is one the family builds, so a full XML parse is not warranted. `RelayState` comes from `req.query.RelayState`.
2. Build a `samlp:Response` containing a `saml:Assertion` with `ID`, `IssueInstant`, `Issuer`, a `samlp:Status`, `Conditions` with `NotBefore`/`NotOnOrAfter` and an `AudienceRestriction`, and a `SubjectConfirmationData` with `Recipient` and `InResponseTo`. `Destination` goes on the `Response`.
3. Apply the variant by changing exactly one thing — every other field stays correct, so a verifier's rejection is attributable:

| variant | change |
|---|---|
| `unsigned` | skip signing |
| `wrongKey` | sign with a second, unrelated key pair |
| `tamperedAfterSign` | sign, then alter a signed value |
| `statusFailure` | `StatusCode` = `urn:oasis:names:tc:SAML:2.0:status:Responder` |
| `expired` | `NotOnOrAfter` in the past |
| `notYetValid` | `NotBefore` in the future |
| `wrongAudience` | `Audience` = `urn:someone:else` |
| `wrongInResponseTo` | `InResponseTo` = `_not-the-request` |
| `wrongDestination` | `Destination` = `http://127.0.0.1:1/other` |
| `wrongRecipient` | `Recipient` = `http://127.0.0.1:1/other` |
| `wrongIssuer` | `Issuer` = `urn:other:idp` |

4. Base64-encode the response and render the auto-submitting form. Every value
   that lands in an attribute is escaped: `RelayState` is opaque data chosen by
   the client, and an ACS URL routinely carries a query string, so `&`, quotes
   and angle brackets all arrive in practice. Unescaped, they either corrupt the
   value or break the markup — and the browser in Task 6 would then parse
   whatever wreckage came out.

```ts
/** Escapes a value for an HTML attribute delimited by double quotes. */
function escapeAttribute(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function autoSubmitForm(acsUrl: string, samlResponse: string, relayState?: string): string {
  const relay =
    relayState === undefined
      ? ''
      : `<input type="hidden" name="RelayState" value="${escapeAttribute(relayState)}"/>`;
  return `<html><body onload="document.forms[0].submit()">
<form method="post" action="${escapeAttribute(acsUrl)}">
<input type="hidden" name="SAMLResponse" value="${escapeAttribute(samlResponse)}"/>
${relay}
</form></body></html>`;
}
```

   Escaping is also what keeps Task 6's attribute regexes sound: once no raw
   quote can appear inside a value, `value="([^"]*)"` cannot terminate early.
   Note the `undefined` check rather than a truthy one — an empty `RelayState`
   is a value the client may legitimately have sent, and dropping it silently
   would make the mock lie about what it received.

5. `repeatLastAssertion()` sets a flag that makes the next response reuse the stored `ID` instead of generating one; `lastAssertionId()` returns it.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/saml.test.ts
```

Expected: PASS, ten cases from this file.

Note what this file does **not** cover, and add it: only `wrongDestination` and
`wrongInResponseTo` have a case above, while the variants table defines eleven.
The strict-by-default rule wants one case per variant, asserting the named field
changed **and** that the neighbouring fields did not — a variant that corrupts
two things at once destroys Task 10's ability to attribute a rejection.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build
git add src/saml.ts src/__tests__/saml.test.ts
git commit -m "feat: SAML IdP returning an auto-submitting form, with corruption variants"
```

---

### Task 10: Independent verification of the corruption variants

**Files:**
- Test: `src/__tests__/samlVerification.test.ts`

**Interfaces:**
- Consumes: everything from Task 9, plus `@node-saml/node-saml`.

This is the task that decides whether the SAML mock is trustworthy. A mock that is wrong leniently produces a green suite and false confidence. So: a valid assertion must be **accepted** by a verifier we did not write, and every corruption must be **detected** — by that verifier where it checks the field, and structurally where it does not.

Note the limitation recorded in Task 8 — `node-saml` shares `xml-crypto` underneath, so this proves profile validation, not canonicalisation against a real identity provider.

**What `@node-saml/node-saml@5.1` actually does.** Its typings and its response-validation path were read while this plan was written. Configure it deliberately from this table rather than discovering each fact through one failing case at a time:

| Fact about the verifier | Consequence here |
|---|---|
| `wantAuthnResponseSigned` defaults to `true`, and Task 8 signs the **Assertion**, not the Response | set `wantAuthnResponseSigned: false` and keep `wantAssertionsSigned: true`, or every case fails alike and the suite proves nothing |
| `validateInResponseTo` defaults to `never` | set `ValidateInResponseTo.always` and seed the request ID, or `wrongInResponseTo` is accepted |
| `idpIssuer` is compared only when set | set it to `mock-idp`, or `wrongIssuer` is accepted |
| `audience` defaults to `issuer` | set both explicitly, so `wrongAudience` fails for the stated reason |
| `acceptedClockSkewMs` defaults to `0` | `expired` and `notYetValid` need no extra option |
| **`Destination` and `SubjectConfirmationData@Recipient` are never validated** — neither appears in the validation path | `wrongDestination` and `wrongRecipient` cannot be proven by rejection; they are asserted structurally |
| the request-ID cache is one-shot — a successful validation calls `removeAsync(inResponseTo)` | a second delivery of the same assertion is rejected, which is where replay gets its independent evidence |
| `InMemoryCacheProvider` is not exported from the package index | supply your own `CacheProvider`; it is three async methods |

**What this task can and cannot say about replay.** `node-saml` has no assertion-ID replay cache, and neither does anything else off the shelf — remembering assertions is the relying party's job, and building that memory is precisely what issue #19's validation strategy will do. So **no test here rejects a replay**, and none should pretend to. What is established instead is the pair of facts that make replay dangerous: both deliveries carry the same assertion ID, and each is *independently valid* — a verifier that has seen nothing accepts both. Nothing in the second message is malformed, which is exactly why only memory catches it.

There is a trap next door. node-saml's request-ID cache is one-shot: validating a response consumes its `InResponseTo`, so a second response naming the same `AuthnRequest` is rejected — **whatever its assertion ID**. That rejection says nothing about replay, and a test that read it as replay detection would stay green with `repeatLastAssertion()` deleted. The property is real and worth pinning, so it gets its own test, delivering a *fresh* assertion to show the rejection has nothing to do with the assertion at all.

- [ ] **Step 1: Write the test**

```ts
import { deflateRawSync } from 'node:zlib';
import { describe, expect, it } from '@jest/globals';
import {
  type CacheItem,
  type CacheProvider,
  SAML,
  ValidateInResponseTo,
} from '@node-saml/node-saml';
import { visit } from '../browser';
import { type SamlVariant, startMockSamlIdp } from '../saml';
import { startServer } from '../server';

const REQUEST_ID = '_req1';

/**
 * The request-ID cache node-saml needs. `InMemoryCacheProvider` exists in the
 * package but is not exported from its index, so this is the smallest thing
 * satisfying the published interface — plus `seed`, because our AuthnRequest is
 * built by hand and never passes through node-saml's own request generation.
 */
function requestIdCache(): CacheProvider & { seed(id: string): void } {
  const keys = new Map<string, CacheItem>();
  return {
    seed(id) {
      keys.set(id, { value: new Date().toISOString(), createdAt: Date.now() });
    },
    async saveAsync(key, value) {
      const item = { value, createdAt: Date.now() };
      keys.set(key, item);
      return item;
    },
    async getAsync(key) {
      return keys.get(key)?.value ?? null;
    },
    async removeAsync(key) {
      if (key === null) return null;
      return keys.delete(key) ? key : null;
    },
  };
}

/** An IdP and an ACS, wired together, able to deliver more than once. */
async function session(variant?: SamlVariant) {
  const received: Record<string, string>[] = [];
  const acs = await startServer({
    'POST /callback': (req, res) => {
      received.push(req.body);
      res.end('ok');
    },
  });
  const idp = await startMockSamlIdp(variant ? { variant } : {});
  const acsUrl = `${acs.url}/callback`;
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `ID="${REQUEST_ID}" Version="2.0" AssertionConsumerServiceURL="${acsUrl}"/>`;
  const request = deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');

  return {
    idp,
    acsUrl,
    async deliver(): Promise<string> {
      await visit(`${idp.url}/sso?SAMLRequest=${encodeURIComponent(request)}`);
      return received[received.length - 1].SAMLResponse;
    },
    async close() {
      await idp.close();
      await acs.close();
    },
  };
}

function verifier(cert: string, acsUrl: string, cacheProvider: CacheProvider): SAML {
  return new SAML({
    idpCert: cert,
    idpIssuer: 'mock-idp',
    issuer: 'mock-sp',
    audience: 'mock-sp',
    callbackUrl: acsUrl,
    wantAssertionsSigned: true,
    // Task 8 signs the Assertion, as SAP identity providers do. Left at its
    // default of true, this option would fail every case for the same reason.
    wantAuthnResponseSigned: false,
    validateInResponseTo: ValidateInResponseTo.always,
    cacheProvider,
  });
}

/** A verifier that has seen nothing yet, with the request ID it expects. */
function freshVerifier(cert: string, acsUrl: string): SAML {
  const cache = requestIdCache();
  cache.seed(REQUEST_ID);
  return verifier(cert, acsUrl, cache);
}

describe('an independent verifier judges the mock', () => {
  it('accepts the valid assertion', async () => {
    const s = await session();
    try {
      const payload = await s.deliver();
      await expect(
        freshVerifier(s.idp.certificatePem, s.acsUrl).validatePostResponseAsync({
          SAMLResponse: payload,
        }),
      ).resolves.toBeDefined();
    } finally {
      await s.close();
    }
  }, 20000);

  const rejected: SamlVariant[] = [
    'unsigned',
    'wrongKey',
    'tamperedAfterSign',
    'statusFailure',
    'expired',
    'notYetValid',
    'wrongAudience',
    'wrongInResponseTo',
    'wrongIssuer',
  ];

  for (const variant of rejected) {
    it(`rejects ${variant}`, async () => {
      const s = await session(variant);
      try {
        const payload = await s.deliver();
        await expect(
          freshVerifier(s.idp.certificatePem, s.acsUrl).validatePostResponseAsync({
            SAMLResponse: payload,
          }),
        ).rejects.toThrow();
      } finally {
        await s.close();
      }
    }, 20000);
  }

  // These two the verifier does not check at all. Asserting rejection would be
  // asserting a check that does not exist; asserting the corruption is present
  // keeps the variant honest and names the gap our own validator must close.
  // If either of these ever fails, node-saml gained a check — move the variant
  // into `rejected` above rather than relaxing the assertion.
  const unchecked: Array<{ variant: SamlVariant; field: RegExp }> = [
    { variant: 'wrongDestination', field: /Destination="([^"]*)"/ },
    { variant: 'wrongRecipient', field: /Recipient="([^"]*)"/ },
  ];

  for (const { variant, field } of unchecked) {
    it(`corrupts ${variant}, which this verifier does not examine`, async () => {
      const s = await session(variant);
      try {
        const payload = await s.deliver();
        const xml = Buffer.from(payload, 'base64').toString('utf8');
        const value = field.exec(xml)?.[1];
        expect(value).toBeTruthy();
        expect(value).not.toBe(s.acsUrl);
        await expect(
          freshVerifier(s.idp.certificatePem, s.acsUrl).validatePostResponseAsync({
            SAMLResponse: payload,
          }),
        ).resolves.toBeDefined();
      } finally {
        await s.close();
      }
    }, 20000);
  }

  // Replay, stated for exactly what can be proven here.
  //
  // No off-the-shelf verifier detects replay, because remembering assertions is
  // the relying party's job — the job issue #19 will build. What this task can
  // establish, without writing that validator, is the pair of facts that make
  // replay dangerous:
  //
  //   1. both deliveries carry the same assertion ID (structural), and
  //   2. each one is independently valid — a verifier that has seen nothing
  //      accepts both.
  //
  // Nothing in the second message is malformed. Only a memory of the first can
  // reject it, and there is nothing off the shelf that keeps one.
  it('produces two individually valid deliveries sharing one assertion ID', async () => {
    const s = await session();
    try {
      const first = await s.deliver();
      const firstId = s.idp.lastAssertionId();
      expect(firstId).toBeTruthy();

      s.idp.repeatLastAssertion();
      const second = await s.deliver();

      const assertionIdOf = (payload: string): string | undefined =>
        /<(?:\w+:)?Assertion[^>]*\bID="([^"]+)"/.exec(
          Buffer.from(payload, 'base64').toString('utf8'),
        )?.[1];

      expect(assertionIdOf(first)).toBe(firstId);
      expect(assertionIdOf(second)).toBe(firstId);

      // Judged alone, each is beyond reproach — including the replay.
      await expect(
        freshVerifier(s.idp.certificatePem, s.acsUrl).validatePostResponseAsync({
          SAMLResponse: first,
        }),
      ).resolves.toBeDefined();
      await expect(
        freshVerifier(s.idp.certificatePem, s.acsUrl).validatePostResponseAsync({
          SAMLResponse: second,
        }),
      ).resolves.toBeDefined();
    } finally {
      await s.close();
    }
  }, 30000);

  // A neighbouring property, easy to mistake for replay detection and not the
  // same thing. node-saml's request-ID cache is one-shot: a successful
  // validation consumes the InResponseTo, so any later response naming the same
  // AuthnRequest is rejected — whatever its assertion ID. Pinned here precisely
  // so nobody reads it as evidence about assertions. Note the second delivery
  // is a *fresh* assertion, and is refused all the same.
  it('consumes the request ID, rejecting a second response to one AuthnRequest', async () => {
    const s = await session();
    try {
      const cache = requestIdCache();
      cache.seed(REQUEST_ID);
      const remembers = verifier(s.idp.certificatePem, s.acsUrl, cache);

      await expect(
        remembers.validatePostResponseAsync({ SAMLResponse: await s.deliver() }),
      ).resolves.toBeDefined();
      const firstId = s.idp.lastAssertionId();

      const another = await s.deliver();
      expect(s.idp.lastAssertionId()).not.toBe(firstId);
      await expect(
        remembers.validatePostResponseAsync({ SAMLResponse: another }),
      ).rejects.toThrow();
    } finally {
      await s.close();
    }
  }, 30000);
});
```

- [ ] **Step 2: Run it**

```bash
npm test -- src/__tests__/samlVerification.test.ts
```

Expected: PASS — one valid case, nine rejections, two structural cases, the replay pair, and the request-ID case.

**Prove the replay pair is load-bearing.** Delete the `s.idp.repeatLastAssertion()`
call and rerun: `expect(assertionIdOf(second)).toBe(firstId)` must go red. An
earlier draft of this plan asserted replay through a verifier that was actually
rejecting a consumed request ID — it passed with `repeatLastAssertion()` removed
entirely, and claimed a property it never tested. Run the mutation.

**A variant behaving unexpectedly is the finding this task exists for.** Do not weaken an assertion to make the suite green. If a variant in `rejected` is accepted, establish which side is wrong — the mock producing a corruption the verifier does not check, or our understanding of what the variant should break — and report it. Moving a variant from `rejected` into `unchecked` is a legitimate outcome **only** with the verifier's source cited for why the field is not examined; silently dropping one is not.

- [ ] **Step 3: Commit**

```bash
npm run lint:check && npm run build && npm test
git add src/__tests__/samlVerification.test.ts
git commit -m "test: an independent verifier accepts the valid assertion and rejects each variant"
```

---

### Task 11: Public surface, README, and the release PR

**Files:**
- Modify: `src/index.ts`, `README.md`, `CHANGELOG.md`

**Interfaces:**
- Produces: the package's entire public API.

- [ ] **Step 1: Write `src/index.ts`**

```ts
/**
 * Mock authorization servers for testing @mcp-abap-adt packages.
 *
 * Everything here starts and stops inside a test. Nothing imports the packages
 * this exists to test: a mock that knows those types would eventually agree
 * with their mistakes instead of catching them.
 */

export { visit } from './browser';
export type { VisitResult } from './browser';
export { startMockOidc } from './oidc';
export type { OidcOptions } from './oidc';
export { startMockSamlIdp } from './saml';
export type { MockSamlIdp, SamlOptions, SamlVariant } from './saml';
export type { MockHandle, RecordedRequest } from './server';
export { generateKeyMaterial, signXml } from './signing';
export type { KeyMaterial } from './signing';
export { startMockUaa } from './uaa';
export type { MockUaa, UaaOptions } from './uaa';
```

Remove `AUTH_MOCKS_VERSION` — the placeholder from Task 1 has served its purpose, and every exported name is a permanent obligation.

- [ ] **Step 2: Write the README**

Cover: what the package is for; the `visit` + `openUrl` wiring with the worked example from the spec; that mocks are strict by default and what each refuses — including that a code or refresh token is bound to the client it was issued to; the SAML variants table, marking the two no independent verifier judges; the two-step shape of replay and why an off-the-shelf verifier cannot catch it; the `samlBearer: 'strict'` note about RFC 7522 and what a failure there means; and the verification limitation from Task 8. Keep the "these do not replace live testing" statement prominent — in six months someone will otherwise conclude that live runs are obsolete.

- [ ] **Step 3: Write the CHANGELOG**

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - <date>

### Added

- `startMockUaa` — authorization code, refresh with configurable rotation and
  reuse detection, and the SAML bearer grant with a strict RFC 7522 mode.
- `startMockOidc` — discovery, PKCE demanded at `/authorize` and verified at
  `/token`, and `state` mirrored rather than judged.
- `startMockSamlIdp` — signs with a per-instance certificate, returns an
  auto-submitting form for the browser to deliver, and can violate one rule at a
  time across eleven variants.
- `visit` — a fake browser that follows redirects and submits forms, wired into
  a strategy through `openUrl`.
```

- [ ] **Step 4: Verify everything**

```bash
npm run lint:check && npm run build && npm test
```

Expected: green, every suite.

- [ ] **Step 5: Commit, push, open the PR — then stop**

```bash
git add -A
git commit -m "release(0.1.0): mock authorization servers"
git push -u origin feat/initial-implementation
gh pr create --title "release(0.1.0): mock authorization servers" --body "<summary>"
```

**Do not merge, do not tag, do not publish.** The PR is reviewed first; the merge, the tag and the publish belong to the repository owner.

---

## After the merge

Consumers adopt the package in separate PRs, one per repository, so each review stays readable:

- `auth-providers` — replace the hand-written guards' tests with flows through the mocks; add the ephemeral-port round trip that has never been tested.
- `proxy` — delete the one-endpoint stub in `callbackPortLifecycle.test.ts` and drive a login through the CLI end to end.
- `auth-broker` — flow-level tests for `mcp-auth` and `mcp-sso`, including the `--config` path.

Two findings this package is expected to surface, both belonging to later cycles rather than this one:

- `OidcBrowserProvider` sends no `state`, so a test written against the OIDC mock will show a CSRF exposure that is currently invisible.
- `exchangeSamlAssertion` forwards a base64 `samlp:Response` where RFC 7522 wants a base64url `Assertion`; `samlBearer: 'strict'` will say so.
