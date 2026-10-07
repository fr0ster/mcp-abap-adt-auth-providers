/**
 * Spec §4.4 / §6b (Task 27 review): a cache hit while a refresh token is
 * quarantined — cut after its refresh was dispatched, its clearing step still
 * queued behind a stalled `onTokens` — never hands that refresh token out,
 * and says `'clear'`: the token was cut, so a stored copy must go.
 *
 * Scenario (the reviewer's q.cjs):
 *   1. a login installs R0; a refresh of R0 answers T1 / R1, and that
 *      commit's `onTokens` stalls;
 *   2. the first refresh's waiter aborts;
 *   3. a second refresh dispatches R1 (it never answers) and its waiter
 *      aborts: R1 is quarantined, `discard(R1)` waits in the queue;
 *   4. `getTokens()` hits the cache (T1 is valid).
 */

import { describe, expect, it } from '@jest/globals';
import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { BaseTokenProvider } from '../../providers/BaseTokenProvider';
import { refreshThenLogin } from '../../renewal';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (n: string) =>
  `${b64({ alg: 'none' })}.${b64({ exp: Math.floor(Date.now() / 1000) + 3600, n })}.x`;
const turn = () => new Promise<void>((resolve) => setImmediate(resolve));
async function turns(n: number): Promise<void> {
  for (let i = 0; i < n; i++) await turn();
}

class Stalling extends BaseTokenProvider {
  readonly told: string[] = [];
  stall = false;
  release: (() => void) | undefined;
  constructor() {
    super({
      renewal: refreshThenLogin(),
      onTokens: async (r) => {
        this.told.push(`${r.refreshTokenDisposition}:${r.refreshToken}`);
        if (this.stall) {
          this.stall = false;
          await new Promise<void>((resolve) => {
            this.release = resolve;
          });
        }
      },
    });
  }
  protected getAuthType(): OAuth2GrantType {
    return 'authorization_code';
  }
  protected async performLogin(): Promise<ITokenResult> {
    return {
      authorizationToken: jwt('L'),
      refreshToken: 'R0',
      authType: 'authorization_code',
    };
  }
  protected performRefresh(
    refreshToken: string,
    _signal: AbortSignal,
    dispatched: () => void,
  ): Promise<ITokenResult> {
    // The request leaves: the site would call this right before it.
    dispatched();
    if (refreshToken === 'R0') {
      return Promise.resolve({
        authorizationToken: jwt('T1'),
        refreshToken: 'R1',
        authType: 'authorization_code',
      });
    }
    return new Promise<ITokenResult>(() => undefined);
  }
}

describe('a cache hit while the held refresh token is quarantined', () => {
  it('hands out no refresh token and says clear, before and after the queue drains', async () => {
    const p = new Stalling();
    await p.getTokens(); // R0 held
    p.stall = true;
    const first = new AbortController();
    const a = p.refreshTokens({ signal: first.signal }).catch(() => 'aborted');
    await turns(10);
    first.abort();
    expect(await a).toBe('aborted');
    const second = new AbortController();
    const b = p.refreshTokens({ signal: second.signal }).catch(() => 'aborted');
    await turns(10);
    second.abort();
    expect(await b).toBe('aborted');

    const hit = await p.getTokens();
    expect(Object.hasOwn(hit, 'refreshToken')).toBe(true);
    expect(hit.refreshToken).toBeUndefined();
    expect(hit.refreshTokenDisposition).toBe('clear');

    p.release?.();
    await turns(10);
    const drained = await p.getTokens();
    expect(drained.refreshToken).toBeUndefined();
    expect(drained.refreshTokenDisposition).toBe('clear');
    expect(p.told).toContain('clear:undefined');
  });
});
