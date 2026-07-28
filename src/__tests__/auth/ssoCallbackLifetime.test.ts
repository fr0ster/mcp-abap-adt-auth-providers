/**
 * Lifetime of the OIDC and SAML callback servers.
 *
 * Neither flow had a timeout: an abandoned login never settled, so the port was
 * held for the life of the process. These are the regressions for that.
 *
 * Ports are asserted by binding — the code being replaced logs nothing useful
 * about release, and log output would not prove it anyway.
 */

import net from 'node:net';
import { describe, expect, it } from '@jest/globals';
import { startOidcBrowserAuth } from '../../auth/oidcBrowserAuth';
import { startSamlBrowserAuth } from '../../auth/saml2Auth';

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

describe('SSO callback lifetime', () => {
  it('releases the OIDC port when the login is abandoned', async () => {
    const PORT = 7873;
    const login = startOidcBrowserAuth(
      'http://127.0.0.1:9/authorize',
      'none',
      undefined,
      PORT,
      300,
    );
    const rejected = expect(login).rejects.toThrow(/timeout/i);
    await rejected;
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);

  it('releases the SAML port when the login is abandoned', async () => {
    const PORT = 7874;
    const login = startSamlBrowserAuth(
      {
        idpSsoUrl: 'http://127.0.0.1:9/sso',
        spEntityId: 'test-sp',
        acsUrl: 'http://127.0.0.1:7874/callback',
      },
      'none',
      undefined,
      PORT,
      300,
    );
    const rejected = expect(login).rejects.toThrow(/timeout/i);
    await rejected;
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);
});
