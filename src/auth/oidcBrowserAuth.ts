/**
 * OIDC browser authorization code flow (capture code)
 */

import type {
  CallbackServerFactory,
  ICallbackServerHandle,
  ICallbackServerOptions,
} from '@mcp-abap-adt/interfaces';
import { runCallbackScope } from './callbackServer';

export interface OidcCallbackResult {
  code: string;
  state?: string;
}

export const withOidcCallbackServer: CallbackServerFactory<
  OidcCallbackResult
> = <TReturn>(
  options: ICallbackServerOptions,
  use: (server: ICallbackServerHandle<OidcCallbackResult>) => Promise<TReturn>,
): Promise<TReturn> =>
  runCallbackScope<OidcCallbackResult, TReturn>(
    options,
    (app, settle) => {
      app.get('/callback', (req, res) => {
        // An IdP that declines says so explicitly. That is a finished login,
        // not a stray request, and it must not wait for the timeout.
        const { error, error_description, error_uri } = req.query;
        if (error) {
          const message = error_description
            ? `${String(error)}: ${String(error_description)}`
            : String(error);
          res.status(400).send(`Authentication failed: ${message}`);
          settle.err(
            new Error(
              `OIDC authentication failed: ${message}` +
                (error_uri ? ` (${String(error_uri)})` : ''),
            ),
            res,
          );
          return;
        }

        const code = req.query.code;
        const state = req.query.state;
        if (!code || typeof code !== 'string') {
          res.status(400).send('Error: not an authorization callback');
          settle.ignore('no code and no error in query', res);
          return;
        }

        res
          .status(200)
          .send('Authentication complete. You can close this window.');
        settle.ok(
          { code, state: typeof state === 'string' ? state : undefined },
          res,
        );
      });
    },
    use,
  );
