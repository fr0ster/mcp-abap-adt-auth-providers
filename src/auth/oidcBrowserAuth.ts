/**
 * OIDC browser authorization code flow (capture code)
 */

import type {
  CallbackServerFactory,
  ICallbackServerHandle,
  ICallbackServerOptions,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthorizationRefusedError } from './callbackScopeError';
import {
  errorHtml,
  runCallbackScope,
  sendHtml,
  sendText,
} from './callbackServer';

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
        const { error, error_description } = req.query;
        if (error) {
          const message = error_description
            ? `${String(error)}: ${String(error_description)}`
            : String(error);
          // The IdP's text is attacker-controllable: escaped in an HTML page.
          sendHtml(res, 400, errorHtml(message));
          // The registered code only: the description and error_uri are
          // anyone's text (a link to the local callback carries them).
          settle.err(new AuthorizationRefusedError(error), res);
          return;
        }

        const code = req.query.code;
        const state = req.query.state;
        if (!code || typeof code !== 'string') {
          sendText(res, 400, 'Error: not an authorization callback');
          settle.ignore('no code and no error in query', res);
          return;
        }

        sendText(
          res,
          200,
          'Authentication complete. You can close this window.',
        );
        settle.ok(
          { code, state: typeof state === 'string' ? state : undefined },
          res,
        );
      });
    },
    use,
  );
