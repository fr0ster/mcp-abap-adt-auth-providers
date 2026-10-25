/**
 * Type test, compiled by `test:check` and run by nothing: the
 * persistence strategy replaces `onTokens`, and the refresh-token
 * disposition is gone — from the configuration, from what the provider
 * returns, and from the module that bridged it.
 */

import type { ITokenResult } from '@mcp-abap-adt/interfaces-auth';
import type { TokenProviderHooks } from '../../index';
import { refreshStatePersistence, refreshThenLogin } from '../../index';
import type * as Base from '../../providers/BaseTokenProvider';

// A persistence strategy is configured as `persistence`.
export const configured: TokenProviderHooks = {
  renewal: refreshThenLogin(),
  persistence: refreshStatePersistence(async () => undefined, {
    onWriteFailure: 'continue',
  }),
};

export const hook: TokenProviderHooks = {
  renewal: refreshThenLogin(),
  // @ts-expect-error onTokens is gone: persistence takes its place
  onTokens: async () => undefined,
};

// @ts-expect-error onWriteFailure is required, with no default
export const noChoice = refreshStatePersistence(async () => undefined, {});

// @ts-expect-error the bridge type is gone
export type Bridged = Base.BridgedTokenResult;

// @ts-expect-error the bridge type is gone
export type Disposition = Base.RefreshTokenDisposition;

// @ts-expect-error a token result carries no disposition
export type Carried = ITokenResult['refreshTokenDisposition'];
