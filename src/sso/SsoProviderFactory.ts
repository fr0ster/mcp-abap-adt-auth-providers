import { authError } from '@mcp-abap-adt/auth-errors';
import type { IRefreshableTokenProvider } from '@mcp-abap-adt/interfaces-auth';
import { misconfigured, ownOptions } from '../auth/configuration';
import { OidcBrowserProvider } from '../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../providers/Saml2PureProvider';
import type { SsoProviderConfig } from './types';

/**
 * Builds the provider a protocol and flow name. A class holding only a static
 * member — biome's noStaticOnlyClass is off for this file (biome.json) — kept
 * a class because it is public: a patch does not change a public type.
 */
export class SsoProviderFactory {
  static create(options: SsoProviderConfig): IRefreshableTokenProvider {
    // Read once as own data: a hostile object throws nothing of its own.
    const config = ownOptions<SsoProviderConfig>(options);
    if (config.protocol === 'oidc') {
      if (config.flow === 'browser') {
        return new OidcBrowserProvider(config.config);
      }
      if (config.flow === 'device') {
        return new OidcDeviceFlowProvider(config.config);
      }
      if (config.flow === 'password') {
        return new OidcPasswordProvider(config.config);
      }
      if (config.flow === 'token_exchange') {
        return new OidcTokenExchangeProvider(config.config);
      }
    }

    if (config.protocol === 'saml2') {
      if (config.flow === 'bearer') {
        return new Saml2BearerProvider(config.config);
      }
      if (config.flow === 'pure') {
        return new Saml2PureProvider(config.config);
      }
    }

    // E23. Fixed words: the config holds the client secret, a password,
    // tokens — and neither protocol nor flow is echoed.
    throw misconfigured(
      authError.configuration({ case: 'unsupported-sso-flow', fields: [] }),
    );
  }
}
