import type { IRefreshableTokenProvider } from '@mcp-abap-adt/interfaces-auth';
import { OidcBrowserProvider } from '../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../providers/Saml2PureProvider';
import type { SsoProviderConfig } from './types';

/** The `never` default of `create`'s switches: the compiler proves no protocol or flow is left. */
function unreachable(config: never): never {
  return config;
}

/**
 * Builds the provider a protocol and flow name. A class holding only a static
 * member — biome's noStaticOnlyClass is off for this file (biome.json) — kept
 * a class because it is public: a patch does not change a public type.
 */
export class SsoProviderFactory {
  static create(options: SsoProviderConfig): IRefreshableTokenProvider {
    // A typed copy: the options are read once, here.
    const config = { ...options };
    switch (config.protocol) {
      case 'oidc':
        switch (config.flow) {
          case 'browser':
            return new OidcBrowserProvider(config.config);
          case 'device':
            return new OidcDeviceFlowProvider(config.config);
          case 'password':
            return new OidcPasswordProvider(config.config);
          case 'token_exchange':
            return new OidcTokenExchangeProvider(config.config);
          default:
            return unreachable(config);
        }
      case 'saml2':
        switch (config.flow) {
          case 'bearer':
            return new Saml2BearerProvider(config.config);
          case 'pure':
            return new Saml2PureProvider(config.config);
          default:
            return unreachable(config);
        }
      default:
        return unreachable(config);
    }
  }
}
