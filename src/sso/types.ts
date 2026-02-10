import type { ITokenProvider } from '@mcp-abap-adt/interfaces';
import type { OidcBrowserProviderConfig } from '../providers/OidcBrowserProvider';
import type { OidcDeviceFlowProviderConfig } from '../providers/OidcDeviceFlowProvider';
import type { OidcPasswordProviderConfig } from '../providers/OidcPasswordProvider';
import type { OidcTokenExchangeProviderConfig } from '../providers/OidcTokenExchangeProvider';
import type { Saml2BearerProviderConfig } from '../providers/Saml2BearerProvider';
import type { Saml2PureProviderConfig } from '../providers/Saml2PureProvider';

export type SsoProviderInstance = ITokenProvider;

export type SsoProviderConfig =
  | {
      protocol: 'oidc';
      flow: 'browser';
      config: OidcBrowserProviderConfig;
    }
  | {
      protocol: 'oidc';
      flow: 'device';
      config: OidcDeviceFlowProviderConfig;
    }
  | {
      protocol: 'oidc';
      flow: 'password';
      config: OidcPasswordProviderConfig;
    }
  | {
      protocol: 'oidc';
      flow: 'token_exchange';
      config: OidcTokenExchangeProviderConfig;
    }
  | {
      protocol: 'saml2';
      flow: 'bearer';
      config: Saml2BearerProviderConfig;
    }
  | {
      protocol: 'saml2';
      flow: 'pure';
      config: Saml2PureProviderConfig;
    };
