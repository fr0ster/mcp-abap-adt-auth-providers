/** What this package knows about the SAP Secure Login Client's installation. */
export const SECURE_LOGIN_CLIENT = 'SAP Secure Login Client';
/** Holds InstallPath64 / InstallPath32, each ending in a separator. */
export const SLC_REGISTRY_KEY = 'HKLM\\Software\\SAP\\SecureLogin';
export const MACOS_SLC_APP = '/Applications/Secure Login Client.app/';
export const MACOS_SLC_LIBRARY =
  '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib';
