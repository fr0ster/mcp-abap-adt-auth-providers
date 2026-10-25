// Rule 8 (src/auth): a Basic authorization value outside legacyBasic. Must
// be found.
export function header(credential: string): Record<string, string> {
  return { Authorization: `Basic ${credential}` };
}
