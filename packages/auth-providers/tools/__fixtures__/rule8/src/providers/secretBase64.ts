// Rule 8 (src/providers): a base64 encoding of a client secret outside
// clientSecretBasic. Must be found.
export function encoded(clientId: string, clientSecret: string): string {
  return Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
}
