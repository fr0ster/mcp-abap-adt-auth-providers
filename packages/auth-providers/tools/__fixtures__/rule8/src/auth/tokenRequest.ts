// Rule 8's own site: legacyBasic in src/auth/tokenRequest.ts may write the
// Basic header. Must pass.
export function legacyBasic(clientId: string, clientSecret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
}
