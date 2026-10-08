/**
 * The pages a callback listener serves (spec §6d.3.4, §6d.3.5): fixed
 * markup, every interpolated value through `escapeHtml`, and the policy
 * every response carries.
 */

import type { PasteWords } from '@mcp-abap-adt/interfaces-auth';

/**
 * Every response: a policy that runs no script, loads nothing and submits
 * only to this listener (the paste form). Inline style is the pages' only
 * need.
 */
export const CALLBACK_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/** `&`, `<`, `>`, `"` and `'` as entities: a value in a page is text, never markup. */
export function escapeHtml(value: string): string {
  // Plain code, no regex: the value is callback text, anyone's.
  let escaped = '';
  for (const character of value) escaped += ENTITIES[character] ?? character;
  return escaped;
}

const ENTITIES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** The one success page, for every protocol. */
export const successHtml = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAP BTP Authentication</title>
<style>body{font-family:'Segoe UI',Tahoma,sans-serif;text-align:center;padding:50px 20px;background:linear-gradient(135deg,#0070f3,#00d4ff);color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,.1);border-radius:20px;padding:40px;max-width:500px}.success-icon{font-size:4rem;margin-bottom:20px;color:#4ade80}h1{font-weight:300}</style>
</head><body><div class="container"><div class="success-icon">✓</div>
<h1>Authentication Successful!</h1>
<p>You have successfully authenticated with SAP BTP. You can close this window.</p>
</div></body></html>`;

/** `message` may be the IdP's (attacker-controllable) text: escaped here. */
export const errorHtml = (message: string): string => `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Authentication Error</title>
<style>body{font-family:'Segoe UI',Tahoma,sans-serif;text-align:center;padding:50px 20px;background:linear-gradient(135deg,#dc2626,#ef4444);color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,.1);border-radius:20px;padding:40px;max-width:500px}.error-icon{font-size:4rem;margin-bottom:20px;color:#fbbf24}h1{font-weight:300}</style>
</head><body><div class="container"><div class="error-icon">✗</div>
<h1>Authentication Failed</h1>
<p>${escapeHtml(message)}</p>
<p>Please check your service key configuration and try again.</p>
</div></body></html>`;

/**
 * The paste page (spec §6d.3.4): the protocol's words, escaped, and this
 * attempt's form token as a hidden field. It posts to `/submit`; another
 * origin cannot read the page (no CORS, the CSP) to learn the token.
 */
export const pastePageHtml = (
  formToken: string,
  words: PasteWords,
  message?: string,
): string => `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAP BTP Authentication — paste</title>
<style>body{font-family:'Segoe UI',Tahoma,sans-serif;text-align:center;padding:50px 20px;background:linear-gradient(135deg,#0070f3,#00d4ff);color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,.1);border-radius:20px;padding:40px;max-width:560px;width:100%}h1{font-weight:300}textarea{width:100%;min-height:6em;padding:12px;border-radius:8px;border:none;font-size:1rem;box-sizing:border-box;margin:14px 0}button{padding:12px 24px;border-radius:8px;border:none;background:#fff;color:#0070f3;font-size:1rem;cursor:pointer}.msg{color:#fde68a;margin-bottom:10px}</style>
</head><body><div class="container">
<h1>Paste the answer</h1>
${message === undefined ? '' : `<p class="msg">${escapeHtml(message)}</p>`}
<p>${escapeHtml(words.instructions)}</p>
<form action="/submit" method="post">
<input type="hidden" name="form_token" value="${escapeHtml(formToken)}" />
<label for="input">${escapeHtml(words.prompt)}</label>
<textarea id="input" name="input" autofocus></textarea>
<button type="submit">Submit</button>
</form></div></body></html>`;
