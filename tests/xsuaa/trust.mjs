// Creates, refreshes or deletes the SAML trust to the test identity provider,
// through the Authorization and Trust Management API of the xsuaa/apiaccess
// key setup.sh saved. `btp create security/trust` only trusts SAP Cloud
// Identity Services tenants, so a custom SAML IdP goes through this API.
//
//   node trust.mjs create|delete <local-dir> <origin>
import fs from 'node:fs';
import path from 'node:path';

const [action, localDir, origin] = process.argv.slice(2);
const read = (file) => fs.readFileSync(path.join(localDir, file), 'utf8');
const key = JSON.parse(read('api-key.json'));
const c = key.credentials ?? key;

const token = (
  await (
    await fetch(`${c.url}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${Buffer.from(`${c.clientid}:${c.clientsecret}`).toString('base64')}`,
      },
      body: 'grant_type=client_credentials',
    })
  ).json()
).access_token;
const headers = {
  Authorization: `Bearer ${token}`,
  'Content-Type': 'application/json',
  Accept: 'application/json',
};
const api = `${c.apiurl}/sap/rest/identity-providers`;
const existing = (await (await fetch(api, { headers })).json()).find(
  (p) => p.originKey === origin,
);

if (action === 'delete') {
  if (!existing) {
    console.log(`trust ${origin}: not present`);
  } else {
    const r = await fetch(`${api}/${existing.id}`, { method: 'DELETE', headers });
    if (!r.ok) throw new Error(`delete trust: ${r.status} ${await r.text()}`);
    console.log(`trust ${origin}: deleted`);
  }
} else if (action === 'create') {
  const cert = read('idp.crt').trim().split('\n').slice(1, -1).join('');
  const metadata =
    `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${origin}">` +
    '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
    '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>' +
    `<ds:X509Certificate>${cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
    '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>' +
    `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${origin}.invalid/sso"/>` +
    '</md:IDPSSODescriptor></md:EntityDescriptor>';
  const body = {
    type: 'saml',
    originKey: origin,
    name: 'auth-providers test IdP (created by tests/xsuaa, removed by teardown.sh)',
    active: true,
    config: JSON.stringify({
      metaDataLocation: metadata,
      idpEntityAlias: origin,
      nameID: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
      assertionConsumerIndex: 0,
      metadataTrustCheck: false,
      showSamlLink: false,
      addShadowUserOnLogin: true,
    }),
  };
  const r = await fetch(existing ? `${api}/${existing.id}` : api, {
    method: existing ? 'PUT' : 'POST',
    headers,
    body: JSON.stringify(existing ? { ...body, id: existing.id } : body),
  });
  if (!r.ok) throw new Error(`create trust: ${r.status} ${await r.text()}`);
  console.log(`trust ${origin}: ${existing ? 'refreshed' : 'created'}`);
} else {
  throw new Error(`unknown action ${action}`);
}
