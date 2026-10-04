import { describe, expect, it } from '@jest/globals';
import {
  clientSecretBasic,
  clientSecretPost,
  noClientAuthentication,
} from '../../clientAuthentication';

const draft = {
  endpoint: 'https://uaa.example/oauth/token',
  clientId: 'my-client',
  grantType: 'client_credentials',
};

describe('noClientAuthentication', () => {
  it('sends client_id in the body and nothing else', async () => {
    const sent = await noClientAuthentication().authenticate(draft);
    expect(sent).toEqual({ parameters: { client_id: 'my-client' } });
  });
  it('presents no TLS material', () => {
    expect(noClientAuthentication().tlsMaterial).toBeUndefined();
  });
});

describe('clientSecretBasic', () => {
  it('sends Basic base64(id:secret) and no body parameters', async () => {
    const sent = await clientSecretBasic('s3cr:et').authenticate(draft);
    expect(sent).toEqual({
      headers: {
        Authorization: `Basic ${Buffer.from('my-client:s3cr:et').toString('base64')}`,
      },
    });
  });
  it('presents no TLS material', () => {
    expect(clientSecretBasic('x').tlsMaterial).toBeUndefined();
  });
});

describe('clientSecretPost', () => {
  it('sends client_id and client_secret in the body and no header', async () => {
    const sent = await clientSecretPost('s3cret').authenticate(draft);
    expect(sent).toEqual({
      parameters: { client_id: 'my-client', client_secret: 's3cret' },
    });
  });
  it('presents no TLS material', () => {
    expect(clientSecretPost('x').tlsMaterial).toBeUndefined();
  });
});
