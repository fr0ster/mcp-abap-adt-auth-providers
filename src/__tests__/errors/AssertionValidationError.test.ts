import { describe, expect, it } from '@jest/globals';
import { AssertionValidationError } from '../../errors/AssertionValidationError';
import { TokenProviderError } from '../../errors/TokenProviderErrors';

describe('AssertionValidationError', () => {
  it('is a TokenProviderError', () => {
    const error = new AssertionValidationError('status', 'the IdP declined');
    expect(error).toBeInstanceOf(TokenProviderError);
    expect(error).toBeInstanceOf(Error);
  });

  it('carries the failed check as a field, not only in the message', () => {
    const error = new AssertionValidationError(
      'audience',
      'not addressed to us',
    );
    expect(error.check).toBe('audience');
    expect(error.message).toContain('not addressed to us');
  });

  it('keeps a stack', () => {
    expect(
      new AssertionValidationError('replay', 'seen before').stack,
    ).toBeTruthy();
  });
});
