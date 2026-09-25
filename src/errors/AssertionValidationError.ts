/**
 * An assertion was refused, and by which check.
 *
 * The check is a field rather than something to read out of the message: a
 * consumer telling "your identity provider declined" from "this was not
 * addressed to us" should not be parsing prose to do it.
 */

import { ASSERTION_ERROR_CODES } from '@mcp-abap-adt/interfaces-auth';
import { TokenProviderError } from './TokenProviderErrors';

/** The checks the shipped validator performs, in the order it performs them. */
export type AssertionCheck =
  | 'document'
  | 'duplicateId'
  | 'signature'
  | 'signedNode'
  | 'status'
  | 'assertionId'
  | 'issuer'
  | 'conditions'
  | 'notBefore'
  | 'notOnOrAfter'
  | 'audience'
  | 'bearerConfirmation'
  | 'destination'
  | 'replay';

export class AssertionValidationError extends TokenProviderError {
  readonly check: AssertionCheck;

  constructor(check: AssertionCheck, message: string) {
    super(message, ASSERTION_ERROR_CODES.VALIDATION_ERROR);
    this.name = 'AssertionValidationError';
    this.check = check;
    // Every sibling in TokenProviderErrors.ts does this; without it
    // `instanceof` fails across a compiled boundary.
    Object.setPrototypeOf(this, AssertionValidationError.prototype);
  }
}
