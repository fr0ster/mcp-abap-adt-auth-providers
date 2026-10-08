/**
 * Authorization by composition: the parts — presentations,
 * transports, protocols — and the composer that joins them.
 */

export {
  type ComposedAuthorization,
  type ComposedStrategy,
  composeAuthorization,
} from './compose';
export * from './presentation';
export * from './protocol';
export * from './transport';
