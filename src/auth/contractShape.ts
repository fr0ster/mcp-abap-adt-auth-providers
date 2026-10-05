/**
 * The shape of a contract object as this package has always built it.
 *
 * `@mcp-abap-adt/interfaces-auth` declares its optional fields `?: T`, which
 * under `exactOptionalPropertyTypes` means "absent, never `undefined`". This
 * package hands those objects out with an optional field that has no value
 * present and set to `undefined` (`refreshToken: undefined`), and a consumer
 * may depend on the key being there: the broker and the stores merge them,
 * `{ ...stored, ...result }`. The key's presence is behaviour, kept as it was.
 */

/** `T` whose optional fields may also hold an explicit `undefined`. */
export type WithUndefined<T> = {
  [K in keyof T]: T[K] | (undefined extends T[K] ? undefined : never);
};

/**
 * The contract type of an object built with explicit `undefined`s. The one
 * assertion between the two shapes: every field still has the contract's
 * type, and no field is added or dropped.
 */
export function asContract<T>(value: WithUndefined<T>): T {
  return value as T;
}
