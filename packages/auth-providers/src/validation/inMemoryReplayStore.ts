/**
 * Remembering assertions so a replay is refused.
 *
 * In memory, and therefore per process. That is honest rather than sufficient:
 * a deployment running several processes needs a shared store, which is why
 * the interface exists at all. What this must not be is per provider instance —
 * a store an attacker escapes by causing a second provider to be constructed
 * is no store.
 *
 * Pruning is lazy, on access, so nothing here holds a timer and nothing needs
 * disposing.
 */

import type {
  AssertionReplayKey,
  IAssertionReplayStore,
} from '@mcp-abap-adt/interfaces-auth';

const compositeKey = (key: AssertionReplayKey): string =>
  // The issuer is length-prefixed so that two different pairs cannot collide
  // by putting the separator inside an identifier.
  `${key.issuer.length}:${key.issuer}:${key.assertionId}`;

/** A store of its own, for a test or a consumer wanting isolation. */
export function createInMemoryReplayStore(): IAssertionReplayStore {
  const seen = new Map<string, number>();

  return {
    async recordIfUnseen(key, retainUntil) {
      const now = Date.now();

      // Lazy prune: drop everything whose retention has passed, so the map
      // cannot grow without bound and no timer is needed.
      for (const [existing, until] of seen) {
        if (until <= now) seen.delete(existing);
      }

      const composite = compositeKey(key);
      if (seen.has(composite)) return false;

      // Nothing awaits between the check and the write, so this is atomic
      // against other callers on the same event loop. A shared-store
      // implementation must achieve the same with a conditional write.
      seen.set(composite, retainUntil.getTime());
      return true;
    },
  };
}

/**
 * The store the shipped validator uses when the consumer supplies none.
 *
 * Module-level, so every default validator in the process shares it.
 */
export const defaultReplayStore: IAssertionReplayStore =
  createInMemoryReplayStore();
