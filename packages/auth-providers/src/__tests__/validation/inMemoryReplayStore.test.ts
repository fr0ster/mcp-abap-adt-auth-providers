import { describe, expect, it } from '@jest/globals';
import { createInMemoryReplayStore } from '../../validation/inMemoryReplayStore';

const future = () => new Date(Date.now() + 60_000);

describe('createInMemoryReplayStore', () => {
  it('records an unseen key and reports it as new', async () => {
    const store = createInMemoryReplayStore();
    expect(
      await store.recordIfUnseen(
        { issuer: 'idp', assertionId: '_a' },
        future(),
      ),
    ).toBe(true);
  });

  it('reports the second sighting of the same key as a replay', async () => {
    const store = createInMemoryReplayStore();
    const key = { issuer: 'idp', assertionId: '_a' };
    await store.recordIfUnseen(key, future());
    expect(await store.recordIfUnseen(key, future())).toBe(false);
  });

  // The reason the key is a pair: two identity providers may legitimately mint
  // the same ID, and refusing the second is a working login broken, not an
  // attack stopped.
  it('keeps two issuers apart when they mint the same ID', async () => {
    const store = createInMemoryReplayStore();
    expect(
      await store.recordIfUnseen(
        { issuer: 'a', assertionId: '_same' },
        future(),
      ),
    ).toBe(true);
    expect(
      await store.recordIfUnseen(
        { issuer: 'b', assertionId: '_same' },
        future(),
      ),
    ).toBe(true);
  });

  it('forgets an entry once its retention has passed', async () => {
    const store = createInMemoryReplayStore();
    const key = { issuer: 'idp', assertionId: '_a' };
    await store.recordIfUnseen(key, new Date(Date.now() - 1));
    expect(await store.recordIfUnseen(key, future())).toBe(true);
  });

  // Concurrency: a check followed by a separate write is the race a replay
  // exploits, so exactly one of two simultaneous calls may be told `true`.
  it('lets only one of two simultaneous calls record the key', async () => {
    const store = createInMemoryReplayStore();
    const key = { issuer: 'idp', assertionId: '_a' };
    const results = await Promise.all([
      store.recordIfUnseen(key, future()),
      store.recordIfUnseen(key, future()),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('gives each store its own memory', async () => {
    const key = { issuer: 'idp', assertionId: '_a' };
    await createInMemoryReplayStore().recordIfUnseen(key, future());
    expect(
      await createInMemoryReplayStore().recordIfUnseen(key, future()),
    ).toBe(true);
  });
});
