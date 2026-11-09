import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createInMemoryReplayStore } from '../../validation/inMemoryReplayStore';

const future = () => new Date(Date.now() + 60_000);

describe('createInMemoryReplayStore', () => {
  it('records an unseen key and reports it as new', async () => {
    const store = createInMemoryReplayStore();
    assert.equal(
      await store.recordIfUnseen(
        { issuer: 'idp', assertionId: '_a' },
        future(),
      ),
      true,
    );
  });

  it('reports the second sighting of the same key as a replay', async () => {
    const store = createInMemoryReplayStore();
    const key = { issuer: 'idp', assertionId: '_a' };
    await store.recordIfUnseen(key, future());
    assert.equal(await store.recordIfUnseen(key, future()), false);
  });

  // The reason the key is a pair: two identity providers may legitimately mint
  // the same ID, and refusing the second is a working login broken, not an
  // attack stopped.
  it('keeps two issuers apart when they mint the same ID', async () => {
    const store = createInMemoryReplayStore();
    assert.equal(
      await store.recordIfUnseen(
        { issuer: 'a', assertionId: '_same' },
        future(),
      ),
      true,
    );
    assert.equal(
      await store.recordIfUnseen(
        { issuer: 'b', assertionId: '_same' },
        future(),
      ),
      true,
    );
  });

  it('forgets an entry once its retention has passed', async () => {
    const store = createInMemoryReplayStore();
    const key = { issuer: 'idp', assertionId: '_a' };
    await store.recordIfUnseen(key, new Date(Date.now() - 1));
    assert.equal(await store.recordIfUnseen(key, future()), true);
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
    assert.equal(results.filter(Boolean).length, 1);
  });

  it('gives each store its own memory', async () => {
    const key = { issuer: 'idp', assertionId: '_a' };
    await createInMemoryReplayStore().recordIfUnseen(key, future());
    assert.equal(
      await createInMemoryReplayStore().recordIfUnseen(key, future()),
      true,
    );
  });
});
