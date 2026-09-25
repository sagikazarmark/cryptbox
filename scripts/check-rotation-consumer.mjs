// The same public consumer CLI runs against SQLite and live PostgreSQL.
import assert from 'node:assert/strict';

export function checkRotation(cli) {
  const instance = (encryption, index) => ({
    CRYPTBOX_GENERATION: '',
    CRYPTBOX_ENCRYPTION: encryption,
    CRYPTBOX_INDEX: index,
  });
  let a = instance('1', '1');
  let b = instance('1', '1');
  const output = (args, config) => cli(args, config).stdout.trim();
  const search = (config, ids, rejected = 0) => assert.equal(
    output(['search', ' ROLLOUT@EXAMPLE.COM '], config),
    `Matches: [${ids.join(', ')}]; rejected: ${rejected}.`,
  );
  cli(['put', '101', 'rollout@example.com'], a);
  search(b, [101]);
  cli(['rotation-canary', 'baseline.canary'], a);

  // A learns E2 first; both still write E1/I1. The canary never enters users.
  cli(['rotation-canary', 'encryption.canary'], instance('2', '1'));
  cli(['rotation-ready', 'encryption.canary'], b, false);
  a = instance('staged', '1');
  assert.equal(output(['rotation-ready', 'encryption.canary'], a), 'Ready.');
  cli(['put', '102', 'rollout@example.com'], a);
  assert.equal(output(['get', '102'], b), '102: rollout@example.com');
  search(b, [101, 102]);
  b = instance('staged', '1');
  assert.equal(output(['rotation-ready', 'encryption.canary'], b), 'Ready.');

  a = instance('2', '1');
  cli(['put', '103', 'rollout@example.com'], a);
  cli(['put', '104', 'rollout@example.com'], b);
  for (const config of [a, b]) {
    assert.equal(output(['get', '101'], config), '101: rollout@example.com');
    assert.equal(output(['get', '103'], config), '103: rollout@example.com');
    search(config, [101, 102, 103, 104]);
  }
  b = instance('2', '1');
  search(b, [101, 102, 103, 104]);

  // Index promotion is independent; E2 stays current throughout this phase.
  cli(['rotation-canary', 'index.canary'], instance('2', '2'));
  cli(['rotation-ready', 'index.canary'], b, false);
  a = instance('2', 'staged');
  assert.equal(output(['rotation-ready', 'index.canary'], a), 'Ready.');
  cli(['put', '105', 'rollout@example.com'], a);
  search(b, [101, 102, 103, 104, 105]);
  b = instance('2', 'staged');
  assert.equal(output(['rotation-ready', 'index.canary'], b), 'Ready.');
  a = instance('2', '2');
  cli(['put', '106', 'rollout@example.com'], a);
  cli(['put', '107', 'rollout@example.com'], b);
  cli(['put', '108', 'different@example.com'], a);
  cli(['demo-false-candidate', '108', '106'], a);
  const ids = [101, 102, 103, 104, 105, 106, 107];
  for (const config of [a, b]) search(config, ids, 1);
  for (const config of [a, b]) {
    for (const canary of ['baseline.canary', 'encryption.canary', 'index.canary']) {
      assert.equal(output(['rotation-ready', canary], config), 'Ready.');
    }
  }
  b = instance('2', '2');
  for (const config of [a, b]) search(config, ids, 1);

  // Roll back write selection, never readability. Each command restarts the process.
  a = instance('staged', 'staged');
  b = instance('staged', 'staged');
  for (const config of [a, b]) {
    assert.equal(output(['get', '106'], config), '106: rollout@example.com');
    search(config, ids, 1);
  }
  cli(['put', '109', 'rollout@example.com'], a);
  search(b, [...ids, 109], 1);
  search(instance('2', '2'), [...ids, 109], 1);

  // Stored metadata proves independent promotion and that no historical row was rewritten.
  const e1 = '10000000-0000-4000-8000-000000000001';
  const e2 = '20000000-0000-4000-8000-000000000002';
  const i1 = '30000000-0000-4000-8000-000000000003';
  const i2 = '40000000-0000-4000-8000-000000000004';
  for (const [id, encryption, index] of [
    [101, e1, i1], [102, e1, i1], [103, e2, i1], [104, e1, i1],
    [105, e2, i1], [106, e2, i2], [107, e2, i1], [109, e1, i1],
  ]) {
    assert.equal(output(['generations', String(id)], a), `Encryption: ${encryption}; index: ${index}.`);
  }
  cli(['get', '106'], instance('1', '1'), false);
  // Losing I2 can silently omit real matches, even while ciphertext remains readable.
  search(instance('2', '1'), [101, 102, 103, 104, 105, 107, 109]);
  cli(['put', '108', 'different@example.com'], instance('2', '2'));
  search(instance('2', '2'), [...ids, 109]);
  console.log('Staggered encryption/index promotion, readiness, restart and compatible rollback passed.');
}
