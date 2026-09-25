// Acceptance seam: every CLI invocation starts a new process against durable storage.
import assert from 'node:assert/strict';

export function checkSweep(cli) {
  const keys = { CRYPTBOX_ENCRYPTION: '2', CRYPTBOX_INDEX: '2' };
  const output = (args, config = keys) => cli(args, config).stdout.trim();
  for (const id of [10, 20, 30]) {
    cli(['put', String(id), 'sweep@example.com'], { CRYPTBOX_GENERATION: '1' });
  }
  cli(['put', '40', 'sweep@example.com'], keys);
  assert.equal(output(['sweep-status', 'rotation-2']), 'Checkpoint: None.');
  assert.equal(output(['sweep-batch', 'rotation-2']),
    'Checkpoint: Some(20); current: 0; stale: 2; conflicts: 0.');
  assert.equal(output(['sweep-status', 'rotation-2']), 'Checkpoint: Some(20).');
  // The process exits after writes but before checkpointing. The next process replays.
  assert.equal(output(['sweep-uncheckpointed', 'rotation-2']),
    'Checkpoint: Some(40); current: 1; stale: 1; conflicts: 0.');
  assert.equal(output(['sweep-status', 'rotation-2']), 'Checkpoint: Some(20).');
  assert.equal(output(['sweep-batch', 'rotation-2']),
    'Checkpoint: Some(40); current: 2; stale: 0; conflicts: 0.');
  assert.equal(output(['sweep-batch', 'rotation-2']),
    'Checkpoint: None; current: 0; stale: 0; conflicts: 0.');
  assert.equal(output(['sweep-verify', 'rotation-2']),
    'Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.');
  cli(['put', '10', 'sweep@example.com'], { CRYPTBOX_GENERATION: '1' });
  assert.equal(output(['sweep-batch', 'rotation-2']),
    'Checkpoint: None; current: 0; stale: 0; conflicts: 0.');
  assert.equal(output(['sweep-verify', 'rotation-2']),
    'Complete: false; current: 3; stale: 1; legacy: 0; malformed: 0.');
  // New identity starts at the beginning; merely resuming cannot repair behind the cursor.
  assert.equal(output(['sweep-batch', 'rotation-2-repair-1']),
    'Checkpoint: Some(20); current: 1; stale: 1; conflicts: 0.');
  output(['sweep-batch', 'rotation-2-repair-1']);
  output(['sweep-batch', 'rotation-2-repair-1']);
  assert.equal(output(['sweep-verify', 'rotation-2-repair-1']),
    'Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.');
  const third = { CRYPTBOX_ENCRYPTION: '3', CRYPTBOX_INDEX: '3' };
  const staged = { CRYPTBOX_ENCRYPTION: 'staged-3', CRYPTBOX_INDEX: 'staged-3' };
  cli(['rotation-canary', 'third.canary'], third);
  assert.equal(output(['rotation-ready', 'third.canary'], staged), 'Ready.');
  // A concurrent application writes through an independent database connection.
  assert.equal(output(['sweep-conflict', 'rotation-3'], third), 'Stored 10.\nConflicts: 1.');
  assert.equal(output(['get', '10'], staged), '10: concurrent@example.com');
  assert.equal(output(['search', 'CONCURRENT@example.com'], staged), 'Matches: [10]; rejected: 0.');
  for (const config of [staged, third]) {
    assert.equal(output(['search', 'SWEEP@example.com'], config), 'Matches: [20, 30, 40]; rejected: 0.');
  }
  assert.equal(output(['sweep-status', 'rotation-3'], third), 'Checkpoint: None.');
  // A worker missing E3 cannot rewrite the concurrent value; no checkpoint advances.
  cli(['sweep-batch', 'missing-key-rehearsal'], keys, false);
  assert.equal(output(['sweep-status', 'missing-key-rehearsal'], third), 'Checkpoint: None.');
  assert.equal(output(['sweep-status', 'rotation-3'], third), 'Checkpoint: None.');
  assert.equal(output(['sweep-batch', 'rotation-3'], third),
    'Checkpoint: Some(20); current: 1; stale: 1; conflicts: 0.');
  assert.equal(output(['search', 'SWEEP@example.com'], staged), 'Matches: [20, 30, 40]; rejected: 0.');
  assert.equal(output(['sweep-batch', 'rotation-3'], third),
    'Checkpoint: Some(40); current: 0; stale: 2; conflicts: 0.');
  output(['sweep-batch', 'rotation-3'], third);
  assert.equal(output(['sweep-verify', 'rotation-3'], third),
    'Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.');
  assert.equal(output(['search', 'SWEEP@example.com'], staged), 'Matches: [20, 30, 40]; rejected: 0.');
  for (const id of [20, 30, 40]) {
    assert.equal(output(['get', String(id)], staged), `${id}: sweep@example.com`);
  }
  console.log('Durable checkpoint restart, uncheckpointed replay, fresh verification/recovery, conflict preservation and second rotation passed.');
}
