// Acceptance seam: documented commands, separate processes, durable database.
import assert from 'node:assert/strict';

export function checkMigration(cli) {
  const keys = { CRYPTBOX_ENCRYPTION: '2', CRYPTBOX_INDEX: '2' };
  const output = (args) => cli(args, keys).stdout.trim();
  assert.equal(output(['migration-seed']), 'Mixed-format fixture ready.');
  assert.equal(output(['migration-search', ' MIXED@example.com ']),
    'Matches: [10, 20, 30, 40, 50, 60]; rejected: 1.');
  for (const id of [10, 20, 30, 40, 50, 60]) {
    assert.equal(output(['migration-get', String(id)]), `${id}: mixed@example.com`);
  }
  // Authenticated legacy recovery must fail closed, with no cursor jump.
  output(['migration-damage']);
  const failure = cli(['sweep-batch', 'legacy-2'], keys, false);
  assert.match(failure.stderr, /AuthenticationFailed/);
  assert.equal(output(['sweep-status', 'legacy-2']), 'Checkpoint: None.');
  assert.equal(cli(['migration-search', 'mixed@example.com'], keys, false).stdout, '');
  assert.equal(output(['migration-quarantine']), 'Quarantined 20; closure blocked.');
  assert.match(cli(['migration-search', 'mixed@example.com'], keys, false).stderr, /unresolved quarantine/);
  assert.match(cli(['migration-close'], keys, false).stderr, /unresolved quarantine/);
  assert.equal(output(['migration-restore']), 'Restored 20 from approved fixture source.');
  // A duplicate restoration raises SQLx's database error, never server detail on stderr.
  assert.equal(cli(['migration-restore'], keys, false).stderr.trim(), 'Error: "database operation failed"');
  assert.equal(output(['sweep-batch', 'legacy-2']),
    'Checkpoint: Some(20); current: 2; stale: 0; conflicts: 0.');
  assert.equal(output(['sweep-uncheckpointed', 'legacy-2']),
    'Checkpoint: Some(40); current: 1; stale: 1; conflicts: 0.');
  assert.equal(output(['sweep-status', 'legacy-2']), 'Checkpoint: Some(20).');
  assert.equal(output(['sweep-batch', 'legacy-2']),
    'Checkpoint: Some(40); current: 2; stale: 0; conflicts: 0.');
  // Ordinary classification and packaged stores cannot use our discriminator.
  cli(['migration-classify', '60'], keys, false);
  cli(['sweep-batch', 'legacy-2'], keys, false);
  assert.equal(output(['sweep-status', 'legacy-2']), 'Checkpoint: Some(40).');
  // The packaged planner also rejects empty indexes on CryptBox envelopes.
  assert.equal(output(['migration-repair-missing']), 'Backfilled missing projection on row 50.');
  cli(['sweep-batch', 'legacy-2'], keys, false);
  assert.equal(output(['sweep-status', 'legacy-2']), 'Checkpoint: Some(40).');
  assert.equal(output(['migration-repair-collision']), 'Repaired discriminator-known row 60.');
  assert.equal(output(['sweep-batch', 'legacy-2']),
    'Checkpoint: Some(60); current: 2; stale: 0; conflicts: 0.');
  output(['sweep-batch', 'legacy-2']);
  output(['sweep-batch', 'legacy-2']);
  assert.equal(output(['sweep-verify', 'legacy-2']),
    'Complete: true; current: 7; stale: 0; legacy: 0; malformed: 0.');
  assert.equal(output(['migration-search', 'mixed@example.com']),
    'Matches: [10, 20, 30, 40, 50, 60]; rejected: 0.');
  // Generation convergence is insufficient: corrupt a current index and audit it.
  output(['demo-false-candidate', '70', '40']);
  assert.equal(output(['migration-search', 'mixed@example.com']),
    'Matches: [10, 20, 30, 40, 50, 60]; rejected: 1.');
  assert.match(output(['sweep-verify', 'legacy-2']), /Complete: true/);
  assert.match(cli(['migration-close'], keys, false).stderr, /index consistency/);
  output(['put', '70', 'other@example.com']);
  assert.equal(output(['migration-close']), 'Closure verified: 7 authenticated, validated, indexed rows.');
  // Every value accepted by a normal writer must remain readable during migration and closure.
  output(['put', '40', ' MiXeD@example.com ']);
  assert.equal(output(['migration-get', '40']), '40:  MiXeD@example.com');
  assert.equal(output(['migration-search', 'mixed@example.com']),
    'Matches: [10, 20, 30, 40, 50, 60]; rejected: 0.');
  assert.equal(output(['migration-close']), 'Closure verified: 7 authenticated, validated, indexed rows.');
  for (const invalid of ['missing-at', 'inner space@example.com', 'é@example.com', `${'x'.repeat(254)}@example.com`]) {
    const rejected = cli(['put', '40', invalid], keys, false);
    assert.equal(rejected.stdout, '');
    assert.equal(rejected.stderr.trim(), 'Error: "application email validation failed"');
    assert.equal(output(['migration-get', '40']), '40:  MiXeD@example.com');
  }
  output(['put', '40', 'mixed@example.com']);
  console.log('Mixed-format lookup, failure/quarantine/resume, manual exceptional-row repairs and closure gates passed.');
}
