// Consumer boundary: closed-process database backup/restore and independent key directories.
import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, renameSync } from 'node:fs';
import { join } from 'node:path';

export function checkRecovery(cli, scratch, onlineDirectory) {
  const historical = { CRYPTBOX_ENCRYPTION: '1', CRYPTBOX_INDEX: '1' };
  const compatible = { CRYPTBOX_ENCRYPTION: '2', CRYPTBOX_INDEX: '2' };
  const online = { CRYPTBOX_ENCRYPTION: '2-only', CRYPTBOX_INDEX: '2-only' };
  const output = (args, config) => cli(args, config).stdout.trim();
  for (const id of [10, 20]) cli(['put', String(id), 'recovery@example.com'], historical);
  cli(['rotation-canary', 'baseline.canary'], historical);
  const backup = join(scratch, 'before-rotation.db');
  assert.equal(output(['recovery-copy', backup], historical), 'Database copy saved.');
  // An existing recovery artifact must never be overwritten by another copy.
  cli(['recovery-copy', backup], historical, false);
  cli(['rotation-canary', 'target.canary'], compatible);
  for (const instance of ['A', 'B']) {
    assert.equal(output(['rotation-ready', 'target.canary'], {
      CRYPTBOX_ENCRYPTION: 'staged', CRYPTBOX_INDEX: 'staged',
    }), 'Ready.', instance);
  }
  cli(['put', '30', 'recovery@example.com'], compatible);
  cli(['put', '40', 'different@example.com'], compatible);
  for (let batch = 0; batch < 3; batch++) cli(['sweep-batch', 'retire-2'], compatible);
  assert.equal(output(['sweep-verify', 'retire-2'], compatible),
    'Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.');
  assert.equal(output(['audit-current'], compatible), 'Audited: 4 authenticated, current-index rows.');
  cli(['demo-false-candidate', '40', '30'], compatible);
  // Generation convergence does not detect a current-generation but inconsistent token.
  assert.equal(output(['sweep-verify', 'retire-2'], compatible),
    'Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.');
  cli(['audit-current'], compatible, false);
  cli(['put', '40', 'different@example.com'], compatible);
  assert.equal(output(['audit-current'], compatible), 'Audited: 4 authenticated, current-index rows.');

  const recoveryDirectory = join(scratch, 'recovery-keys');
  mkdirSync(recoveryDirectory);
  // Historical material is now absent from online storage, not merely unselected.
  for (const role of ['encryption', 'index']) {
    renameSync(join(onlineDirectory, `${role}-1.hex`), join(recoveryDirectory, `${role}-1.hex`));
  }
  assert.equal(output(['audit-current'], online), 'Audited: 4 authenticated, current-index rows.');
  assert.equal(output(['search', 'RECOVERY@example.com'], online), 'Matches: [10, 20, 30]; rejected: 0.');
  cli(['rotation-ready', 'baseline.canary'], online, false);
  cli(['get', '10'], compatible, false); // A stale deployment config cannot silently restore old access.

  const restored = join(scratch, 'isolated-recovery.db');
  copyFileSync(backup, restored); // Closed SQLite copy, new location; the original backup remains intact.
  const restoredUrl = `sqlite://${restored}?mode=rw`;
  const recovery = { ...historical, DATABASE_URL: restoredUrl, CRYPTBOX_KEY_DIR: recoveryDirectory };
  cli(['get', '10'], { ...online, DATABASE_URL: restoredUrl }, false);
  for (const id of [10, 20]) {
    assert.equal(output(['get', String(id)], recovery), `${id}: recovery@example.com`);
  }
  cli(['get', '30'], recovery, false); // This really is the pre-rotation snapshot.
  assert.equal(output(['audit-current'], recovery), 'Audited: 2 authenticated, current-index rows.');
  assert.equal(output(['search', ' RECOVERY@EXAMPLE.COM '], recovery), 'Matches: [10, 20]; rejected: 0.');
  // Encryption recovery alone is insufficient: missing historical probes silently omit rows.
  copyFileSync(join(onlineDirectory, 'index-2.hex'), join(recoveryDirectory, 'index-2.hex'));
  const missingProbe = { ...recovery, CRYPTBOX_INDEX: '2-only' };
  assert.equal(output(['get', '10'], missingProbe), '10: recovery@example.com');
  assert.equal(output(['search', 'recovery@example.com'], missingProbe), 'Matches: []; rejected: 0.');
  cli(['audit-current'], missingProbe, false);
  // Recovery never changes the live database or its current-only keyset.
  assert.equal(output(['get', '30'], online), '30: recovery@example.com');
  assert.equal(output(['search', 'RECOVERY@example.com'], online), 'Matches: [10, 20, 30]; rejected: 0.');
  console.log('Pre-rotation copy, live convergence, online removal and isolated historical read/search recovery passed.');
}
