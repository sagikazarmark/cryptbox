// The documented CLI is the test seam: all observations cross a process boundary.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { checkRotation } from './check-rotation-consumer.mjs';
import { checkSweep } from './check-sweep-consumer.mjs';
import { checkMigration } from './check-migration-consumer.mjs';
import { checkRecovery } from './check-recovery-consumer.mjs';

const [mode = 'checkout', backend = 'sqlite', scenario = 'searchable'] = process.argv.slice(2);
assert.ok(['searchable', 'sweep', 'migration', 'recovery'].includes(scenario));
assert.ok(scenario !== 'recovery' || backend === 'sqlite', 'recovery uses a SQLite database copy');
const features = scenario === 'migration' ? `${backend},legacy-migration`
  : ['sweep', 'recovery'].includes(scenario) ? `${backend},maintenance` : backend;
assert.ok(['checkout', 'published'].includes(mode));
assert.ok(['sqlite', 'postgres'].includes(backend));
if (backend === 'postgres' && !process.env.DATABASE_URL) {
  throw new Error('PostgreSQL execution requires DATABASE_URL pointing to a disposable database');
}
const scratch = mkdtempSync(join(tmpdir(), 'cryptbox-searchable-'));
const target = resolve(process.env.CARGO_TARGET_DIR ?? 'target', 'consumers', mode, backend);
const env = {
  ...process.env,
  CARGO_TARGET_DIR: target,
  DATABASE_URL: backend === 'sqlite' ? `sqlite://${scratch}/users.db?mode=rwc` : process.env.DATABASE_URL,
  CRYPTBOX_KEY_DIR: join(scratch, 'keys'),
  CRYPTBOX_GENERATION: '1',
  CRYPTBOX_ENCRYPTION: undefined,
  CRYPTBOX_INDEX: undefined,
};
function command(program, args, overrides = {}, success = true) {
  const result = spawnSync(program, args, { cwd: scratch, env: { ...env, ...overrides }, encoding: 'utf8' });
  if (result.error) throw result.error;
  assert.equal(result.signal, null);
  assert.equal(result.status === 0, success, `${program} ${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
  return result;
}
const cli = (args, overrides, success) => command(join(target, 'debug/searchable-consumer'), args, overrides, success);
const schema = `cryptbox_consumer_${randomBytes(8).toString('hex')}`;
const fixture = (operation) => command('cargo', ['run', '--locked', '--no-default-features', '--features', backend,
  '--bin', 'database-fixture', '--', operation, schema], { DATABASE_URL: process.env.DATABASE_URL });
let schemaCreated = false;
try {
  mkdirSync(join(scratch, 'src'));
  let manifest = readFileSync('docs/snippets/searchable.toml', 'utf8');
  if (mode === 'checkout') manifest += `\n[patch.crates-io]\ncryptbox = { path = ${JSON.stringify(resolve('.'))} }\n`;
  writeFileSync(join(scratch, 'Cargo.toml'), manifest);
  writeFileSync(join(scratch, 'src/main.rs'), readFileSync('docs/snippets/searchable.rs'));
  if (scenario === 'migration') {
    writeFileSync(join(scratch, 'src/migration.rs'), readFileSync('docs/snippets/migration.rs'));
  }
  for (const db of ['sqlite', 'postgres']) {
    writeFileSync(join(scratch, `src/${db}.sql`), readFileSync(`docs/snippets/searchable-${db}.sql`));
  }
  if (backend === 'postgres') {
    // Test infrastructure only: isolate runs without adding administrative commands to the consumer.
    mkdirSync(join(scratch, 'src/bin'));
    writeFileSync(join(scratch, 'src/bin/database-fixture.rs'), `
use sqlx::Connection;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut db = sqlx::PgConnection::connect(&std::env::var("DATABASE_URL")?).await?;
    assert!(args[2].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    let sql = match args[1].as_str() {
        "create" => format!("CREATE SCHEMA {}", args[2]),
        "drop" => format!("DROP SCHEMA {} CASCADE", args[2]),
        _ => panic!("invalid fixture command"),
    };
    sqlx::query(&sql).execute(&mut db).await?;
    Ok(())
}
`);
  }
  command('cargo', ['check', '--no-default-features', '--features', features]);
  command('cargo', ['build', '--locked', '--no-default-features', '--features', features]);
  if (backend === 'postgres') {
    fixture('create');
    schemaCreated = true;
    const url = new URL(env.DATABASE_URL);
    const options = url.searchParams.get('options') ?? '';
    url.searchParams.set('options', `${options} -c search_path=${schema}`.trim());
    env.DATABASE_URL = url.toString();
  }
  assert.match(cli(['init'], {}, false).stderr, /key configuration/);
  mkdirSync(env.CRYPTBOX_KEY_DIR);
  if (scenario === 'migration') {
    writeFileSync(join(env.CRYPTBOX_KEY_DIR, 'legacy.hex'), randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
  }
  for (const role of ['encryption', 'index']) {
    for (const generation of scenario === 'sweep' ? [1, 2, 3] : [1, 2]) {
      writeFileSync(join(env.CRYPTBOX_KEY_DIR, `${role}-${generation}.hex`), randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
    }
  }
  const configurationError = 'Error: "database configuration: DATABASE_URL must be valid UTF-8 and present"';
  assert.equal(cli(['init'], { DATABASE_URL: undefined }, false).stderr.trim(), configurationError);
  // The supported macOS/Linux shells can pass raw environment bytes that Node strings cannot.
  const invalidUnicode = command('bash', ['-c',
    String.raw`export DATABASE_URL=$'postgres://user:SYNTHETIC_PASSWORD\xff@localhost/db'; exec "$1" init`,
    'invalid-database-configuration', join(target, 'debug/searchable-consumer')], {}, false);
  assert.equal(invalidUnicode.stdout, '');
  assert.equal(invalidUnicode.stderr.trim(), configurationError);
  assert.equal(cli(['init']).stdout.trim(), 'Schema ready.');
  if (scenario === 'migration') {
    checkMigration(cli);
    command('cargo', ['clippy', '--locked', '--no-default-features', '--features', features, '--', '-D', 'warnings']);
    // Physically remove the online legacy handler and secret, then build without migration features.
    rmSync(join(scratch, 'src/migration.rs'));
    rmSync(join(env.CRYPTBOX_KEY_DIR, 'legacy.hex'));
    command('cargo', ['check', '--locked', '--no-default-features', '--features', backend]);
    command('cargo', ['build', '--locked', '--no-default-features', '--features', backend]);
    const strict = { CRYPTBOX_ENCRYPTION: '2', CRYPTBOX_INDEX: '2' };
    for (const id of [10, 20, 30, 40, 50, 60]) {
      assert.equal(cli(['get', String(id)], strict).stdout.trim(), `${id}: mixed@example.com`);
    }
    assert.equal(cli(['search', 'MIXED@example.com'], strict).stdout.trim(),
      'Matches: [10, 20, 30, 40, 50, 60]; rejected: 0.');
    assert.equal(cli(['search', 'OTHER@example.com'], strict).stdout.trim(), 'Matches: [70]; rejected: 0.');
    cli(['put', '80', 'strict@example.com'], strict);
    assert.equal(cli(['get', '80'], strict).stdout.trim(), '80: strict@example.com');
    assert.equal(cli(['search', 'STRICT@example.com'], strict).stdout.trim(), 'Matches: [80]; rejected: 0.');
    cli(['migration-search', 'mixed@example.com'], strict, false);
    console.log(`${mode}/${backend}: strict rebuild without legacy handler/key or migration features passed.`);
  } else if (scenario === 'recovery') {
    checkRecovery(cli, scratch, env.CRYPTBOX_KEY_DIR);
    command('cargo', ['clippy', '--locked', '--no-default-features', '--features', features, '--', '-D', 'warnings']);
  } else if (scenario === 'sweep') {
    checkSweep(cli);
    command('cargo', ['clippy', '--locked', '--no-default-features', '--features', features, '--', '-D', 'warnings']);
  } else {
    // Begin the generation-1 rehearsal on empty storage, as the runbook requires.
    checkRotation(cli);
    assert.equal(cli(['put', '1', ' Alice@Example.com ']).stdout.trim(), 'Stored 1.');
    assert.equal(cli(['get', '1']).stdout.trim(), '1:  Alice@Example.com');
    assert.equal(cli(['search', 'alice@example.com']).stdout.trim(), 'Matches: [1]; rejected: 0.');
    assert.equal(cli(['put-null', '2']).stdout.trim(), 'Stored 2.');
    assert.equal(cli(['get', '2']).stdout.trim(), '2: NULL');
    cli(['put', '2', 'before@example.com']);
    cli(['put', '2', ' Alice@Example.com ']);
    assert.equal(cli(['search', 'before@example.com']).stdout.trim(), 'Matches: []; rejected: 0.');
    assert.equal(cli(['search', 'alice@example.com']).stdout.trim(), 'Matches: [1, 2]; rejected: 0.');
    cli(['put-null', '2']);
    assert.equal(cli(['search', 'alice@example.com']).stdout.trim(), 'Matches: [1]; rejected: 0.');
    env.CRYPTBOX_GENERATION = '2';
    cli(['put', '3', 'alice@example.com']);
    cli(['put', '4', 'bob@example.com']);
    cli(['demo-false-candidate', '4', '3']);
    assert.equal(cli(['get', '1']).stdout.trim(), '1:  Alice@Example.com');
    assert.equal(cli(['get', '3']).stdout.trim(), '3: alice@example.com');
    assert.equal(cli(['get', '4']).stdout.trim(), '4: bob@example.com');
    assert.equal(cli(['search', ' ALICE@EXAMPLE.COM ']).stdout.trim(), 'Matches: [1, 3]; rejected: 1.');
    assert.equal(cli(['search', 'alice@example.com'], { CRYPTBOX_GENERATION: '1' }).stdout.trim(), 'Matches: [1, 3]; rejected: 1.');
    assert.match(cli(['get', '1'], { CRYPTBOX_GENERATION: '3' }, false).stderr, /key configuration/);
    const keyFile = join(env.CRYPTBOX_KEY_DIR, 'encryption-1.hex');
    const original = readFileSync(keyFile);
    for (const malformed of ['z'.repeat(64), '00']) {
      writeFileSync(keyFile, malformed);
      assert.match(cli(['get', '1'], {}, false).stderr, /key configuration/);
    }
    writeFileSync(keyFile, original);
    assert.equal(cli(['get', '1']).stdout.trim(), '1:  Alice@Example.com');
    for (const role of ['encryption', 'index']) {
      const file = join(env.CRYPTBOX_KEY_DIR, `${role}-2.hex`);
      const original = readFileSync(file);
      writeFileSync(file, randomBytes(32).toString('hex'));
      cli(['rotation-ready', 'index.canary'], {}, false);
      writeFileSync(file, original);
      assert.equal(cli(['rotation-ready', 'index.canary']).stdout.trim(), 'Ready.');
    }
    assert.match(cli(['get', '1'], { CRYPTBOX_ENCRYPTION: '2' }, false).stderr, /set both/);
    assert.match(cli(['get', '1'], { CRYPTBOX_ENCRYPTION: 'invalid', CRYPTBOX_INDEX: '1' }, false).stderr, /key configuration/);
    command('cargo', ['check', '--locked', '--no-default-features', '--features', `${backend},macro-check`]);
    command('cargo', ['build', '--locked', '--no-default-features', '--features', `${backend},macro-check`]);
    assert.equal(cli(['macro-get', '1']).stdout.trim(), '1:  Alice@Example.com');
    assert.equal(cli(['macro-get', '2']).stdout.trim(), '2: NULL');
    assert.equal(cli(['macro-get', '3']).stdout.trim(), '3: alice@example.com');
    assert.equal(cli(['macro-put', '5', 'macro@example.com']).stdout.trim(), 'Stored 5.');
    assert.equal(cli(['macro-put', '5', 'invalid address'], {}, false).stderr.trim(),
      'Error: "application email validation failed"');
    assert.equal(cli(['get', '5']).stdout.trim(), '5: macro@example.com');
    assert.equal(cli(['search', 'MACRO@example.com']).stdout.trim(), 'Matches: [5]; rejected: 0.');
    command('cargo', ['clippy', '--locked', '--no-default-features', '--features', `${backend},macro-check`, '--', '-D', 'warnings']);
    console.log(`${mode}/${backend}: durable restart, nullable updates, both readable generations, false-candidate rejection and invalid-key failures passed.`);
  }
} finally {
  try {
    if (schemaCreated) fixture('drop');
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}
