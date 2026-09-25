// Run consumer-owned manifests without inheriting the library's dev-dependencies.
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';

const checkout = resolve('.');
const mode = process.argv[2] ?? 'checkout';
const selected = process.argv[3];
const recipes = [['first-field', 'first_field'], ['sqlite', 'sqlx_sqlite'], ['custom-profile', 'custom_profile']];
if (!['checkout', 'published'].includes(mode) || (selected && !recipes.some(([name]) => name === selected))) {
  throw new Error('usage: check-consumers.mjs [checkout|published] [first-field|sqlite|custom-profile]');
}
const scratch = mkdtempSync(join(tmpdir(), 'cryptbox-consumers-'));
const run = (args, cwd) => execFileSync('cargo', args, {
  cwd, stdio: 'inherit',
  env: { ...process.env, CARGO_TARGET_DIR: resolve(process.env.CARGO_TARGET_DIR ?? 'target', 'consumers', mode) },
});
try {
  for (const [name, source] of recipes.filter(([name]) => !selected || name === selected)) {
    const directory = join(scratch, name);
    mkdirSync(join(directory, 'src'), { recursive: true });
    let manifest = readFileSync(`docs/snippets/${name}.toml`, 'utf8');
    if (mode === 'checkout') {
      // Cargo's patch keeps the advertised dependency/features but selects this checkout.
      manifest += `\n[patch.crates-io]\ncryptbox = { path = ${JSON.stringify(checkout)} }\n`;
    }
    writeFileSync(join(directory, 'Cargo.toml'), manifest);
    writeFileSync(join(directory, 'src/main.rs'), readFileSync(`examples/${source}.rs`));
    run(['check', '--all-targets'], directory);
    run(['run', '--locked'], directory);
    if (name !== 'sqlite') run(['test', '--locked'], directory);
    run(['clippy', '--locked', '--all-targets', '--', '-D', 'warnings'], directory);
  }
  if (!selected) {
    execFileSync(process.execPath, ['scripts/check-testing-consumers.mjs', mode], { stdio: 'inherit' });
    execFileSync(process.execPath, ['scripts/check-searchable-consumer.mjs', mode, 'sqlite'], { stdio: 'inherit' });
    execFileSync(process.execPath, ['scripts/check-searchable-consumer.mjs', mode, 'sqlite', 'sweep'], { stdio: 'inherit' });
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
