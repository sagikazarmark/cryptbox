// Run consumer-owned manifests without inheriting the library's dev-dependencies.
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';

const checkout = resolve('.');
const mode = process.argv[2] ?? 'checkout';
if (!['checkout', 'published'].includes(mode)) throw new Error('expected checkout or published');
const scratch = mkdtempSync(join(tmpdir(), 'cryptbox-consumers-'));
const run = (args, cwd) => execFileSync('cargo', args, {
  cwd, stdio: 'inherit',
  env: { ...process.env, CARGO_TARGET_DIR: resolve(process.env.CARGO_TARGET_DIR ?? 'target', 'consumers', mode) },
});
try {
  for (const [name, source] of [['first-field', 'first_field'], ['sqlite', 'sqlx_sqlite']]) {
    const directory = join(scratch, name);
    mkdirSync(join(directory, 'src'), { recursive: true });
    let manifest = readFileSync(`docs/snippets/${name}.toml`, 'utf8');
    if (mode === 'checkout') {
      // Cargo's patch keeps the advertised dependency/features but selects this checkout.
      manifest += `\n[patch.crates-io]\ncryptbox = { path = ${JSON.stringify(checkout)} }\n`;
    }
    writeFileSync(join(directory, 'Cargo.toml'), manifest);
    writeFileSync(join(directory, 'src/main.rs'), readFileSync(`examples/${source}.rs`));
    run(['check'], directory);
    run(['run', '--locked'], directory);
    if (name === 'first-field') run(['test', '--locked'], directory);
  }
  execFileSync(process.execPath, ['scripts/check-testing-consumers.mjs', mode], { stdio: 'inherit' });
  execFileSync(process.execPath, ['scripts/check-searchable-consumer.mjs', mode, 'sqlite'], { stdio: 'inherit' });
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
