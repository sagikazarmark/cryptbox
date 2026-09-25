// Exercise the testing guide at its consumer-owned public API/process seams.
import assert from 'node:assert/strict';
import { execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

const mode = process.argv[2] ?? 'checkout';
const selected = process.argv[3];
const recipes = ['local', 'automatic', 'diagnostics'];
if (!['checkout', 'published'].includes(mode) || (selected && !recipes.includes(selected))) {
  throw new Error('usage: check-testing-consumers.mjs [checkout|published] [local|automatic|diagnostics]');
}
const scratch = mkdtempSync(join(tmpdir(), 'cryptbox-testing-'));
const target = resolve(process.env.CARGO_TARGET_DIR ?? 'target', 'consumers', mode);
const env = { ...process.env, CARGO_TARGET_DIR: target };
try {
  for (const recipe of selected ? [selected] : recipes) {
    const name = `testing-${recipe}`;
    const directory = join(scratch, name);
    mkdirSync(join(directory, 'src'), { recursive: true });
    let manifest = readFileSync(`docs/snippets/${name}.toml`, 'utf8');
    if (mode === 'checkout') {
      manifest += `\n[patch.crates-io]\ncryptbox = { path = ${JSON.stringify(resolve('.'))} }\n`;
    }
    writeFileSync(join(directory, 'Cargo.toml'), manifest);
    writeFileSync(join(directory, 'src', recipe === 'local' ? 'lib.rs' : 'main.rs'),
      readFileSync(`docs/snippets/${name}.rs`));
    const cargo = (args) => execFileSync('cargo', args, { cwd: directory, env, stdio: 'inherit' });
    cargo(['check', '--all-targets']);
    if (recipe === 'local') {
      cargo(['test', '--locked', '--lib', '--', '--test-threads=2']);
    } else {
      cargo(['build', '--locked']);
      const binary = join(target, 'debug', `${name}-consumer`);
      if (recipe === 'automatic') {
        // Each invocation owns its static context. The processes may overlap.
        const outputs = await Promise.all(['first', 'second'].map((fixture) =>
          promisify(execFile)(binary, [fixture], { env })));
        for (const output of outputs) {
          assert.equal(output.stdout, 'Automatic adapter round trip succeeded.\n');
          assert.equal(output.stderr, '');
        }
      } else {
        const { stdout, stderr } = await promisify(execFile)(binary, [], { env });
        assert.equal(stdout, 'field_id=ca274e85-63c4-4f7d-a255-2dfecbfe5e25 field_name=user-email operation=decrypt error=authentication_failed\n');
        assert.equal(stderr, '');
      }
    }
    cargo(['clippy', '--locked', '--all-targets', '--', '-D', 'warnings']);
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
