// Canonical example sources -> copyable Markdown blocks. No npm dependencies.
import { readFileSync, writeFileSync } from 'node:fs';

const read = (path) => readFileSync(path, 'utf8').trimEnd();
const example = read('examples/first_field.rs');
const start = '// ANCHOR: first-field\n';
const end = '// ANCHOR_END: first-field';
if (example.split(start).length !== 2 || example.split(end).length !== 2
    || example.indexOf(start) >= example.indexOf(end)) {
  throw new Error('examples/first_field.rs: expected one ordered first-field anchor pair');
}
const firstField = example.split(start)[1].split(end)[0].trimEnd();
const sources = {
  'first-field': ['rust', firstField],
  'first-field-manifest': ['toml', read('docs/snippets/first-field.toml')],
  'sqlite-manifest': ['toml', read('docs/snippets/sqlite.toml')],
  sqlite: ['rust', read('examples/sqlx_sqlite.rs')],
  lifecycle: ['mermaid', read('docs/diagrams/lifecycle.mmd')],
};
const pages = {
  'README.md': ['first-field'],
  'docs/first-field.md': ['first-field-manifest', 'first-field', 'lifecycle'],
  'docs/first-field-sqlite.md': ['sqlite-manifest', 'sqlite'],
  'docs/concepts.md': ['lifecycle'],
};
const write = process.argv.includes('--write');
for (const [page, expected] of Object.entries(pages)) {
  const before = readFileSync(page, 'utf8');
  const matched = [];
  const after = before.replace(
    /<!-- BEGIN SHARED: ([\w-]+) -->[\s\S]*?<!-- END SHARED: \1 -->/g,
    (_, name) => {
      matched.push(name);
      const [language, source] = sources[name];
      return `<!-- BEGIN SHARED: ${name} -->\n\n\`\`\`${language}\n${source}\n\`\`\`\n\n<!-- END SHARED: ${name} -->`;
    },
  );
  if (JSON.stringify(matched) !== JSON.stringify(expected)
      || before.split('<!-- BEGIN SHARED:').length !== expected.length + 1
      || before.split('<!-- END SHARED:').length !== expected.length + 1) {
    throw new Error(`${page}: missing, duplicated, or malformed shared snippet markers`);
  }
  if (write) writeFileSync(page, after);
  else if (before !== after) throw new Error(`${page}: run node scripts/doc-snippets.mjs --write`);
}
// rustdoc includes the exact same snippet, including its runnable main function.
const rustdoc = `\`\`\`rust\n${firstField}\n\`\`\`\n`;
if (write) writeFileSync('docs/snippets/first-field.md', rustdoc);
else if (readFileSync('docs/snippets/first-field.md', 'utf8') !== rustdoc) {
  throw new Error('rustdoc snippet is stale: run node scripts/doc-snippets.mjs --write');
}
