// Canonical example sources -> copyable Markdown blocks. No npm dependencies.
import { readFileSync, writeFileSync } from 'node:fs';

const read = (path) => readFileSync(path, 'utf8').trimEnd();
const anchored = (path, name) => {
  const example = read(path);
  const start = `// ANCHOR: ${name}\n`;
  const end = `// ANCHOR_END: ${name}`;
  if (example.split(start).length !== 2 || example.split(end).length !== 2
      || example.indexOf(start) >= example.indexOf(end)) {
    throw new Error(`${path}: expected one ordered ${name} anchor pair`);
  }
  return example.split(start)[1].split(end)[0].trimEnd();
};
const firstField = anchored('examples/first_field.rs', 'first-field');
const tenantField = anchored('examples/tenant_field.rs', 'tenant-field');
const sources = {
  'first-field': ['rust', firstField],
  'tenant-field': ['rust', tenantField],
  'first-field-manifest': ['toml', read('docs/snippets/first-field.toml')],
  lifecycle: ['mermaid', read('docs/diagrams/lifecycle.mmd')],
  ...Object.fromEntries([
    'searchable-put', 'searchable-get', 'searchable-search',
    'searchable-macro-get', 'searchable-macro-put',
  ].map((name) => [name, ['rust', anchored('examples/searchable/main.rs', name)]])),
  rotation: ['mermaid', read('docs/diagrams/rotation.mmd')],
  'trust-boundary': ['mermaid', read('docs/diagrams/trust-boundary.mmd')],
};
const pages = {
  'docs/first-field.md': ['first-field-manifest', 'first-field'],
  'docs/ownership.md': ['lifecycle'],
  'examples/searchable/README.md': [
    'searchable-put', 'searchable-get', 'searchable-search',
    'searchable-macro-get', 'searchable-macro-put',
  ],
  'docs/key-rotation.md': ['rotation'],
  'docs/security.md': ['trust-boundary'],
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
// rustdoc includes the exact same snippets, including their runnable main functions.
for (const [path, source] of [
  ['docs/snippets/first-field.md', firstField],
  ['docs/snippets/tenant-field.md', tenantField],
]) {
  const rustdoc = `\`\`\`rust\n${source}\n\`\`\`\n`;
  if (write) writeFileSync(path, rustdoc);
  else if (readFileSync(path, 'utf8') !== rustdoc) {
    throw new Error(`${path} is stale: run node scripts/doc-snippets.mjs --write`);
  }
}
