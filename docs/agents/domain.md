# Domain documentation

This repository uses a single-context layout.

Before exploring, read [the glossary](../glossary.md) and relevant decisions in
`docs/adr/` when present. The root CONTEXT.md is a pointer to the glossary for tools
and skills that expect that filename; maintain definitions in docs/glossary.md.
If CONTEXT-MAP.md exists later, follow its pointers to the relevant contexts.
Proceed silently when these documents do not exist; create them lazily when
domain terminology or architectural decisions are resolved.

Use glossary terminology consistently. Read the raw Markdown and follow the
agent guidance in its HTML comments. Maintain that guidance beside the relevant
definitions, keeping reader-facing conceptual distinctions in the visible text.
Surface conflicts with existing ADRs explicitly rather than silently overriding
them.
