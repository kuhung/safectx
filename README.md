# SafeContext

![SafeContext turns sensitive work into a local AI-safe copy](assets/social-card.png)

Your work can use AI. Your sensitive details do not have to.

SafeContext adds a local checkpoint before an AI agent reads work files. It
creates a separate `.ai-safe/` copy, replaces common identifiers and secrets
with stable placeholders, and reports only categories and counts.

[Try the browser demo](https://safectx-ai-privacy.dainty-nova-4389.chatgpt.site/?utm_source=github&utm_medium=repository&utm_campaign=agent-preview-v1&utm_content=readme-demo&variant=manual_cleanup)

## What stays local

- Original files
- Detected values
- Custom company and project terms
- The private placeholder mapping

The scanner makes no network requests. Originals are never modified.

## Supported inputs

The preview supports regular UTF-8 text, Markdown, CSV, JSON, YAML, TOML,
configuration files, and common source-code formats. It intentionally skips
symlinks, binary files, files larger than 5 MB, generated directories, PDF,
Office documents, images, archives, and email containers.

## Try it locally

Use synthetic or already-public content for the first run:

```bash
node skills/make-ai-safe-copy/scripts/safectx.mjs sanitize \
  --out-dir .ai-safe \
  --term "Example Project" \
  ./example
```

Read `.ai-safe/report.json`, then let the AI work only with files inside
`.ai-safe/files/`.

## Agent packages

This repository includes:

- `.codex-plugin/plugin.json` for Codex
- `.claude-plugin/plugin.json` for Claude Code
- `gemini-extension.json` for Gemini CLI
- `skills/make-ai-safe-copy/SKILL.md` as the shared agent workflow

Codex CLI can add the public marketplace and install the versioned plugin:

```bash
codex plugin marketplace add kuhung/safectx --ref main
codex plugin add safectx@safectx
```

Claude Code can add the same public repository as a marketplace:

```bash
claude plugin marketplace add kuhung/safectx
claude plugin install safectx@safectx
```

Gemini CLI can install the public release directly from GitHub:

```bash
gemini extensions install kuhung/safectx --ref v0.3.0
```

Codex and Claude marketplace instructions will be added after their first
catalog submission. The included manifests can already be validated or tested
locally.

## Capability boundary

SafeContext reduces accidental exposure; it does not detect every confidential
fact, make any document safe, provide a compliance guarantee, or replace
enterprise DLP. Review every sanitized copy before sharing it externally.

Optional local restoration exists for workflows that require it, but it is not
the default product promise.

## Development

Requires Node.js 22 or newer.

```bash
npm test
```

Security and privacy reports: use the
[SafeContext contact form](https://safectx-ai-privacy.dainty-nova-4389.chatgpt.site/contact).
