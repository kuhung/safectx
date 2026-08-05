# ContextArmor

![ContextArmor checks sensitive work locally](assets/social-card.png)

**See what reached AI. Protect the next message locally.**

ContextArmor is a local-first privacy toolkit for people who use AI with real
client work. It separates two jobs that are often confused:

1. **Free exposure audit:** inspect explicitly selected AI conversation records
   after the fact and show current, daily, and weekly risk trends.
2. **Local protection:** create sanitized copies before supported work is read
   by an AI.

Raw transcripts, files, detected values, custom terms, and private mappings stay
on the device. The baseline is risk reduction, not guaranteed anonymization,
compliance, or proof of a breach.

## Free AI exposure audit

The `audit-ai-exposure` Skill works across the packaged Codex, Claude Code, and
Gemini CLI integrations. It scans only transcript paths or exports the user
explicitly selects. It never claims background access to every AI client.

```bash
node skills/audit-ai-exposure/scripts/audit.mjs scan \
  --client codex \
  --term "Example Client" \
  ./synthetic-transcripts
```

Show the locally recorded trend without rescanning content:

```bash
node skills/audit-ai-exposure/scripts/audit.mjs report
```

The local event store contains only timestamps, client labels, counts,
categories, severities, and skip reasons. Repeated scans may observe the same
occurrence again, so the report does not call findings unique leaks.

Each report also contains a protection link with a random 128-bit installation
ID, local audit number, client label, and finding-count band. The scanner does
not open the link or make a network request. If the user chooses to open it,
those aggregate fields can connect first audit, repeat audit, checkout, and paid
conversion without sending transcript text, detected values, filenames, or
custom terms.

## Local safe copy

The `make-ai-safe-copy` Skill creates a separate `.ai-safe/` copy with stable
placeholders before an agent reads supported files.

```bash
node skills/make-ai-safe-copy/scripts/safectx.mjs sanitize \
  --out-dir .ai-safe \
  --term "Example Client" \
  ./example
```

Originals remain untouched. The aggregate report excludes detected values; a
mode-0600 private mapping remains local for optional restoration.

## Install

Agent Skills CLI:

```bash
npx skills add https://github.com/kuhung/contextarmor --skill audit-ai-exposure
npx skills add https://github.com/kuhung/contextarmor --skill make-ai-safe-copy
```

Codex CLI:

```bash
codex plugin marketplace add kuhung/contextarmor --ref main
codex plugin add contextarmor@contextarmor
```

Claude Code:

```bash
claude plugin marketplace add kuhung/contextarmor
claude plugin install contextarmor@contextarmor
```

Gemini CLI:

```bash
gemini extensions install kuhung/contextarmor --ref v0.4.1
```

## What stays local

- Selected transcripts and source files
- Detected values and custom client/project terms
- Aggregate day/week event history
- Random local installation ID used only after a user voluntarily opens the protection link
- Private placeholder mappings

The bundled scanners make no network requests. They do not silently modify
original files or claim access to AI history the host does not expose.

## Supported baseline

The exposure audit accepts UTF-8 `.txt`, `.md`, `.log`, `.json`, `.jsonl`,
`.ndjson`, `.csv`, `.yaml`, `.yml`, and `.xml` files up to 25 MB. The safe-copy
workflow supports common text, source, configuration, and data formats listed
in its Skill instructions.

Office documents, PDF, images, archives, metadata, comments, attachments, and
OCR layers are intentionally outside the current baseline. Contextual secrets
not provided as custom terms may remain.

## Product and research

- [See the local protection workflow](https://contextarmor.vercel.app/?utm_source=github&utm_medium=repository&utm_campaign=contextarmor-v1&utm_content=readme)
- [Report a missed category](https://github.com/kuhung/contextarmor/issues/new?template=missed-detection.yml)
- [Report an incorrect detection](https://github.com/kuhung/contextarmor/issues/new?template=false-positive.yml)
- [Share workflow feedback](https://github.com/kuhung/contextarmor/issues/new?template=workflow-feedback.yml)

Never paste real secrets, customer data, private transcripts, detected values,
or internal screenshots into a public issue.

## Development

Requires Node.js 22 or newer.

Release builds set `CONTEXTARMOR_PROTECTION_URL` to the deployed `/r/audit`
endpoint. Development and tests can override it without changing the local
scan or storage boundary.

```bash
npm test
```

Security and privacy reports: use the
[private contact form](https://safectx-ai-privacy.dainty-nova-4389.chatgpt.site/contact).
