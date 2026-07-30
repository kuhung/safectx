---
name: make-ai-safe-copy
description: Create sanitized local copies of text, code, configuration, Markdown, CSV, JSON, and similar files before their contents are shared with an AI. Use when a user wants to send files or workspace context to ChatGPT, Codex, Claude, Gemini, or another model and mentions secrets, credentials, PII, client data, confidential company terms, privacy, redaction, pseudonymization, or data-leakage risk.
---

# Make AI-Safe Copy

Create deterministic copies under `.ai-safe/` before reading file content into
the model context. Report what was detected without printing detected values.

## Non-negotiable boundary

- Do not read, summarize, grep, print, or otherwise place the original file
  contents into model context before sanitization.
- Use only paths the user supplied or clearly placed in scope.
- Never pass original contents as a command-line argument.
- Keep `.ai-safe/report.json` free of detected values and replacement mappings.
- Treat the output as risk reduction, not guaranteed anonymization or
  compliance. Ask the user to review it before external sharing.

## Workflow

1. Resolve the files or directory in scope without opening file contents.
2. Run the bundled local scanner:

   ```bash
   node "<skill-root>/scripts/safectx.mjs" \
     --out-dir ".ai-safe" \
     --term "optional company name" \
     <path> [<path> ...]
   ```

   Repeat `--term` for each company name, project codename, customer name, or
   other contextual identifier the user explicitly wants replaced. Omit it
   when none were provided.

3. Read `.ai-safe/report.json`. It contains only paths, counts, categories,
   sizes, and skipped-file reasons.
4. Tell the user how many files and findings were processed, which categories
   appeared, and which files were skipped.
5. Read or share only files inside `.ai-safe/files/` for the downstream AI
   task. Do not open the originals afterward unless the user explicitly asks
   and understands that doing so exposes them to the current model context.

## Supported first-version inputs

The scanner accepts regular UTF-8 text files and common source/config formats:
`.txt`, `.md`, `.csv`, `.json`, `.yaml`, `.yml`, `.toml`, `.env`, `.js`,
`.jsx`, `.ts`, `.tsx`, `.py`, `.go`, `.rs`, `.java`, `.rb`, `.php`, `.sql`,
`.html`, `.css`, and `.xml`.

It intentionally skips binaries, files over 5 MB, symlinks, generated
directories, and Office/PDF files. For Word, PDF, spreadsheet, image, archive,
or email inputs, explain that this validation plugin does not yet inspect
hidden content, metadata, OCR layers, comments, or attachments; do not create
a false sense of safety.

## Detection scope

The first version detects common API keys, AWS and GitHub credential shapes,
email addresses, phone numbers, US Social Security numbers, payment-card-like
numbers, IPv4 addresses, and explicit custom terms. Contextual trade secrets
that do not match an explicit term may remain.

## Failure handling

- If no supported files are found, stop and list the skip reasons.
- If a file cannot be decoded safely, leave it untouched and report it as
  skipped.
- If the output directory overlaps an input, exclude the output directory from
  scanning.
- Never silently overwrite the original file.
