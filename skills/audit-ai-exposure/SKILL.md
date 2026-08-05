---
name: audit-ai-exposure
description: Audit AI conversation transcripts, exported chats, or local agent records for possible secrets, PII, client identifiers, and other sensitive content after it has been shared with an AI. Use when a user asks how much sensitive information appeared in Codex, Claude Code, Gemini CLI, ChatGPT, Claude, or another AI conversation; wants a local privacy checkup; or wants current, daily, or weekly exposure statistics without uploading raw content.
---

# Audit AI Exposure

Run a post-exposure audit locally. Report counts and trends without printing
detected values or placing transcript contents into the current model context.

## Boundary

- State that this is an after-the-fact checkup, not a pre-send blocker.
- Scan only transcript files, exports, or paths the user explicitly supplies or
  clearly places in scope.
- Do not read, grep, summarize, print, or otherwise load original transcript
  contents into model context.
- Never pass original contents as command-line arguments.
- Never describe a detection occurrence as a confirmed breach or unique leak.
- Keep raw text and detected values on the device. The bundled script writes
  only aggregate events to its local statistics store.

## Scan

1. Resolve paths without opening their contents.
2. Choose a client label: `codex`, `claude-code`, `gemini-cli`,
   `chatgpt-export`, `claude-export`, or `other`.
3. Run:

   ```bash
   node "<skill-root>/scripts/audit.mjs" scan \
     --client codex \
     --term "optional client name" \
     <transcript-path> [<transcript-path> ...]
   ```

   Repeat `--term` only for client names, project codenames, internal domains,
   or other contextual identifiers the user explicitly provides. Omit it when
   none were provided.

4. Read the JSON printed by the script. It contains only aggregate counts,
   categories, severities, skipped-source reasons, and local trends.
5. Tell the user:
   - how many sources were checked;
   - how many possible exposure occurrences appeared in this audit;
   - the risk categories and severity totals;
   - today's and this week's locally observed totals;
   - the limitations and the fact that repeated scans can observe the same
     occurrence again.
6. If findings exist, point to the paid/local protection path configured by the
   product surface, but do not claim that this Skill prevented the exposure.

## Trends

To show the current local report without rescanning content, run:

```bash
node "<skill-root>/scripts/audit.mjs" report
```

The local store defaults to `~/.contextarmor/audit/`. Use `--store-dir` only
when the user requests another local location or when running tests. Do not
open the event store in model context; use the aggregate `report` command.

## Supported inputs

The first version accepts regular UTF-8 `.txt`, `.md`, `.log`, `.json`,
`.jsonl`, `.ndjson`, `.csv`, `.yaml`, `.yml`, and `.xml` files up to 25 MB. It
skips symlinks, binaries, unsupported formats, and generated directories.

For a web AI without locally accessible history, ask the user for an official
conversation export or another explicitly selected local transcript. Do not
claim that Codex, Claude Code, Gemini CLI, ChatGPT, and Claude expose identical
history or permissions.

## Detection scope

The baseline detector covers common credential shapes, JWTs, email addresses,
phone numbers, US Social Security numbers, payment-card-like numbers, Mainland
China ID shapes, IPv4 addresses, and explicit custom terms. Contextual trade
secrets not supplied as custom terms may remain.

## Failure handling

- If no supported source is found, list only aggregate skip reasons.
- If a source cannot be decoded safely, leave it untouched and report it as
  skipped.
- If the client cannot expose local history, explain the boundary and offer an
  official export workflow.
- Do not infer daily or weekly background monitoring. Trends include only
  explicit audits already recorded on this device.
