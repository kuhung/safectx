import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = path.resolve(
  "skills/audit-ai-exposure/scripts/audit.mjs",
);

function run(args, cwd) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd,
    encoding: "utf8",
  });
}

test("audits selected transcripts and stores only aggregate local trends", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "contextarmor-audit-test-"));
  const transcripts = path.join(root, "transcripts");
  const store = path.join(root, "private-stats");
  await mkdir(transcripts);
  const privateEmail = "maya.synthetic@example.com";
  const privateKey = "sk-proj-SyntheticKey123456";
  const privateTerm = "Project Atlas";
  await writeFile(
    path.join(transcripts, "conversation.jsonl"),
    `${JSON.stringify({ role: "user", text: `Contact ${privateEmail} about ${privateTerm}.` })}\n` +
      `${JSON.stringify({ role: "user", text: `Temporary key ${privateKey}` })}\n`,
  );

  const result = run(
    [
      "scan",
      "--client",
      "codex",
      "--store-dir",
      store,
      "--term",
      privateTerm,
      transcripts,
    ],
    root,
  );
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout, /maya\.synthetic|SyntheticKey|Project Atlas/);

  const payload = JSON.parse(result.stdout);
  assert.equal(payload.boundary, "post_exposure_audit");
  assert.equal(payload.current_audit.processed_sources, 1);
  assert.equal(payload.current_audit.total_findings, 3);
  assert.deepEqual(payload.current_audit.categories, {
    CUSTOM: 1,
    EMAIL: 1,
    SECRET: 1,
  });
  assert.equal(payload.trends.today.audits, 1);
  assert.equal(payload.trends.today.findings, 3);
  assert.equal(payload.trends.daily.length, 7);

  const eventsPath = path.join(store, "events.jsonl");
  const reportPath = path.join(store, "latest-report.json");
  const events = await readFile(eventsPath, "utf8");
  const report = await readFile(reportPath, "utf8");
  assert.doesNotMatch(events, /maya\.synthetic|SyntheticKey|Project Atlas|conversation\.jsonl/);
  assert.doesNotMatch(report, /maya\.synthetic|SyntheticKey|Project Atlas|conversation\.jsonl/);
  assert.equal((await stat(store)).mode & 0o777, 0o700);
  assert.equal((await stat(eventsPath)).mode & 0o777, 0o600);
  assert.equal((await stat(reportPath)).mode & 0o777, 0o600);

  const trendResult = run(["report", "--store-dir", store], root);
  assert.equal(trendResult.status, 0, trendResult.stderr);
  const trend = JSON.parse(trendResult.stdout);
  assert.equal(trend.recorded_audits, 1);
  assert.equal(trend.trends.this_week.findings, 3);
});

test("makes repeated observations explicit instead of claiming unique leaks", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "contextarmor-repeat-test-"));
  const store = path.join(root, "stats");
  const source = path.join(root, "chat.md");
  await writeFile(source, "Synthetic contact: repeat.synthetic@example.com\n");

  for (let index = 0; index < 2; index += 1) {
    const result = run(
      ["scan", "--client", "claude-code", "--store-dir", store, source],
      root,
    );
    assert.equal(result.status, 0, result.stderr);
  }

  const trendResult = run(["report", "--store-dir", store], root);
  const trend = JSON.parse(trendResult.stdout);
  assert.equal(trend.recorded_audits, 2);
  assert.equal(trend.trends.today.audits, 2);
  assert.equal(trend.trends.today.findings, 2);
  assert.match(trend.limitations.join(" "), /Repeated scans/);
});

test("reports unsupported sources without exposing their paths", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "contextarmor-skip-test-"));
  const store = path.join(root, "stats");
  const source = path.join(root, "private-document.pdf");
  await writeFile(source, "synthetic content");

  const result = run(
    ["scan", "--client", "gemini-cli", "--store-dir", store, source],
    root,
  );
  assert.equal(result.status, 2, result.stderr);
  assert.doesNotMatch(result.stdout, /private-document\.pdf/);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.current_audit.processed_sources, 0);
  assert.equal(payload.current_audit.skipped_sources.unsupported_type, 1);
});

test("rejects unknown client labels", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "contextarmor-client-test-"));
  const source = path.join(root, "chat.txt");
  await writeFile(source, "synthetic transcript");
  const result = run(["scan", "--client", "unknown-client", source], root);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unsupported client/);
});
