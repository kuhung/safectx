import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = path.resolve(
  "skills/make-ai-safe-copy/scripts/safectx.mjs",
);

function run(args, cwd) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd,
    encoding: "utf8",
  });
}

test("creates a separate safe copy without exposing values in the report", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "safectx-public-test-"));
  const source = path.join(root, "source");
  await mkdir(source);
  const privateEmail = "maya.synthetic@example.com";
  const privateKey = "sk-live-SyntheticKey123";
  await writeFile(
    path.join(source, "sample.md"),
    `Contact ${privateEmail}. Example Project uses ${privateKey}.\n`,
  );

  const result = run(
    [
      "sanitize",
      "--out-dir",
      ".ai-safe",
      "--term",
      "Example Project",
      "source",
    ],
    root,
  );
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout, /maya\.synthetic|SyntheticKey123|Example Project/);

  const report = await readFile(
    path.join(root, ".ai-safe", "report.json"),
    "utf8",
  );
  const safeCopy = await readFile(
    path.join(root, ".ai-safe", "files", "source", "sample.md"),
    "utf8",
  );
  const mapping = path.join(root, ".ai-safe", "private", "mapping.json");

  assert.doesNotMatch(report, /maya\.synthetic|SyntheticKey123|Example Project/);
  assert.match(safeCopy, /<EMAIL_1>/);
  assert.match(safeCopy, /<SECRET_1>/);
  assert.match(safeCopy, /<CUSTOM_1>/);
  assert.equal((await stat(mapping)).mode & 0o777, 0o600);
});

test("keeps plugin metadata and distribution URLs aligned for 0.4.1", async () => {
  const files = [
    "package.json",
    ".codex-plugin/plugin.json",
    ".claude-plugin/plugin.json",
    ".claude-plugin/marketplace.json",
    ".agents/plugins/marketplace.json",
    "gemini-extension.json",
  ];
  const documents = await Promise.all(
    files.map(async (file) => JSON.parse(await readFile(file, "utf8"))),
  );

  assert.equal(documents[0].name, "contextarmor");
  assert.equal(documents[0].version, "0.4.1");
  assert.equal(documents[1].version, "0.4.1");
  assert.equal(documents[2].version, "0.4.1");
  assert.equal(documents[3].plugins[0].version, "0.4.1");
  assert.equal(documents[5].version, "0.4.1");

  for (const document of documents) {
    const serialized = JSON.stringify(document);
    assert.doesNotMatch(serialized, /kuhung\/safectx/);
  }
  assert.equal(documents[1].skills, "./skills/");
  assert.equal(documents[2].skills, "./skills/");
});
