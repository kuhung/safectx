#!/usr/bin/env node

import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const MAX_BYTES = 5 * 1024 * 1024;
const SUPPORTED_EXTENSIONS = new Set([
  ".txt",
  ".md",
  ".csv",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".env",
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".py",
  ".go",
  ".rs",
  ".java",
  ".rb",
  ".php",
  ".sql",
  ".html",
  ".css",
  ".xml",
]);
const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".ai-safe",
  ".next",
  "build",
  "dist",
  "node_modules",
]);
const PATTERNS = [
  {
    type: "SECRET",
    severity: "high",
    regex:
      /\b(?:sk-(?:live|test)-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b/g,
  },
  {
    type: "SSN",
    severity: "high",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    type: "CARD",
    severity: "high",
    regex: /\b(?:\d[ -]*?){13,16}\b/g,
  },
  {
    type: "EMAIL",
    severity: "medium",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  {
    type: "PHONE",
    severity: "medium",
    regex: /(?<!\w)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\w)/g,
  },
  {
    type: "IP",
    severity: "medium",
    regex:
      /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  },
];

function parseArgs(argv) {
  const inputs = [];
  const terms = [];
  let outDir = ".ai-safe";

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--out-dir") {
      outDir = argv[index + 1] ?? "";
      index += 1;
    } else if (arg === "--term") {
      const term = argv[index + 1]?.trim();
      if (term) terms.push(term);
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      return { help: true, inputs, terms, outDir };
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      inputs.push(arg);
    }
  }
  return { help: false, inputs, terms, outDir };
}

function help() {
  console.log(`SafeContext local file sanitizer

Usage:
  node safectx.mjs [--out-dir .ai-safe] [--term "Company"] <path> [<path> ...]

The command writes sanitized copies under <out-dir>/files and an aggregate
report to <out-dir>/report.json. It never prints detected values.`);
}

async function collectFiles(inputPath, outputRoot, files, skipped) {
  const absolute = path.resolve(inputPath);
  let info;
  try {
    info = await stat(absolute);
  } catch {
    skipped.push({ path: safeRelative(absolute), reason: "not_found" });
    return;
  }

  if (absolute === outputRoot || absolute.startsWith(`${outputRoot}${path.sep}`)) {
    return;
  }

  if (info.isDirectory()) {
    if (IGNORED_DIRECTORIES.has(path.basename(absolute))) return;
    const entries = await readdir(absolute, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        skipped.push({
          path: safeRelative(path.join(absolute, entry.name)),
          reason: "symlink",
        });
        continue;
      }
      await collectFiles(path.join(absolute, entry.name), outputRoot, files, skipped);
    }
    return;
  }

  if (!info.isFile()) {
    skipped.push({ path: safeRelative(absolute), reason: "not_regular_file" });
    return;
  }

  const extension =
    path.basename(absolute) === ".env" ? ".env" : path.extname(absolute).toLowerCase();
  if (!SUPPORTED_EXTENSIONS.has(extension)) {
    skipped.push({ path: safeRelative(absolute), reason: "unsupported_type" });
    return;
  }
  if (info.size > MAX_BYTES) {
    skipped.push({ path: safeRelative(absolute), reason: "over_5mb" });
    return;
  }

  files.push({ absolute, size: info.size });
}

function safeRelative(absolute) {
  const relative = path.relative(process.cwd(), absolute);
  return relative.startsWith("..") ? path.basename(absolute) : relative;
}

function collectMatches(text, terms) {
  const matches = [];
  for (const pattern of PATTERNS) {
    pattern.regex.lastIndex = 0;
    for (const match of text.matchAll(pattern.regex)) {
      if (match.index === undefined) continue;
      matches.push({
        start: match.index,
        end: match.index + match[0].length,
        value: match[0],
        type: pattern.type,
        severity: pattern.severity,
      });
    }
  }

  for (const term of terms) {
    let from = 0;
    while (from < text.length) {
      const index = text.toLocaleLowerCase().indexOf(term.toLocaleLowerCase(), from);
      if (index < 0) break;
      matches.push({
        start: index,
        end: index + term.length,
        value: text.slice(index, index + term.length),
        type: "CUSTOM",
        severity: "high",
      });
      from = index + term.length;
    }
  }

  matches.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const accepted = [];
  for (const match of matches) {
    if (accepted.some((item) => match.start < item.end && match.end > item.start)) {
      continue;
    }
    accepted.push(match);
  }
  return accepted.sort((a, b) => a.start - b.start);
}

function sanitize(text, terms) {
  const matches = collectMatches(text, terms);
  const counters = new Map();
  const tokenByValue = new Map();
  const counts = {};
  let cursor = 0;
  let output = "";

  for (const match of matches) {
    const key = `${match.type}:${match.value.toLocaleLowerCase()}`;
    let token = tokenByValue.get(key);
    if (!token) {
      const next = (counters.get(match.type) ?? 0) + 1;
      counters.set(match.type, next);
      token = `<${match.type}_${next}>`;
      tokenByValue.set(key, token);
    }
    output += text.slice(cursor, match.start);
    output += token;
    cursor = match.end;
    counts[match.type] = (counts[match.type] ?? 0) + 1;
  }
  output += text.slice(cursor);
  return { output, counts, findingCount: matches.length };
}

function safeOutputRelative(absolute) {
  const relative = path.relative(process.cwd(), absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    return path.basename(absolute);
  }
  return relative;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    help();
    return;
  }
  if (args.inputs.length === 0) {
    help();
    process.exitCode = 2;
    return;
  }

  const outputRoot = path.resolve(args.outDir);
  const files = [];
  const skipped = [];
  for (const input of args.inputs) {
    await collectFiles(input, outputRoot, files, skipped);
  }

  const uniqueFiles = [...new Map(files.map((file) => [file.absolute, file])).values()];
  const processed = [];
  const aggregate = {};
  let totalFindings = 0;

  for (const file of uniqueFiles) {
    let original;
    try {
      original = await readFile(file.absolute, "utf8");
    } catch {
      skipped.push({ path: safeRelative(file.absolute), reason: "decode_or_read_error" });
      continue;
    }

    if (original.includes("\u0000")) {
      skipped.push({ path: safeRelative(file.absolute), reason: "binary_content" });
      continue;
    }

    const result = sanitize(original, args.terms);
    const relative = safeOutputRelative(file.absolute);
    const destination = path.join(outputRoot, "files", relative);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, result.output, "utf8");

    for (const [type, count] of Object.entries(result.counts)) {
      aggregate[type] = (aggregate[type] ?? 0) + count;
    }
    totalFindings += result.findingCount;
    processed.push({
      path: relative,
      output_path: path.relative(process.cwd(), destination),
      bytes: file.size,
      findings: result.findingCount,
      categories: Object.keys(result.counts),
    });
  }

  const report = {
    version: 1,
    generated_at: new Date().toISOString(),
    output_root: path.relative(process.cwd(), outputRoot) || ".",
    processed_files: processed.length,
    total_findings: totalFindings,
    categories: aggregate,
    files: processed,
    skipped,
    limitations: [
      "Rule-based prototype; contextual secrets may remain.",
      "Office, PDF, image, archive, metadata, comments, and OCR layers are not processed.",
      "Review sanitized copies before external sharing.",
    ],
  };

  await mkdir(outputRoot, { recursive: true });
  await writeFile(
    path.join(outputRoot, "report.json"),
    `${JSON.stringify(report, null, 2)}\n`,
    "utf8",
  );

  console.log(
    JSON.stringify({
      ok: processed.length > 0,
      report: path.relative(process.cwd(), path.join(outputRoot, "report.json")),
      processed_files: processed.length,
      total_findings: totalFindings,
      categories: aggregate,
      skipped_files: skipped.length,
    }),
  );

  if (processed.length === 0) process.exitCode = 2;
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, error: error.message }));
  process.exitCode = 1;
});
