#!/usr/bin/env node

import { lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
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
  const values = [...argv];
  const mode =
    values[0] === "restore" || values[0] === "sanitize"
      ? values.shift()
      : "sanitize";
  const inputs = [];
  const terms = [];
  let outDir = ".ai-safe";
  let mappingPath = "";
  let inputFile = "";
  let outputFile = "";

  for (let index = 0; index < values.length; index += 1) {
    const arg = values[index];
    if (arg === "--out-dir") {
      outDir = values[index + 1] ?? "";
      index += 1;
    } else if (arg === "--term") {
      const term = values[index + 1]?.trim();
      if (term) terms.push(term);
      index += 1;
    } else if (arg === "--mapping") {
      mappingPath = values[index + 1] ?? "";
      index += 1;
    } else if (arg === "--input") {
      inputFile = values[index + 1] ?? "";
      index += 1;
    } else if (arg === "--output") {
      outputFile = values[index + 1] ?? "";
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      return {
        help: true,
        mode,
        inputs,
        terms,
        outDir,
        mappingPath,
        inputFile,
        outputFile,
      };
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      inputs.push(arg);
    }
  }
  return {
    help: false,
    mode,
    inputs,
    terms,
    outDir,
    mappingPath,
    inputFile,
    outputFile,
  };
}

function help() {
  console.log(`SafeContext local file sanitizer

Usage:
  node safectx.mjs sanitize [--out-dir .ai-safe] [--term "Company"] <path> [<path> ...]
  node safectx.mjs restore --mapping .ai-safe/private/mapping.json \\
    --input ai-response.txt --output restored-response.txt

The command writes sanitized copies under <out-dir>/files and an aggregate
report to <out-dir>/report.json. A private mode-0600 mapping supports local
restoration. Neither command prints detected or restored values.`);
}

async function collectFiles(inputPath, outputRoot, files, skipped) {
  const absolute = path.resolve(inputPath);
  let info;
  try {
    info = await lstat(absolute);
  } catch {
    skipped.push({ path: safeRelative(absolute), reason: "not_found" });
    return;
  }

  if (info.isSymbolicLink()) {
    skipped.push({ path: safeRelative(absolute), reason: "symlink" });
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

function createMappingState() {
  return {
    counters: new Map(),
    tokenByValue: new Map(),
    valueByToken: {},
  };
}

function sanitize(text, terms, state) {
  const matches = collectMatches(text, terms);
  const counts = {};
  let cursor = 0;
  let output = "";

  for (const match of matches) {
    const key = `${match.type}:${match.value.toLocaleLowerCase()}`;
    let token = state.tokenByValue.get(key);
    if (!token) {
      const next = (state.counters.get(match.type) ?? 0) + 1;
      state.counters.set(match.type, next);
      token = `<${match.type}_${next}>`;
      state.tokenByValue.set(key, token);
      state.valueByToken[token] = match.value;
    }
    output += text.slice(cursor, match.start);
    output += token;
    cursor = match.end;
    counts[match.type] = (counts[match.type] ?? 0) + 1;
  }
  output += text.slice(cursor);
  return { output, counts, findingCount: matches.length };
}

function restore(text, tokens) {
  let output = text;
  let restoredCount = 0;

  const entries = Object.entries(tokens)
    .filter(
      ([token, value]) =>
        /^<[A-Z]+_\d+>$/.test(token) &&
        typeof value === "string" &&
        value.length > 0,
    )
    .sort(([a], [b]) => b.length - a.length);

  for (const [token, value] of entries) {
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    output = output.replace(new RegExp(escaped, "gi"), () => {
      restoredCount += 1;
      return value;
    });
  }

  return {
    output,
    restoredCount,
    unresolvedTokens: [...new Set(output.match(/<[A-Z]+_\d+>/g) ?? [])],
  };
}

function safeOutputRelative(absolute) {
  const relative = path.relative(process.cwd(), absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    return path.basename(absolute);
  }
  return relative;
}

async function sanitizeFiles(args) {
  if (args.inputs.length === 0) {
    throw new Error("Sanitize mode requires at least one input path.");
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
  const mappingState = createMappingState();

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

    const result = sanitize(original, args.terms, mappingState);
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

  const privateDirectory = path.join(outputRoot, "private");
  const privateMappingPath = path.join(privateDirectory, "mapping.json");
  await mkdir(privateDirectory, { recursive: true, mode: 0o700 });
  await writeFile(
    privateMappingPath,
    `${JSON.stringify(
      {
        version: 1,
        generated_at: new Date().toISOString(),
        tokens: mappingState.valueByToken,
      },
      null,
      2,
    )}\n`,
    { encoding: "utf8", mode: 0o600 },
  );

  const report = {
    version: 2,
    generated_at: new Date().toISOString(),
    output_root: path.relative(process.cwd(), outputRoot) || ".",
    private_mapping_path: path.relative(process.cwd(), privateMappingPath),
    restoration_available: totalFindings > 0,
    processed_files: processed.length,
    total_findings: totalFindings,
    categories: aggregate,
    files: processed,
    skipped,
    limitations: [
      "Rule-based prototype; contextual secrets may remain.",
      "Office, PDF, image, archive, metadata, comments, and OCR layers are not processed.",
      "Review sanitized copies before external sharing.",
      "The private mapping contains original values; never share it with an AI or external service.",
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
      private_mapping: path.relative(process.cwd(), privateMappingPath),
      processed_files: processed.length,
      total_findings: totalFindings,
      categories: aggregate,
      skipped_files: skipped.length,
    }),
  );

  if (processed.length === 0) process.exitCode = 2;
}

async function restoreFile(args) {
  if (!args.mappingPath || !args.inputFile || !args.outputFile) {
    throw new Error(
      "Restore mode requires --mapping, --input, and --output paths.",
    );
  }

  const mappingPath = path.resolve(args.mappingPath);
  const inputPath = path.resolve(args.inputFile);
  const outputPath = path.resolve(args.outputFile);
  if (inputPath === outputPath || mappingPath === outputPath) {
    throw new Error("Restore output must be a new, separate file.");
  }

  const [inputInfo, mappingInfo] = await Promise.all([
    lstat(inputPath),
    lstat(mappingPath),
  ]);
  if (
    inputInfo.isSymbolicLink() ||
    !inputInfo.isFile() ||
    inputInfo.size > MAX_BYTES
  ) {
    throw new Error("Restore input must be a regular UTF-8 file under 5 MB.");
  }
  if (mappingInfo.isSymbolicLink() || !mappingInfo.isFile()) {
    throw new Error("Mapping must be a regular SafeContext mapping file.");
  }

  const mappingDocument = JSON.parse(await readFile(mappingPath, "utf8"));
  if (
    mappingDocument?.version !== 1 ||
    !mappingDocument.tokens ||
    typeof mappingDocument.tokens !== "object" ||
    Array.isArray(mappingDocument.tokens)
  ) {
    throw new Error("Unsupported or invalid SafeContext mapping.");
  }

  const aiResponse = await readFile(inputPath, "utf8");
  if (aiResponse.includes("\u0000")) {
    throw new Error("Restore input appears to contain binary content.");
  }

  const result = restore(aiResponse, mappingDocument.tokens);
  await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  await writeFile(outputPath, result.output, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });

  console.log(
    JSON.stringify({
      ok: true,
      output: safeRelative(outputPath),
      restored_placeholders: result.restoredCount,
      unresolved_placeholders: result.unresolvedTokens.length,
    }),
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    help();
    return;
  }
  if (args.mode === "restore") {
    await restoreFile(args);
    return;
  }
  await sanitizeFiles(args);
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, error: error.message }));
  process.exitCode = 1;
});
