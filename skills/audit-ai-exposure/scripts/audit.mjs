#!/usr/bin/env node

import {
  appendFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import path from "node:path";
import process from "node:process";

const MAX_BYTES = 25 * 1024 * 1024;
const DEFAULT_STORE = path.join(homedir(), ".contextarmor", "audit");
const DEFAULT_PROTECTION_URL =
  "https://contextarmor.vercel.app/r/audit";
const SUPPORTED_EXTENSIONS = new Set([
  ".txt",
  ".md",
  ".log",
  ".json",
  ".jsonl",
  ".ndjson",
  ".csv",
  ".yaml",
  ".yml",
  ".xml",
]);
const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".ai-safe",
  ".contextarmor",
  ".next",
  "build",
  "dist",
  "node_modules",
]);
const CLIENTS = new Set([
  "codex",
  "claude-code",
  "gemini-cli",
  "chatgpt-export",
  "claude-export",
  "other",
]);
const PATTERNS = [
  {
    type: "SECRET",
    severity: "high",
    regex:
      /\b(?:sk-(?:(?:live|test|proj)-)?[A-Za-z0-9_-]{12,}|sk-ant-[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
  },
  {
    type: "JWT",
    severity: "high",
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    type: "US_SSN",
    severity: "high",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    type: "CN_ID",
    severity: "high",
    regex: /(?<!\d)\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?!\d)/g,
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
  const mode = values[0] === "scan" || values[0] === "report" ? values.shift() : "scan";
  const inputs = [];
  const terms = [];
  let client = "other";
  let storeDir = DEFAULT_STORE;

  for (let index = 0; index < values.length; index += 1) {
    const arg = values[index];
    if (arg === "--client") {
      client = values[index + 1] ?? "";
      index += 1;
    } else if (arg === "--store-dir") {
      storeDir = values[index + 1] ?? "";
      index += 1;
    } else if (arg === "--term") {
      const term = values[index + 1]?.trim();
      if (term) terms.push(term);
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      return { help: true, mode, inputs, terms, client, storeDir };
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      inputs.push(arg);
    }
  }

  if (!CLIENTS.has(client)) {
    throw new Error(`Unsupported client: ${client}`);
  }
  if (!storeDir) throw new Error("--store-dir requires a local path.");
  return { help: false, mode, inputs, terms, client, storeDir };
}

function help() {
  console.log(`ContextArmor local AI exposure audit

Usage:
  node audit.mjs scan --client codex [--term "Client"] <path> [<path> ...]
  node audit.mjs report [--store-dir <local-directory>]

The scan command reads explicitly selected local transcript files and stores
only aggregate counts. It never prints or stores detected values. Trends reflect
explicit audits, not background monitoring or unique confirmed breaches.`);
}

function safeExtension(filePath) {
  return path.extname(filePath).toLowerCase();
}

async function collectSources(inputPath, storeRoot, sources, skipped) {
  const absolute = path.resolve(inputPath);
  let info;
  try {
    info = await lstat(absolute);
  } catch {
    skipped.not_found = (skipped.not_found ?? 0) + 1;
    return;
  }

  if (info.isSymbolicLink()) {
    skipped.symlink = (skipped.symlink ?? 0) + 1;
    return;
  }
  if (absolute === storeRoot || absolute.startsWith(`${storeRoot}${path.sep}`)) return;

  if (info.isDirectory()) {
    if (IGNORED_DIRECTORIES.has(path.basename(absolute))) return;
    const entries = await readdir(absolute, { withFileTypes: true });
    for (const entry of entries) {
      await collectSources(path.join(absolute, entry.name), storeRoot, sources, skipped);
    }
    return;
  }

  if (!info.isFile()) {
    skipped.not_regular_file = (skipped.not_regular_file ?? 0) + 1;
    return;
  }
  if (!SUPPORTED_EXTENSIONS.has(safeExtension(absolute))) {
    skipped.unsupported_type = (skipped.unsupported_type ?? 0) + 1;
    return;
  }
  if (info.size > MAX_BYTES) {
    skipped.over_25mb = (skipped.over_25mb ?? 0) + 1;
    return;
  }
  sources.push({ absolute, size: info.size });
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
        type: pattern.type,
        severity: pattern.severity,
      });
    }
  }

  const lowered = text.toLocaleLowerCase();
  for (const term of terms) {
    const target = term.toLocaleLowerCase();
    let from = 0;
    while (from < lowered.length) {
      const index = lowered.indexOf(target, from);
      if (index < 0) break;
      matches.push({
        start: index,
        end: index + term.length,
        type: "CUSTOM",
        severity: "high",
      });
      from = index + term.length;
    }
  }

  matches.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const accepted = [];
  for (const match of matches) {
    if (accepted.some((item) => match.start < item.end && match.end > item.start)) continue;
    accepted.push(match);
  }
  return accepted;
}

function summarizeMatches(matches, categories, severities) {
  for (const match of matches) {
    categories[match.type] = (categories[match.type] ?? 0) + 1;
    severities[match.severity] = (severities[match.severity] ?? 0) + 1;
  }
}

function localDayKey(value) {
  const date = new Date(value);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function startOfLocalDay(date) {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate());
}

function startOfLocalWeek(date) {
  const start = startOfLocalDay(date);
  const day = start.getDay();
  start.setDate(start.getDate() - (day === 0 ? 6 : day - 1));
  return start;
}

function addSummary(target, event) {
  target.audits += 1;
  target.sources += event.processed_sources;
  target.findings += event.total_findings;
  for (const [type, count] of Object.entries(event.categories ?? {})) {
    target.categories[type] = (target.categories[type] ?? 0) + count;
  }
  for (const [severity, count] of Object.entries(event.severities ?? {})) {
    target.severities[severity] = (target.severities[severity] ?? 0) + count;
  }
}

function emptySummary() {
  return { audits: 0, sources: 0, findings: 0, categories: {}, severities: {} };
}

function findingBand(count) {
  if (count === 0) return "0";
  if (count <= 5) return "1-5";
  if (count <= 20) return "6-20";
  return "21plus";
}

async function ensureAnonymousInstallId(storeRoot) {
  const installIdPath = path.join(storeRoot, "anonymous-install-id");
  try {
    const existing = (await readFile(installIdPath, "utf8")).trim();
    if (/^[a-f0-9]{32}$/.test(existing)) return existing;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const created = randomBytes(16).toString("hex");
  try {
    await writeFile(installIdPath, `${created}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    return created;
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const existing = (await readFile(installIdPath, "utf8")).trim();
    if (!/^[a-f0-9]{32}$/.test(existing)) {
      throw new Error("Local anonymous installation identifier is invalid.");
    }
    return existing;
  }
}

function buildConversion(urlValue, anonymousId, event, auditNumber) {
  let url;
  try {
    url = new URL(urlValue || DEFAULT_PROTECTION_URL);
  } catch {
    url = new URL(DEFAULT_PROTECTION_URL);
  }
  if (url.protocol !== "https:") url = new URL(DEFAULT_PROTECTION_URL);
  url.searchParams.set("utm_source", "agent_skill");
  url.searchParams.set("utm_medium", "local_audit");
  url.searchParams.set("utm_campaign", "contextarmor_v1");
  url.searchParams.set("aid", anonymousId);
  url.searchParams.set("an", String(auditNumber));
  url.searchParams.set("client", event.client);
  url.searchParams.set("band", findingBand(event.total_findings));
  return {
    url: url.toString(),
    audit_number: auditNumber,
    repeat_audit: auditNumber > 1,
    finding_band: findingBand(event.total_findings),
    privacy:
      "The scanner makes no network request. Opening this link voluntarily shares only a random installation ID, audit number, client label, and finding-count band; never transcript text or detected values.",
  };
}

async function readEvents(eventsPath) {
  let raw;
  try {
    raw = await readFile(eventsPath, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }

  const events = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line);
      if (
        event?.version === 1 &&
        typeof event.scanned_at === "string" &&
        Number.isInteger(event.total_findings) &&
        Number.isInteger(event.processed_sources)
      ) {
        events.push(event);
      }
    } catch {
      // Ignore a malformed aggregate line instead of exposing its contents.
    }
  }
  return events;
}

function buildTrends(events, now = new Date()) {
  const todayStart = startOfLocalDay(now);
  const weekStart = startOfLocalWeek(now);
  const sevenDaysStart = startOfLocalDay(now);
  sevenDaysStart.setDate(sevenDaysStart.getDate() - 6);
  const today = emptySummary();
  const thisWeek = emptySummary();
  const last7Days = emptySummary();
  const dailyByKey = new Map();

  for (const event of events) {
    const timestamp = new Date(event.scanned_at);
    if (Number.isNaN(timestamp.getTime())) continue;
    if (timestamp >= todayStart) addSummary(today, event);
    if (timestamp >= weekStart) addSummary(thisWeek, event);
    if (timestamp >= sevenDaysStart) {
      addSummary(last7Days, event);
      const key = localDayKey(timestamp);
      if (!dailyByKey.has(key)) dailyByKey.set(key, emptySummary());
      addSummary(dailyByKey.get(key), event);
    }
  }

  const daily = [];
  for (let offset = 0; offset < 7; offset += 1) {
    const day = new Date(sevenDaysStart);
    day.setDate(day.getDate() + offset);
    const key = localDayKey(day);
    daily.push({ date: key, ...(dailyByKey.get(key) ?? emptySummary()) });
  }
  return { today, this_week: thisWeek, last_7_days: last7Days, daily };
}

async function ensureStore(storeRoot) {
  await mkdir(storeRoot, { recursive: true, mode: 0o700 });
  return {
    eventsPath: path.join(storeRoot, "events.jsonl"),
    reportPath: path.join(storeRoot, "latest-report.json"),
    installIdPath: path.join(storeRoot, "anonymous-install-id"),
  };
}

async function writeAggregateReport(storeRoot, payload) {
  const { reportPath } = await ensureStore(storeRoot);
  await writeFile(reportPath, `${JSON.stringify(payload, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

async function scan(args) {
  if (args.inputs.length === 0) {
    throw new Error("Scan mode requires at least one explicitly selected transcript path.");
  }

  const storeRoot = path.resolve(args.storeDir);
  const sources = [];
  const skipped = {};
  for (const input of args.inputs) {
    await collectSources(input, storeRoot, sources, skipped);
  }
  const uniqueSources = [...new Map(sources.map((source) => [source.absolute, source])).values()];
  const categories = {};
  const severities = {};
  let processedSources = 0;
  let totalFindings = 0;
  let totalBytes = 0;

  for (const source of uniqueSources) {
    let original;
    try {
      original = await readFile(source.absolute, "utf8");
    } catch {
      skipped.decode_or_read_error = (skipped.decode_or_read_error ?? 0) + 1;
      continue;
    }
    if (original.includes("\u0000")) {
      skipped.binary_content = (skipped.binary_content ?? 0) + 1;
      continue;
    }
    const matches = collectMatches(original, args.terms);
    summarizeMatches(matches, categories, severities);
    processedSources += 1;
    totalFindings += matches.length;
    totalBytes += source.size;
  }

  const store = await ensureStore(storeRoot);
  const event = {
    version: 1,
    scanned_at: new Date().toISOString(),
    client: args.client,
    processed_sources: processedSources,
    processed_bytes: totalBytes,
    total_findings: totalFindings,
    categories,
    severities,
    skipped_sources: skipped,
  };
  await appendFile(store.eventsPath, `${JSON.stringify(event)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  const events = await readEvents(store.eventsPath);
  const anonymousInstallId = await ensureAnonymousInstallId(storeRoot);
  const conversion = buildConversion(
    process.env.CONTEXTARMOR_PROTECTION_URL,
    anonymousInstallId,
    event,
    events.length,
  );
  const payload = {
    ok: processedSources > 0,
    boundary: "post_exposure_audit",
    unit: "detected_occurrences_across_explicit_audits",
    current_audit: event,
    engagement: {
      audit_number: events.length,
      repeat_audit: events.length > 1,
      locally_recorded_audits: events.length,
    },
    trends: buildTrends(events),
    conversion,
    limitations: [
      "Findings are possible exposure occurrences, not confirmed or unique breaches.",
      "Repeated scans can observe the same occurrence again.",
      "Only explicitly selected local sources were checked; there is no background monitoring.",
      "Rule-based baseline; contextual secrets not supplied as custom terms may remain.",
    ],
  };
  await writeAggregateReport(storeRoot, payload);
  console.log(JSON.stringify(payload));
  if (processedSources === 0) process.exitCode = 2;
}

async function report(args) {
  const storeRoot = path.resolve(args.storeDir);
  const { eventsPath } = await ensureStore(storeRoot);
  const events = await readEvents(eventsPath);
  const lastEvent = events.at(-1) ?? {
    client: "other",
    total_findings: 0,
  };
  const anonymousInstallId = await ensureAnonymousInstallId(storeRoot);
  const payload = {
    ok: true,
    boundary: "post_exposure_audit",
    unit: "detected_occurrences_across_explicit_audits",
    recorded_audits: events.length,
    engagement: {
      audit_number: events.length,
      repeat_audit: events.length > 1,
      locally_recorded_audits: events.length,
    },
    trends: buildTrends(events),
    conversion: buildConversion(
      process.env.CONTEXTARMOR_PROTECTION_URL,
      anonymousInstallId,
      lastEvent,
      events.length,
    ),
    limitations: [
      "Statistics include only explicit local audits recorded on this device.",
      "Repeated scans can observe the same occurrence again.",
    ],
  };
  await writeAggregateReport(storeRoot, payload);
  console.log(JSON.stringify(payload));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    help();
    return;
  }
  if (args.mode === "report") {
    await report(args);
    return;
  }
  await scan(args);
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, error: error.message }));
  process.exitCode = 1;
});
