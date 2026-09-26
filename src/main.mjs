#!/usr/bin/env node
// sato-preflight-action — Preflight for your lockfile.
//
// Zero dependencies, no build step. Node 20+ (built-in fetch). Inputs arrive as
// INPUT_<NAME> environment variables, exactly as GitHub Actions passes them.
//
// WHAT THIS IS. It sends your dependency manifest to Sato Hub's Preflight batch
// endpoint and prints what Sato Hub has ON RECORD for each name: is it a listing
// we track, is it active, when was it last checked. That is all a verdict is.
//
// WHAT THIS IS NOT. Not a vulnerability scanner, not a licence checker, not a
// security review, and not an opinion about whether a package is safe to
// install. `go` is not "safe". `no` is "the listing is retired, or its observed
// record is mostly failure" — it is still not "dangerous".
//
// AND: `unknown` NEVER fails your build. A package Sato Hub has never heard of
// is unknown, which is a fact about Sato Hub's index, not about your dependency.
// If this action could redden a build over a name we simply do not index, the
// only rational response would be to stop running it.

import { readFileSync, existsSync, appendFileSync, writeFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { runCustody, UA } from "./custody.mjs";

const TIMEOUT_MS = 60_000;
const CAVEAT =
  "A Preflight verdict describes what Sato Hub has on record for a target and when it was read. It is not a security review, a vulnerability scan or a quality judgment, and `unknown` means no record — never a finding.";

// ---------- inputs ----------

function input(name, fallback = "") {
  const up = name.toUpperCase();
  const v = process.env[`INPUT_${up}`] ?? process.env[`INPUT_${up.replace(/-/g, "_")}`] ?? process.env[`INPUT_${up.replace(/_/g, "-")}`];
  if (v === undefined || v === null) return fallback;
  const s = String(v).trim();
  return s === "" ? fallback : s;
}
function boolInput(name, fallback) {
  const v = input(name, "").toLowerCase();
  if (v === "") return fallback;
  return v === "true" || v === "1" || v === "yes";
}
function listInput(name) {
  return input(name, "").split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
}

// ---------- GitHub Actions plumbing ----------

function esc(s) {
  return String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function warn(msg) { console.log(`::warning::${esc(msg)}`); }
function fail(msg) { console.log(`::error::${esc(msg)}`); }
function notice(msg) { console.log(`::notice::${esc(msg)}`); }

function annotate(level, file, line, message) {
  const loc = file ? `file=${esc(file)}${line ? `,line=${line}` : ""}` : "";
  console.log(`::${level} ${loc}::${esc(message)}`);
}

function setOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  const v = String(value ?? "");
  if (!f) { console.log(`${name}=${v}`); return; }
  const delim = `ghadelim_${Math.random().toString(36).slice(2)}`;
  appendFileSync(f, `${name}<<${delim}\n${v}\n${delim}\n`);
}

function writeSummary(md) {
  const f = process.env.GITHUB_STEP_SUMMARY;
  if (f) { try { appendFileSync(f, md + "\n"); return; } catch { /* fall through */ } }
  console.log(md);
}

// ---------- the manifest ----------

function kindFor(path) {
  const p = path.toLowerCase();
  if (p.endsWith("package.json")) return "package.json";
  if (/requirements[^/]*\.txt$/.test(p)) return "requirements.txt";
  return null;
}

function readManifest() {
  const path = input("manifest", "package.json");
  if (path.toLowerCase() === "false" || path === "") return null;
  const abs = resolvePath(process.cwd(), path);
  if (!existsSync(abs)) {
    // Not an error: a repo with only explicit inputs, or a python repo where the
    // default package.json does not exist, is a legitimate way to use this.
    notice(`No manifest at ${path}; checking only the explicit inputs.`);
    return null;
  }
  const kind = input("manifest-kind", "") || kindFor(path);
  if (kind !== "package.json" && kind !== "requirements.txt") {
    warn(`Cannot tell what kind of manifest ${path} is. Set manifest-kind to package.json or requirements.txt.`);
    return null;
  }
  return { path, kind, text: readFileSync(abs, "utf8") };
}

// ---------- the call ----------

async function callBatch(api, body) {
  const url = `${api.replace(/\/$/, "")}/api/preflight/batch`;
  const res = await fetch(url, {
    method: "POST",
    // One user-agent for every call (custody.mjs UA): the published name by
    // default, SATO_CHECK_UA when Sato Hub's own CI runs the Action.
    headers: { "content-type": "application/json", "user-agent": UA },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* leave null */ }
  return { status: res.status, json, text };
}

// ---------- the table ----------

const ICON = { go: "🟢", caution: "🟡", no: "🔴", unknown: "⚪" };

function table(results) {
  const rows = [...results].sort((a, b) => rank(a.verdict) - rank(b.verdict) || a.target.localeCompare(b.target));
  const lines = ["| | target | verdict | rule | what was read |", "|---|---|---|---|---|"];
  for (const r of rows) {
    const first = r.reason ?? (r.evidence?.[0] ? `${r.evidence[0].check}: ${r.evidence[0].result}` : "no checks were run");
    const name = r.sato_url ? `[\`${r.target}\`](${r.sato_url})` : `\`${r.target}\``;
    lines.push(`| ${ICON[r.verdict] ?? ""} | ${name} | \`${r.verdict}\` | ${r.rule} | ${String(first).replace(/\|/g, "\\|")} |`);
  }
  return lines.join("\n");
}
function rank(v) { return { no: 0, caution: 1, unknown: 2, go: 3 }[v] ?? 9; }

function plainTable(results) {
  const w = Math.min(46, Math.max(12, ...results.map((r) => r.target.length)));
  const out = [];
  for (const r of [...results].sort((a, b) => rank(a.verdict) - rank(b.verdict) || a.target.localeCompare(b.target))) {
    out.push(`  ${(ICON[r.verdict] ?? " ")} ${r.verdict.padEnd(8)} ${r.target.slice(0, w).padEnd(w)}  ${r.rule}`);
  }
  return out.join("\n");
}

// ---------- main ----------

// fail_on is a comma list: one Preflight level (no | caution | none) plus, since
// v1.1, the custody opt-in `key_egress_observed`. `fail-on` is accepted as an alias.
function failOnList() {
  return `${input("fail_on", "")},${input("fail-on", "")}`.toLowerCase().split(/[\s,]+/).filter(Boolean);
}

async function preflight() {
  const api = input("api", "https://satohub.ai");
  const levels = failOnList().filter((v) => v !== "key_egress_observed");
  const failOn = levels[0] || "no";
  if (!["no", "caution", "none"].includes(failOn)) {
    warn(`fail_on must be no, caution or none (plus optionally key_egress_observed); got "${failOn}". Using "no".`);
  }
  const manifest = readManifest();
  const body = {
    fail_on: ["no", "caution", "none"].includes(failOn) ? failOn : "no",
    packages: listInput("packages"),
    repos: listInput("repos"),
    endpoints: listInput("endpoints"),
    agents: listInput("agents"),
  };
  if (manifest) {
    body.manifest = manifest.text;
    body.manifest_kind = manifest.kind;
    body.manifest_path = manifest.path;
  }
  if (!manifest && !body.packages.length && !body.repos.length && !body.endpoints.length && !body.agents.length) {
    warn("Nothing to check: no manifest was found and no explicit inputs were given.");
    setOutput("verdict", "unknown");
    for (const k of ["go", "caution", "no", "unknown", "total"]) setOutput(k, 0);
    return 0;
  }

  let out;
  try {
    out = await callBatch(api, body);
  } catch (e) {
    // The endpoint being unreachable is not a verdict about anybody's code.
    warn(`Sato Hub Preflight was unreachable (${e?.message || e}). Reported as unknown; not failing the build.`);
    setOutput("verdict", "unknown");
    return 0;
  }

  if (out.status !== 200 || !out.json) {
    const msg = out.json?.error || `HTTP ${out.status}`;
    if (out.status === 404 || out.status === 405) {
      // Not "refused": there is nothing at that path. Either `api` points
      // somewhere else, or this endpoint is not deployed there yet.
      notice(`No Preflight batch endpoint at ${api.replace(/\/$/, "")}/api/preflight/batch (HTTP ${out.status}). Nothing checked; not failing the build.`);
    } else if (out.status >= 400 && out.status < 500) {
      // A 4xx is OUR request being wrong, which is worth seeing and still not a
      // reason to redden someone's build over their dependencies.
      warn(`Sato Hub Preflight refused the request: ${msg}`);
    } else {
      warn(`Sato Hub Preflight answered ${out.status}. Reported as unknown; not failing the build.`);
    }
    setOutput("verdict", "unknown");
    return 0;
  }

  const { summary, results, findings, exit_code, skipped, manifest_path } = out.json;

  // ---------- annotations ----------
  if (boolInput("annotations", true) && Array.isArray(findings)) {
    for (const f of findings) {
      if (f.level === "note") continue; // go and unknown do not belong in a diff
      const loc = f.locations?.[0]?.physicalLocation;
      annotate(f.level === "error" ? "error" : "warning", loc?.artifactLocation?.uri, loc?.region?.startLine, f.message?.text ?? "");
    }
  }

  // ---------- the SARIF log ----------
  let sarifPath = "";
  if (Array.isArray(findings) && findings.length) {
    sarifPath = resolvePath(process.env.RUNNER_TEMP || process.cwd(), "sato-preflight.sarif");
    const log = {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Sato Hub Preflight",
              informationUri: `${api.replace(/\/$/, "")}/preflight`,
              rules: ["go", "caution", "no", "unknown"].map((v) => ({
                id: `sato-preflight/${v}`,
                name: `preflight-${v}`,
                shortDescription: { text: `Preflight verdict: ${v}` },
                fullDescription: { text: CAVEAT },
                helpUri: `${api.replace(/\/$/, "")}/preflight/methodology`,
              })),
            },
          },
          results: findings,
        },
      ],
    };
    try { writeFileSync(sarifPath, JSON.stringify(log, null, 2)); } catch { sarifPath = ""; }
  }

  // ---------- the report ----------
  const head = `${summary.go} go · ${summary.caution} caution · ${summary.no} no · ${summary.unknown} unknown (${summary.total} checked)`;
  console.log(`Sato Hub Preflight — ${head}`);
  if (results.length) console.log(plainTable(results));

  const md = [
    "## Sato Hub Preflight",
    "",
    `**${head}**${manifest_path ? ` — \`${manifest_path}\`` : ""}`,
    "",
    results.length ? table(results) : "_Nothing was checked._",
    "",
    skipped?.length ? `_Skipped: ${skipped.map((s) => `\`${s.value}\` (${s.reason})`).join(", ")}_\n` : "",
    `> ${CAVEAT}`,
    "",
    `[Preflight](${api.replace(/\/$/, "")}/preflight) · [methodology](${api.replace(/\/$/, "")}/preflight/methodology)`,
  ].join("\n");
  writeSummary(md);

  setOutput("verdict", summary.no ? "no" : summary.caution ? "caution" : summary.go ? "go" : "unknown");
  setOutput("go", summary.go);
  setOutput("caution", summary.caution);
  setOutput("no", summary.no);
  setOutput("unknown", summary.unknown);
  setOutput("total", summary.total);
  setOutput("sarif", sarifPath);
  setOutput("report", md);

  if (exit_code) {
    fail(`Preflight: ${summary.no} target(s) came back \`no\`${failOn === "caution" ? ` and ${summary.caution} \`caution\`` : ""}. See the job summary for what was read.`);
    return 1;
  }
  if (summary.unknown) notice(`${summary.unknown} target(s) are not in the Sato Hub index. That is a gap in our records, not a finding about your dependencies.`);
  return 0;
}

async function main() {
  const code = await preflight();
  if (!boolInput("custody", true)) return code;
  const custody = await runCustody({
    api: input("api", "https://satohub.ai"),
    failOn: failOnList(),
    token: input("github-token", ""),
    io: { summary: writeSummary },
  });
  if (custody.skipped) console.log(`Sato Check diff mode skipped: ${custody.skipped}.`);
  setOutput("custody_subjects", custody.subjects ?? 0);
  setOutput("key_egress_observed", custody.egress ? "true" : "false");
  setOutput("policy_violations", custody.violations ?? 0);
  return code || custody.code;
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    // A crash in the action itself is not a verdict about anyone's code.
    warn(`sato-preflight-action crashed: ${e?.message || e}. Not failing the build.`);
    process.exit(0);
  });
