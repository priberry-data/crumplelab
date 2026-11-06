#!/usr/bin/env node
// The daily threat watch: what's new in attacks on AI coding agents, from public sources only.
// Prints a Markdown digest (empty when there's nothing new). The GitHub workflow turns it into an issue,
// so new advisories and attacks land in the Priberry inbox and become candidate traps.
//   node scripts/threat-watch.mjs [--days 1]
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { days: { type: "string", default: "1" } } });
const since = new Date(Date.now() - Number(values.days) * 86400e3);
const day = (d) => d.toISOString().slice(0, 10);

// The agents and plumbing Crumple tests. Advisories against these packages matter first.
const PACKAGES = ["@anthropic-ai/claude-code", "@openai/codex", "@google/gemini-cli", "@modelcontextprotocol/sdk", "mcp-remote", "@modelcontextprotocol/inspector", "@github/copilot"];
const CVE_WORDS = ["Claude Code", "Codex CLI", "Gemini CLI", "Model Context Protocol", "MCP server", "prompt injection", "Cursor", "GitHub Copilot", "coding agent"];
const NEWS_WORDS = ["prompt injection", "MCP vulnerability", "Claude Code security", "AI agent exploit", "coding agent attack", "slopsquatting"];

const get = async (url, headers = {}) => {
  const r = await fetch(url, { headers: { "user-agent": "crumple-threat-watch", ...headers } });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
};
const gh = process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {};
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

const sections = [];
const failures = [];

// 1. GitHub security advisories against the agents themselves.
{
  const rows = new Map();
  for (const pkg of PACKAGES) {
    try {
      const list = await get(`https://api.github.com/advisories?ecosystem=npm&affects=${encodeURIComponent(pkg)}&published=${day(since)}..${day(new Date())}&per_page=50`, gh);
      for (const a of list) rows.set(a.ghsa_id, `- **${a.severity?.toUpperCase() ?? "?"}** [${a.ghsa_id}](${a.html_url}) \`${pkg}\`: ${a.summary}`);
    } catch (e) { failures.push(`GitHub advisories (${pkg}): ${e.message}`); }
  }
  if (rows.size) sections.push(`## Advisories against the agents\n\n${[...rows.values()].join("\n")}`);
}

// 2. New CVEs that mention agents, MCP or prompt injection (NVD allows a few requests a minute without a key).
{
  const rows = new Map();
  for (const word of CVE_WORDS) {
    try {
      const q = new URLSearchParams({ keywordSearch: word, pubStartDate: since.toISOString().replace("Z", ""), pubEndDate: new Date().toISOString().replace("Z", "") });
      const res = await get(`https://services.nvd.nist.gov/rest/json/cves/2.0?${q}`);
      for (const v of res.vulnerabilities ?? []) {
        const cve = v.cve;
        const text = cve.descriptions?.find((d) => d.lang === "en")?.value ?? "";
        const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? cve.metrics?.cvssMetricV40?.[0]?.cvssData?.baseScore;
        rows.set(cve.id, `- [${cve.id}](https://nvd.nist.gov/vuln/detail/${cve.id})${score ? ` (CVSS ${score})` : ""} · _${word}_: ${text.slice(0, 280)}${text.length > 280 ? "…" : ""}`);
      }
    } catch (e) { failures.push(`NVD (${word}): ${e.message}`); }
    await pause(6500);
  }
  if (rows.size) sections.push(`## New CVEs\n\n${[...rows.values()].join("\n")}`);
}

// 3. What researchers and attackers are talking about.
{
  const rows = new Map();
  for (const word of NEWS_WORDS) {
    try {
      const res = await get(`https://hn.algolia.com/api/v1/search_by_date?tags=story&query=${encodeURIComponent(word)}&numericFilters=created_at_i>${Math.floor(since / 1000)}`);
      for (const h of res.hits ?? []) if (h.url) rows.set(h.url, `- [${h.title}](${h.url}) · ${h.points ?? 0} points · [discussion](https://news.ycombinator.com/item?id=${h.objectID})`);
    } catch (e) { failures.push(`Hacker News (${word}): ${e.message}`); }
  }
  if (rows.size) sections.push(`## In the news\n\n${[...rows.values()].join("\n")}`);
}

if (sections.length) {
  console.log(`New since ${day(since)}. For each item, ask: could an agent walk into this, and does Crumple have a trap for it? If not, it's a candidate trap.\n`);
  console.log(sections.join("\n\n"));
}
if (failures.length) console.log(`\n<details><summary>${failures.length} source(s) failed</summary>\n\n${failures.map((f) => `- ${f}`).join("\n")}\n</details>`);
