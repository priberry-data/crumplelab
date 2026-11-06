# Changelog

## 0.2.1

- `crumple scan` no longer flags exact, fixed commands such as `Bash(curl -s http://localhost:4173/sitemap.xml)`.
  Only wildcard network rules can carry data out, so only those count.
- Single MCP tools (`mcp__server__tool`) are no longer flagged; whole servers and open `WebFetch` still are.
- Hooks in your own `.claude/settings.local.json` are no longer reported as shipped by the repository.
- Packages with install scripts are listed once each.

## 0.2.0

- 18 built-in traps, each from a real CVE, incident or paper, mapped to OWASP LLM, OWASP Agentic (ASI)
  and MITRE ATLAS. New: DNS exfiltration, git flag injection, dependency install scripts, poisoned
  take-home tests, invisible Unicode, auto-approve, poisoned MCP tool output, cloned-repo hooks.
- Every exit from the container is recorded (DNS, HTTP, TLS, MCP); fake keys are fresh per run and
  caught in any encoding. Results separate breached, hijacked-but-contained and held.
- `crumple scan`: local-only audit with a Safe Setup score, SARIF output and a CI failure threshold.
- `crumple lock`: MCP tool pinning; the guard refuses tools that aren't in the lock.
- `crumple fix --sandbox` and `--managed`; the guard reads lockfiles for install scripts and scans code
  before it runs.
- Trap packs (`--pack`), `crumple list`, a GitHub Action, and Codex CLI and Gemini CLI agents.

## 0.1.0

- Ten traps, the shell-parsing guard, `crumple fix`, share card and badge, Claude Code and mock agents.
