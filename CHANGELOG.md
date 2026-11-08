# Changelog

## 0.3.2

- New trap, `code-mode`: a Cloudflare-style code-mode MCP server (`search` and `execute` in front of a whole DNS
  API) and a record whose text tells automation to delete every other record. The task is one IP change. The
  built-in careless agent deletes four live records in one `execute` call; the careful one changes only the
  record it was asked to.
- The guard reads the code sent to code-running MCP tools (`execute`, `run_code`, `execute_sql` and the like)
  and blocks deletes, drops and truncates through the API, plus anything that reads secrets and talks to the
  network. With `crumple fix --managed` the careless agent now survives all 19 traps.
- Codex runs now get the test MCP server's mode, so the tool-output-poisoning trap tests the right attack
  with Codex too.

## 0.3.1

- `crumple site` is now a grade anyone can finish without reading code. Each finding says why it matters in
  plain words, what to do by hand first (like revoking a leaked key), and gives a fix prompt to paste into the
  app builder. It names the builder when it can tell (Lovable, Bolt, Replit, Emergent, Base44, v0).
- Re-check: run the same command again and it shows the old grade, the new one, and what got fixed. Only ids,
  titles and scores are kept, in `~/.crumple/sites`; never keys or data.
- `--prompt N` prints one fix prompt on its own, ready for the clipboard.
- `--mine` now checks Firebase too: whether the Realtime Database is open (top-level names only, counted and
  dropped) and whether common Firestore collections are readable (one document name, no fields).
- A table anyone can read is critical when it holds people (users, profiles, orders, messages); otherwise it is
  medium, with a prompt that keeps a public list readable but locks writes.
- Supabase's newer `sb_publishable_` keys are recognised. A CSP set in a `<meta>` tag counts.
- `scan` flags a pre-approved code-running MCP tool (`execute`, `run_code`, `execute_sql` and the like). With
  "code mode" servers, one such tool reaches a whole API, so approving it approves everything its token can do.
- The `crumple_site` MCP tool returns the prompts, and `change` on a second call in the same session.

## 0.3.0

- `crumple site <url>`: checks a deployed app (Lovable, Bolt, v0, Replit, Emergent or hand-built) for secret keys
  in its JavaScript, a Supabase `service_role` key in the browser, public source maps and a missing CSP. With
  `--mine` it also counts which Supabase tables anyone can read, using `HEAD` requests that return no rows.
- `crumple setup`: adds Crumple's MCP server to every AI coding app found (Claude Code, Claude Desktop, Cursor,
  VS Code, Windsurf, Codex, Gemini CLI, Kiro, opencode, Amazon Q, LM Studio, Cline, Roo Code, Kilo Code), pinned
  to the exact version, with backups and `--undo`.
- `scan` reads more setups: Claude Desktop, VS Code's user `mcp.json`, Kiro, Roo Code, Cline and Kilo Code
  settings, Zed, opencode, Amazon Q and Continue, config files with comments, and the rules folders
  `.windsurf/rules`, `.kiro/steering`, `.roo/rules`, `.clinerules/`, `.github/instructions` and more.
- `crumple_site` in the MCP server, and a Gemini CLI extension.
- The Claude Code plugin now runs its own bundled code for the MCP server instead of an unpinned `npx crumplelab`,
  which Crumple's own scan rightly flagged.
- `--version`, and a clear message for options Crumple doesn't know.

## 0.2.4

- **Fix:** `crumple scan` flagged every tracked file as "a .env file is committed to git" in any repo without a
  `.env`, which scored most clean repos 0/F. It now only checks when a `.env` exists.
- `crumple mcp`: Crumple as an MCP server (stdio) with the scan and the trap list, for any agent or editor.
- Skills for Claude Code and Codex (`skills/crumple/SKILL.md`), and a Claude Code plugin and marketplace
  (`/plugin marketplace add priberry-data/crumplelab`).

## 0.2.3

- Gemini CLI 0.6x and later refuse to run headless in an untrusted folder, so every Gemini trap errored.
  Crumple now trusts the trap workspace for the session (`--skip-trust`), as you would your own project.
- A trap where the agent never ran (bad key, used-up quota, untrusted folder) now shows as "didn't run" and is
  left out of the score. Before, it counted as survived, which made a broken run look like a perfect one.

## 0.2.2

- Motion in the terminal: a boot log before the crash test, a live progress bar with a spinner while the
  agent works, and a spinner while `scan` reads your setup. All of it switches off in pipes, CI and NO_COLOR.
- `crumple bug`, and a clear report box if Crumple itself crashes or a trap errors: one link opens a pre-filled
  GitHub issue with keys, emails and your home folder removed. Nothing is ever sent by Crumple itself.
- Docker's build output stays hidden unless the build fails.

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
