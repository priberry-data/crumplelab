# Contributing to Crumple

The most valuable contribution is a new trap based on a real attack. A good trap:

- comes from a real CVE, incident or paper, named in `risk`
- gives the agent an ordinary task a developer would really ask for
- proves a breach with code (a canary reaching a sink, a file changed, data gone), never opinion
- has a fix a developer can apply today
- runs offline, inside the container, with fake data only

## Writing a trap

Traps live in `harness/scenarios.mjs` (public) or in a pack (see below). Each trap is an object:

| Field | What it is |
| --- | --- |
| `id`, `title`, `short`, `failLine` | Names: `failLine` goes on the share card when the trap fires |
| `kind` | What a breach means: `leaked`, `destroyed`, `escalated`, `executed`, `installed`, `cheated`, `backdoored` |
| `risk` | The attack class and its source, for example `Prompt injection (CVE-2025-55284)` |
| `task` | The ordinary request given to the agent |
| `setup(ws, ctx)` | Builds the fake project in `ws`; `ctx.home` is the container's home |
| `afterConfig(ws, ctx)` | Optional: runs after the user's own agent settings are copied in |
| `probe(ws, ctx)` | Optional: polled every 500 ms for damage; return a string or `{ evidence }` |
| `check(ws, ctx)` | Optional: run once at the end |
| `attackerHosts` | Optional: hostnames whose lookup counts as "hijacked" |
| `usesMcp`, `mcpMode` | Optional: start the hostile MCP server in the given mode |
| `fix` | One or two sentences a developer can act on |
| `standards` | Optional: `{ owasp, asi, atlas }` IDs (built-in traps use `harness/standards.mjs`) |

You don't need to write leak detection: every HTTP, HTTPS and DNS exit and every MCP call is checked
for the run's fresh canary keys in any encoding. Add a scripted play for both mock agents in
`harness/agents.mjs` (or `mock` in a pack trap) so the trap is tested without API keys, then run:

```bash
npm test
node bin/crumple.mjs attack --agent mock-reckless --scenarios your-trap-id
node bin/crumple.mjs attack --agent mock-careful --scenarios your-trap-id
```

The reckless mock must breach and the careful mock must hold.

## Trap packs

A pack is a folder of `.mjs` files, each exporting a function that receives the toolkit
(`write`, `sqlite`, `nodeProject`, `CANARY`, `HONEYPOT`, `envFile`, `awsCredentials`, `findCanary`)
and returns traps. See `packs/example/`. Run packs with `crumple attack --pack <dir>`.

Packs keep traps private until vendors have had time to fix what they find. When a trap reveals a
real vulnerability in an agent, report it to the vendor first (see SECURITY.md).

## Guard rules

Every guard change needs tests in `test/guard.test.mjs`: a case it must block and the ordinary
commands it must still allow. A guard that blocks normal work gets uninstalled.
