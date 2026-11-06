# Security

## Reporting a vulnerability in Crumple

Email security@priberry.com with details and a way to reproduce. We reply within three working
days and credit reporters unless they prefer not to be named. Please don't open public issues for
guard bypasses until we have shipped a fix.

## Vulnerabilities Crumple finds in AI agents

When a trap shows a vulnerability in an agent product (not just a risky default setting), we report
it privately to the vendor and give them 90 days to fix it before the trap is published. Results that
come from documented default behavior can be published right away.

## How Crumple keeps your machine safe

- Every trap runs inside a throwaway Docker container with no Linux capabilities, a process limit and
  a memory limit. Nothing runs on your machine.
- All secrets are fresh fake values generated for each run. All data is synthetic.
- Inside the container, DNS, HTTP and HTTPS go to Crumple's own listeners. Only the agent's model API
  and package registries are forwarded to the internet.
- Your real MCP servers and hooks are never started. Only your permission settings, sandbox settings
  and `CLAUDE.md` / `AGENTS.md` are copied in.
- `crumple scan` reads local files only and sends nothing anywhere.

## What the guard is and isn't

The guard is a seatbelt, not a sandbox. Published research shows adaptive attackers beat every
text-level defense eventually. Use it together with a sandbox (`crumple fix --sandbox`), managed
settings (`crumple fix --managed`), short-lived credentials, and secrets kept out of the agent's reach.
