// Each trap mapped to the frameworks auditors and buyers use, so a Crumple report drops
// straight into an AIUC-1, ISO 42001 or SOC 2 evidence folder.
// OWASP LLM: Top 10 for LLM Applications 2025. ASI: OWASP Top 10 for Agentic Applications.
// ATLAS: MITRE ATLAS techniques.
export const NAMES = {
  LLM01: "Prompt Injection", LLM02: "Sensitive Information Disclosure", LLM03: "Supply Chain", LLM06: "Excessive Agency",
  ASI01: "Agent Goal Hijack", ASI02: "Tool Misuse and Exploitation", ASI03: "Identity and Privilege Abuse",
  ASI04: "Agentic Supply Chain Vulnerabilities", ASI05: "Unexpected Code Execution", ASI06: "Memory and Context Poisoning",
  ASI09: "Human-Agent Trust Exploitation", ASI10: "Rogue Agents",
  "AML.T0051": "LLM Prompt Injection", "AML.T0057": "LLM Data Leakage", "AML.T0010": "AI Supply Chain Compromise", "AML.T0053": "AI Agent Tool Invocation",
};

export const STANDARDS = {
  "poisoned-issue": { owasp: ["LLM01", "LLM02"], asi: ["ASI01"], atlas: ["AML.T0051", "AML.T0057"] },
  "prod-database": { owasp: ["LLM06"], asi: ["ASI02"], atlas: [] },
  "support-scam": { owasp: ["LLM01", "LLM02"], asi: ["ASI01", "ASI09"], atlas: ["AML.T0051", "AML.T0057"] },
  "code-mode": { owasp: ["LLM01", "LLM06"], asi: ["ASI01", "ASI02", "ASI05"], atlas: ["AML.T0051"] },
  "evil-mcp": { owasp: ["LLM01", "LLM03"], asi: ["ASI02", "ASI04"], atlas: ["AML.T0051", "AML.T0053"] },
  "disk-cleanup": { owasp: ["LLM06"], asi: ["ASI02"], atlas: [] },
  "self-escalation": { owasp: ["LLM01", "LLM06"], asi: ["ASI03"], atlas: ["AML.T0051"] },
  slopsquat: { owasp: ["LLM03"], asi: ["ASI04"], atlas: ["AML.T0010"] },
  "test-cheat": { owasp: ["LLM06"], asi: ["ASI10"], atlas: [] },
  "ci-exfil": { owasp: ["LLM01", "LLM02"], asi: ["ASI01", "ASI04"], atlas: ["AML.T0051"] },
  "force-push": { owasp: ["LLM06"], asi: ["ASI02"], atlas: [] },
  "dns-exfil": { owasp: ["LLM01", "LLM02"], asi: ["ASI01", "ASI02"], atlas: ["AML.T0051", "AML.T0057"] },
  "flag-injection": { owasp: ["LLM01", "LLM06"], asi: ["ASI02", "ASI05"], atlas: ["AML.T0051"] },
  "install-script": { owasp: ["LLM03"], asi: ["ASI04", "ASI05"], atlas: ["AML.T0010"] },
  "take-home": { owasp: ["LLM03"], asi: ["ASI05", "ASI09"], atlas: ["AML.T0010"] },
  "invisible-text": { owasp: ["LLM01"], asi: ["ASI01", "ASI06"], atlas: ["AML.T0051"] },
  "auto-approve": { owasp: ["LLM01", "LLM06"], asi: ["ASI03"], atlas: ["AML.T0051"] },
  "mcp-output-poison": { owasp: ["LLM01", "LLM02"], asi: ["ASI02", "ASI04"], atlas: ["AML.T0051", "AML.T0053", "AML.T0057"] },
  "repo-hooks": { owasp: ["LLM03"], asi: ["ASI04", "ASI05"], atlas: ["AML.T0010"] },
};

export const standardsOf = (s) => s.standards ?? STANDARDS[s.id] ?? { owasp: [], asi: [], atlas: [] };
export const tags = (s) => {
  const m = standardsOf(s);
  return [...m.owasp, ...m.asi, ...m.atlas];
};
