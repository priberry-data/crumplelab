// crumple scan --cves: checks the MCP servers your agents start (npx / bunx / pnpm dlx / uvx) against
// published vulnerabilities in OSV.dev, the open database that GitHub advisories and the CVE feeds
// flow into. Opt-in, because it is the one part of `scan` that goes online. Only package names and
// versions are sent (to osv.dev, and to the npm or PyPI registry to learn the newest version of
// servers that aren't pinned). Nothing about your project, files or keys leaves the machine.

const OSV = "https://api.osv.dev/v1";
const LEVEL = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

async function getJson(fetcher, url, init) {
  const res = await fetcher(url, { ...init, signal: AbortSignal.timeout(10000) });
  if (!res.ok) throw new Error(`${url} answered ${res.status}`);
  return res.json();
}

// An unpinned server runs whatever is newest, so check the newest version.
async function latest(fetcher, { ecosystem, name }) {
  if (ecosystem === "PyPI") return (await getJson(fetcher, `https://pypi.org/pypi/${encodeURIComponent(name)}/json`)).info?.version ?? null;
  return (await getJson(fetcher, `https://registry.npmjs.org/${name.replace("/", "%2F")}/latest`)).version ?? null;
}

// The first "fixed" version OSV lists for this package, if any.
function fixedIn(vuln, { ecosystem, name }) {
  for (const a of vuln.affected ?? []) {
    if (a.package?.ecosystem !== ecosystem || a.package?.name?.toLowerCase() !== name.toLowerCase()) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) return e.fixed;
  }
  return null;
}

const severityOf = (v) => LEVEL[String(v.database_specific?.severity ?? "").toUpperCase()] ?? "high";

export async function checkAdvisories(packages, { fetcher = globalThis.fetch } = {}) {
  const findings = [];
  const errors = [];
  const seen = new Map(); // ecosystem:name@version → where (several configs often start the same server)
  for (const p of packages) {
    let version = p.version;
    if (!version) {
      try {
        version = await latest(fetcher, p);
      } catch (e) {
        errors.push(`${p.name}: ${e.message}`);
        continue;
      }
    }
    if (!version) continue;
    const key = `${p.ecosystem}:${p.name}@${version}`;
    if (seen.has(key)) seen.get(key).wheres.push(p.where);
    else seen.set(key, { ...p, version, pinned: Boolean(p.version), wheres: [p.where] });
  }
  const list = [...seen.values()];
  if (!list.length) return { findings, errors, checked: 0 };
  let results;
  try {
    results = (await getJson(fetcher, `${OSV}/querybatch`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ queries: list.map((p) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version })) }),
    })).results ?? [];
  } catch (e) {
    return { findings, errors: [...errors, `osv.dev: ${e.message}`], checked: 0 };
  }
  for (const [i, p] of list.entries()) {
    for (const { id } of results[i]?.vulns ?? []) {
      let v;
      try {
        v = await getJson(fetcher, `${OSV}/vulns/${encodeURIComponent(id)}`);
      } catch (e) {
        errors.push(`${id}: ${e.message}`);
        continue;
      }
      const name = [...new Set([id, ...(v.aliases ?? []).filter((a) => a.startsWith("CVE-"))])].join(" / ");
      const fixed = fixedIn(v, p);
      findings.push({
        severity: severityOf(v),
        where: p.wheres.join(", "),
        title: `MCP server ${p.name}@${p.version} has a published vulnerability (${name})`,
        why: `${(v.summary || v.details || "See the advisory.").split("\n")[0].slice(0, 220)}${p.pinned ? "" : " This server isn't pinned and even the newest release is affected."}`,
        fix: fixed ? `Update to ${p.name}@${fixed} or later and pin it. Details: https://osv.dev/vulnerability/${id}` : `No fixed release yet. Remove the server or limit what it can reach until one ships. Details: https://osv.dev/vulnerability/${id}`,
        id,
      });
    }
  }
  return { findings, errors, checked: list.length };
}
