// crumple site <url>: checks a deployed app the way a curious stranger would, for the mistakes that
// AI app builders (Lovable, Bolt, v0, Replit, Emergent and the rest) ship most often:
//   - secret keys inside the JavaScript every visitor downloads
//   - a Supabase database whose tables anyone can read with the public key (with --mine only)
//   - source maps that hand out the whole source code
// It reads only what the site serves to every visitor. The database check asks Postgres for a row
// count, never for rows, and runs only when you say the app is yours.
import { SEVERITY } from "./scan.mjs";

const SECRETS = [
  [/sk_live_[0-9A-Za-z]{20,}/, "A live Stripe secret key", "Anyone can charge, refund and read your customers' payments."],
  [/rk_live_[0-9A-Za-z]{20,}/, "A live Stripe restricted key", "Anyone can do whatever this key allows on your Stripe account."],
  [/sk-(proj|svcacct|admin)-[0-9A-Za-z_-]{20,}|sk-[0-9A-Za-z]{48}\b/, "An OpenAI API key", "Anyone can run up your OpenAI bill."],
  [/sk-ant-[0-9A-Za-z_-]{20,}/, "An Anthropic API key", "Anyone can run up your Anthropic bill."],
  [/AKIA[0-9A-Z]{16}/, "An AWS access key", "Depending on its rights: your servers, storage and bill."],
  [/gh[pousr]_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{20,}/, "A GitHub token", "Access to your code, and possibly the right to change it."],
  [/xox[bpas]-[0-9A-Za-z-]{10,}/, "A Slack token", "Anyone can read or post in your Slack."],
  [/re_[0-9A-Za-z]{8}_[0-9A-Za-z]{20,}/, "A Resend API key", "Anyone can send email as you."],
  [/SG\.[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}/, "A SendGrid API key", "Anyone can send email as you."],
  [/AC[0-9a-f]{32}[^0-9a-f][\s\S]{0,80}?[0-9a-f]{32}/, "Twilio credentials", "Anyone can send texts and make calls on your account."],
  [/gsk_[0-9A-Za-z]{40,}/, "A Groq API key", "Anyone can run up your Groq bill."],
  [/AIza[0-9A-Za-z_-]{35}(?=[\s\S]{0,400}(generativelanguage|gemini))/, "A Google AI (Gemini) API key", "Anyone can run up your Gemini bill. (Firebase keys are public by design; this one sits next to Gemini calls.)"],
];
const JWT = /eyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}/g;
const SUPABASE_URL = /https:\/\/([a-z0-9]{20})\.supabase\.co/;

const decodeJwt = (t) => {
  try {
    return JSON.parse(Buffer.from(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch {
    return null;
  }
};

async function get(url, { timeout = 15000, headers = {}, method = "GET", max = 8 * 1024 * 1024, fetcher = fetch } = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetcher(url, { method, headers: { "user-agent": "crumple-site (+https://crumple.priberry.com)", ...headers }, signal: ctl.signal, redirect: "follow" });
    const text = method === "HEAD" ? "" : (await r.text()).slice(0, max);
    return { status: r.status, headers: r.headers, text, url: r.url };
  } catch (e) {
    return { status: 0, error: e.name === "AbortError" ? "timed out" : e.message, text: "" };
  } finally {
    clearTimeout(t);
  }
}

export async function siteScan(target, { mine = false, fetcher = fetch, maxScripts = 40 } = {}) {
  const fetchOpts = (o = {}) => ({ ...o, fetcher });
  const url = new URL(/^https?:\/\//.test(target) ? target : `https://${target}`);
  const findings = [];
  const add = (severity, where, title, why, fix) => findings.push({ severity, where, title, why, fix });

  const page = await get(url.href, fetchOpts());
  if (!page.status || page.status >= 400) throw new Error(`could not load ${url.href} (${page.error || page.status})`);
  const origin = new URL(page.url || url.href).origin;

  // Every script the page loads from its own site, plus the scripts those import.
  const srcs = new Set();
  const collect = (html, base) => {
    for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) srcs.add(new URL(m[1], base).href);
    for (const m of html.matchAll(/<link[^>]+href=["']([^"']+\.m?js)["']/gi)) srcs.add(new URL(m[1], base).href);
  };
  collect(page.text, origin);
  const bundles = [{ where: "the page itself", text: page.text }];
  const seen = new Set();
  for (let pass = 0; pass < 2; pass++) {
    for (const src of [...srcs]) {
      if (seen.has(src) || seen.size >= maxScripts || new URL(src).origin !== origin) continue;
      seen.add(src);
      const r = await get(src, fetchOpts());
      if (r.status !== 200) continue;
      bundles.push({ where: new URL(src).pathname, text: r.text, url: src });
      for (const m of r.text.matchAll(/(?:import\(|from\s*)["'](\.{0,2}\/[^"']+\.m?js)["']/g)) srcs.add(new URL(m[1], src).href);
    }
  }

  let supabase = null;
  const keysSeen = new Set();
  for (const b of bundles) {
    for (const [re, title, why] of SECRETS) {
      const m = b.text.match(re);
      if (m && !keysSeen.has(m[0])) {
        keysSeen.add(m[0]);
        add("critical", b.where, `${title} is in code every visitor downloads`, `${why} Found: ${m[0].slice(0, 8)}…`, "Revoke this key now, make a new one, and call that service only from your backend (an edge function or server route), never from the browser.");
      }
    }
    for (const t of b.text.match(JWT) || []) {
      const p = decodeJwt(t);
      if (!p) continue;
      if (p.role === "service_role" && !keysSeen.has(t)) {
        keysSeen.add(t);
        add("critical", b.where, "Your Supabase service_role key is in the browser code", "This key skips every security rule: anyone can read, change and delete all of your data and users.", "Rotate it in Supabase (Settings → API) and use it only on a server. The browser should only ever have the anon key.");
      }
      if (p.role === "anon" && p.iss === "supabase") supabase = { ...(supabase || {}), anon: t, ref: p.ref };
    }
    const su = b.text.match(SUPABASE_URL);
    if (su) supabase = { ...(supabase || {}), url: su[0], ref: supabase?.ref || su[1] };
    if (b.url && /sourceMappingURL=([^\s'"]+\.map)/.test(b.text)) {
      const mapUrl = new URL(b.text.match(/sourceMappingURL=([^\s'"]+\.map)/)[1], b.url).href;
      const r = await get(mapUrl, fetchOpts({ method: "HEAD" }));
      if (r.status === 200 && !findings.some((f) => f.title.startsWith("Source maps")))
        add("medium", new URL(mapUrl).pathname, "Source maps are public", "Anyone can read your app's original source code, including comments and any logic you assumed was hidden.", "Turn off source maps in production builds (for Vite: build.sourcemap = false).");
    }
  }

  // Supabase: with the public anon key, which tables can anyone read?
  let tables = null;
  if (supabase?.url && supabase.anon) {
    if (!mine) {
      add("low", "Supabase", "Database checks skipped", "This app uses Supabase. Crumple can check which tables anyone on the internet can read, but only for an app you own.", `Run \`npx crumplelab site ${url.host} --mine\` if this is your app.`);
    } else {
      const h = { apikey: supabase.anon, authorization: `Bearer ${supabase.anon}` };
      const api = await get(`${supabase.url}/rest/v1/`, fetchOpts({ headers: h }));
      let names = [];
      try {
        names = Object.keys(JSON.parse(api.text).paths || {}).map((p) => p.slice(1)).filter((p) => p && !p.startsWith("rpc/"));
      } catch {}
      tables = [];
      for (const t of names.slice(0, 60)) {
        // A HEAD request with count=exact returns how many rows are visible, and no rows.
        const r = await get(`${supabase.url}/rest/v1/${encodeURIComponent(t)}?select=*`, fetchOpts({ method: "HEAD", headers: { ...h, prefer: "count=exact", range: "0-0" } }));
        const n = Number((r.headers?.get("content-range") || "").split("/")[1]);
        if (r.status < 300 && n > 0) tables.push({ table: t, rows: n });
      }
      for (const { table, rows } of tables) {
        const personal = /user|profile|customer|account|order|payment|message|contact|lead|email|subscri|invoice/i.test(table);
        add(personal ? "critical" : "high", `Supabase table "${table}"`, `Anyone on the internet can read ${rows.toLocaleString("en-US")} row${rows > 1 ? "s" : ""} of "${table}"`, "The anon key is public (it ships in your app), so a table without Row Level Security is readable by everyone. This is how most vibe-coded apps have leaked data.", `In Supabase, open Table Editor → ${table} → turn on RLS, then add a policy so people read only their own rows (for example: auth.uid() = user_id).`);
      }
    }
  }

  if (!page.headers?.get("content-security-policy")) add("low", "response headers", "No Content-Security-Policy", "If an attacker gets a script into the page (through a comment, a profile field or a dependency), nothing stops it from sending your users' data out.", "Add a Content-Security-Policy header in your host's settings.");

  const penalty = findings.reduce((a, f) => a + SEVERITY[f.severity], 0);
  const score = Math.max(0, 100 - penalty);
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  const order = ["critical", "high", "medium", "low"];
  findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  return { url: origin, score, grade, scripts: bundles.length - 1, supabase: supabase ? { project: supabase.ref, checked: mine, readable: tables } : null, findings };
}
