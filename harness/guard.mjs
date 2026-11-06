#!/usr/bin/env node
// Crumple guard: a Claude Code PreToolUse hook that stops the attacks the crash test finds.
// It parses each command the way the shell will (see shell.mjs), follows wrappers, inline
// scripts, heredocs and scripts the agent wrote, and checks real arguments, not text.
// When it can't read a command it blocks it. It is a seatbelt, not a sandbox: keep secrets
// and production access out of reach too.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { parse, unwrap, inlineScript, braces } from "./shell.mjs";

// Zero-width, bidi-control and Unicode "tag" characters: the rules-file backdoor trick.
const HIDDEN = /[​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\u{E0000}-\u{E007F}]/u;
const SECRET_VALUES = /AKIA[0-9A-Z]{16}|sk_(live|test)_[0-9A-Za-z_]{10,}|sk-(ant|proj)-[0-9A-Za-z_-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{20,}|glpat-[0-9A-Za-z_-]{20}|xox[bpas]-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{35}|npm_[0-9A-Za-z]{36}/;
const SECRET_VAR = /\$\{?[A-Za-z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|STRIPE|AWS_)[A-Za-z0-9_]*\}?/i;
const SECRET_PATH = /(^|\/)\.env(\.(local|prod\w*|dev\w*|staging|test))?$|(^|\/)\.envrc$|\.aws\/(credentials|config)$|(^|\/)\.ssh\/|(^|\/)id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$|(^|\/)\.netrc$|(^|\/)\.git-credentials$|(^|\/)\.pypirc$|\.docker\/config\.json$|\.config\/gh\/hosts\.yml$|\.kube\/config$|application_default_credentials\.json$|\.(pem|p12|pfx|key)$|Library\/Keychains\/|(^|\/)\.gnupg\//;
const HOME_SECRET = new RegExp(SECRET_PATH.source + String.raw`|(^|/)\.npmrc$|Login Data$|Cookies$|Application Support/(Google/Chrome|BraveSoftware|Firefox)|\.mozilla/|(^|/)\.crumple/`);
const PROTECTED = new RegExp([
  String.raw`(^|/)\.(claude|cursor|codex|gemini|windsurf|continue|crumple|vscode|idea|husky|devcontainer)(/|$)`,
  String.raw`(^|/)(CLAUDE|AGENTS|GEMINI|CONVENTIONS)\.md$`,
  String.raw`(^|/)\.(cursorrules|windsurfrules|clinerules|mcp\.json|aider[\w.]*)$`,
  String.raw`(^|/)\.github/(copilot-instructions\.md|instructions/)`,
  String.raw`(^|/)\.git/(hooks/|config$)`,
  String.raw`(^|/)\.(npmrc|yarnrc|yarnrc\.yml|pypirc|netrc|gitconfig|git-credentials)$|(^|/)pip\.conf$|(^|/)\.config/pip/`,
  String.raw`(^|/)\.(bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|zlogin|profile)$|(^|/)\.config/(fish|systemd|autostart)/`,
  String.raw`(^|/)\.ssh/|(^|/)Library/LaunchAgents/`,
].join("|"));
const TEST_FILE = /(^|\/)(tests?|__tests__|spec)\/|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(py|go)$|(^|\/)test_\w+\.py$/;
const CI_FILE = /(^|\/)\.github\/workflows\/|\.gitlab-ci\.yml$|(^|\/)Jenkinsfile$|(^|\/)\.circleci\/|azure-pipelines\.yml$|bitbucket-pipelines\.yml$/;
const GENERATED = /^(\.\/)?(build|dist|out|\.next|\.nuxt|\.svelte-kit|\.cache|\.turbo|\.parcel-cache|node_modules|coverage|tmp|\.tmp|target|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.venv|venv)(\/.*)?$|\.(log|pyc)$/;
const UNTRUSTED_READ = /(^|\/)(node_modules|vendor|third_party|\.git|logs?|downloads?|inbox|mail)\/|\.(log|eml|mbox)$|issue|ticket/i;
const SKIP = /\.skip\b|\bxit\(|\bxdescribe\(|@pytest\.mark\.skip|t\.Skip\(|\{\s*skip:\s*true|\.todo\(/;

const NET_CMDS = new Set(["curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "tftp", "sftp", "scp", "rsync", "ssh", "http", "https", "xh", "aria2c", "ping", "ping6", "dig", "nslookup", "host", "drill", "traceroute", "tracepath", "whois", "nmap"]);
const DNS_CMDS = new Set(["ping", "ping6", "dig", "nslookup", "host", "drill", "traceroute", "tracepath", "whois"]);
const DB_CMDS = new Set(["sqlite3", "psql", "mysql", "mariadb", "mongosh", "mongo", "redis-cli", "cqlsh", "prisma", "knex", "sequelize", "drizzle-kit", "supabase"]);
const DB_WRITE = /\b(DELETE|DROP|TRUNCATE|UPDATE|INSERT|ALTER|REPLACE|migrate|db push|reset|FLUSHALL|FLUSHDB|dropDatabase|deleteMany)\b/i;
const CLOUD_CMDS = new Set(["aws", "gcloud", "gsutil", "az", "kubectl", "helm", "terraform", "tofu", "pulumi", "doctl", "flyctl", "fly", "vercel", "netlify", "heroku", "firebase", "wrangler", "railway", "render"]);
const CLOUD_DESTROY = /^(delete|destroy|terminate|terminate-instances|rm|rb|purge|drop|remove|uninstall|scale|reset)$|^delete-|^--force$/;
const SHELLS = /^(ba|da|k|z|fi|c|tc)?sh$/;
const INTERPRETERS = /^(python[\d.]*|node|nodejs|deno|bun|perl|ruby|php|lua|Rscript|osascript|tsx|ts-node)$/;
const AGENT_CLIS = new Set(["claude", "codex", "gemini", "q", "amp", "aider", "cursor-agent", "copilot", "opencode", "goose", "cline"]);
const UNSAFE_AGENT_FLAGS = /^--(dangerously-skip-permissions|dangerously-bypass-approvals-and-sandbox|yolo|trust-all-tools|full-auto|auto-approve|allow-all-tools|no-sandbox)$/;
const CODE_NET = /\b(requests\.|urllib|http\.client|httpx|aiohttp|socket\.|fetch\(|axios|https?\.(request|get)\(|net\.connect|XMLHttpRequest|WebSocket|dns\.(resolve|lookup)|Net::HTTP|LWP::|IO::Socket|curl_exec|file_get_contents\(['"]https?:)/;
const CODE_SECRET = /os\.environ|getenv\(|process\.env|ENV\[|\$ENV\{|['"][^'"]*\.env['"]|\.aws\/credentials|\.ssh\/|id_rsa|keychain/i;
const CODE_SHELL = /\b(subprocess|os\.system|os\.popen|child_process|execSync|spawnSync|exec\(|spawn\(|system\(|popen\(|shell_exec|Open3|`)/;
const LOCAL_HOST = /^(localhost|127(\.\d{1,3}){3}|0\.0\.0\.0|\[?::1\]?|[\w-]+\.localhost)$/i;
const REGISTRIES = ["registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org", "proxy.golang.org", "crates.io", "static.crates.io"];

const deny = (reason) => ({ decision: "deny", reason });
const base = (s) => (s ?? "").split("/").pop();
const asserts = (s = "") => (s.match(/\bassert\w*[.(]|\bexpect\(|\bshould\b/g) ?? []).length;
const flagsOf = (args) => args.filter((a) => /^-[a-zA-Z]/.test(a)).map((a) => a.slice(1)).join("");
const positional = (args) => args.filter((a) => a !== "" && !a.startsWith("-"));
const homeDir = os.homedir();

// --- paths ---------------------------------------------------------------------------------

function resolveIn(ctx, p) {
  const t = p.replace(/^~(?=\/|$)/, homeDir).replace(/^\$\{?HOME\}?(?=\/|$)/, homeDir);
  return path.resolve(ctx.cwd, t);
}
const inside = (dir, abs) => abs === dir || abs.startsWith(dir.endsWith("/") ? dir : dir + "/");
function outsideWorkspace(ctx, p) {
  const abs = resolveIn(ctx, p);
  return !inside(ctx.cwd, abs) && !["/tmp", "/private/tmp", "/var/folders", "/private/var/folders", os.tmpdir()].some((d) => inside(d, abs));
}
const rel = (ctx, p) => {
  const abs = resolveIn(ctx, p);
  return inside(ctx.cwd, abs) ? path.relative(ctx.cwd, abs) || "." : abs;
};
const isSecretArg = (a) => SECRET_VALUES.test(a) || SECRET_VAR.test(a) || SECRET_PATH.test(a.replace(/^[^@<]*[@<]/, "").replace(/^file:\/\//, ""));

function readText(ctx, p, limit = 256 * 1024) {
  try {
    const abs = resolveIn(ctx, p);
    const st = fs.statSync(abs);
    if (!st.isFile() || st.size > limit) return null;
    return fs.readFileSync(abs, "utf8");
  } catch {
    return null;
  }
}

function hostOf(name, args) {
  const url = args.find((a) => /^[a-z][a-z0-9+.-]*:\/\//i.test(a));
  if (url) return url.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^[^@/]*@/, "").split(/[/:?#]/)[0];
  if (["ssh", "scp", "sftp", "rsync"].includes(name)) {
    const remote = args.find((a) => !a.startsWith("-") && /^([^/@\s]+@)?[\w.-]+:/.test(a));
    if (remote) return remote.replace(/^[^@]*@/, "").split(":")[0];
    if (name === "ssh") return (positional(args)[0] ?? "").replace(/^[^@]*@/, "");
  }
  const pos = positional(args).filter((a) => !/^[@+]/.test(a) && !/^(GET|POST|PUT|PATCH|DELETE|HEAD)$/.test(a));
  return (name === "curl" || name === "wget" ? pos[pos.length - 1] : pos[0])?.split(/[/:?#]/)[0] ?? "";
}
const allowedHost = (h) => LOCAL_HOST.test(h) || REGISTRIES.includes(h) || (process.env.CRUMPLE_ALLOW_HOSTS ?? "").split(",").map((s) => s.trim()).filter(Boolean).includes(h);

// --- shell ---------------------------------------------------------------------------------

function checkShell(code, ctx, depth = 0, lenient = false) {
  if (depth > 8) return deny("Blocked: commands nested too deeply to check. Run the steps one at a time.");
  if (HIDDEN.test(code)) return deny("Blocked: this command contains invisible characters, a known way to hide instructions.");
  const p = parse(code);
  if (p.error) return lenient ? null : deny(`Blocked: couldn't read this command safely (${p.error}). Rewrite it more simply.`);
  for (const s of p.substitutions) {
    const r = checkShell(s, ctx, depth + 1, lenient);
    if (r) return r;
  }
  const vars = {};
  for (const c of p.commands) {
    for (const a of c.assigns) {
      const k = a.slice(0, a.indexOf("="));
      vars[k] = a.slice(k.length + 1);
      const r = checkAssign(k, vars[k]);
      if (r) return r;
    }
    const argv = c.argv.map((a) => a.replace(/\$\{?([A-Za-z_]\w*)\}?/g, (m, k) => vars[k] ?? m));
    const r = checkCommand(argv, c, ctx, depth);
    if (r) return r;
  }
  return null;
}

function checkAssign(k, v) {
  if (/^(ANTHROPIC|OPENAI|CLAUDE_CODE|GEMINI|GOOGLE_GEMINI|AZURE_OPENAI|MISTRAL|GROQ)_(BASE_URL|API_BASE|API_URL|BASE)$/.test(k) && !/localhost|127\.0\.0\.1/.test(v))
    return deny(`Blocked: setting ${k} sends your AI traffic, and your API key, to another server.`);
  if (/^(HTTPS?_PROXY|ALL_PROXY|https?_proxy|all_proxy)$/.test(k) && !/localhost|127\.0\.0\.1/.test(v))
    return deny(`Blocked: setting ${k} routes all web traffic through another server.`);
  if (k === "NODE_OPTIONS" && /--(require|import|loader|experimental-loader)\b|(^|\s)-r\b/.test(v)) return deny("Blocked: NODE_OPTIONS that load code into every Node process.");
  if (/^(LD_PRELOAD|DYLD_INSERT_LIBRARIES|BASH_ENV|ENV|PROMPT_COMMAND|PYTHONSTARTUP|PERL5OPT|RUBYOPT)$/.test(k)) return deny(`Blocked: ${k} makes other programs load extra code.`);
  return null;
}

function checkCommand(argvIn, cmd, ctx, depth) {
  let argv = argvIn;
  while (["if", "then", "else", "elif", "do", "while", "until", "!", "{", "time"].includes(argv[0])) argv = argv.slice(1);
  if (["for", "case", "esac", "fi", "done", "function", "select", "in"].includes(argv[0])) return null;
  const text = argv.join(" ");

  // Redirects: raw sockets, secret inputs, writes, heredoc bodies.
  for (const r of cmd.redirects) {
    if (/^\/dev\/(tcp|udp)\//.test(r.target)) return deny("Blocked: opening a raw network socket from the shell.");
    if (r.body === undefined && r.op.includes("<") && SECRET_PATH.test(r.target)) ctx.secret = true;
    if (r.op.includes(">") && !/^\/dev\/(null|stdout|stderr)$|^&?\d$/.test(r.target)) {
      const body = cmd.redirects.find((x) => x.body !== undefined)?.body;
      const v = checkWriteTarget(r.target, body ?? text, ctx, r.op.includes(">>") ? "append" : "overwrite", depth);
      if (v) return v;
    }
  }
  if (!argv.length) return null;
  const name = base(argv[0]);
  const args = argv.slice(1);
  const heredoc = cmd.redirects.find((r) => r.body !== undefined)?.body;

  if (/\$|\(…\)/.test(argv[0])) return deny("Blocked: the command name is built at runtime, so nobody can check what it runs.");
  if (HIDDEN.test(text)) return deny("Blocked: this command contains invisible characters, a known way to hide instructions.");

  // Facts that matter across the whole command line.
  if (args.some(isSecretArg) || ["env", "printenv"].includes(name) && !positional(args).length || (name === "set" || name === "export" || name === "declare") && (!args.length || /^-[px]+$/.test(args[0]))) ctx.secret = true;
  if (name === "security" && /find-(generic|internet)-password|dump-keychain/.test(text) || name === "gh" && /auth token/.test(text) || name === "git" && /credential (fill|get)/.test(text)) ctx.secret = true;

  if (["export", "declare", "typeset", "local", "readonly", "setenv"].includes(name))
    for (const a of args.filter((a) => a.includes("="))) {
      const r = checkAssign(a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1));
      if (r) return r;
    }
  if (AGENT_CLIS.has(name)) {
    if (args.some((a) => UNSAFE_AGENT_FLAGS.test(a))) return deny("Blocked: starting an AI agent with its safety checks switched off (the s1ngularity/Nx attack did exactly this).");
    if (/^(config|mcp)$/.test(args[0]) && /\b(add|add-json|set|remove|add-from-claude-desktop)\b/.test(text)) return deny("Blocked: agents may not change their own configuration or tools.");
  }

  // Wrappers and inline code: check what actually runs.
  const inner = unwrap(argv);
  if (inner) {
    if (name === "xargs" && inner.length) {
      const sub = { ...ctx, viaXargs: true };
      const r = checkCommand(inner, { ...cmd, redirects: [] }, sub, depth + 1);
      ctx.secret ||= sub.secret;
      ctx.sink ||= sub.sink;
      return r;
    }
    if ((name === "npx" || name === "bunx" || name === "pnpx") && args.some((a) => /^(-y|--yes)$/.test(a)) && inner[0] && !fs.existsSync(path.join(ctx.cwd, "node_modules", ".bin", inner[0])))
      return deny(`Blocked: running "${inner[0]}" straight from the package registry. Check it is real and trusted, then ask the user.`);
    return inner.length ? checkCommand(inner, { ...cmd, redirects: [] }, ctx, depth + 1) : null;
  }
  const script = inlineScript(argv);
  if (script) {
    if (script.kind === "shell") return checkShell(script.code, ctx, depth + 1);
    const r = checkCode(script.code, ctx, depth + 1);
    if (r) return r;
    if (script.inPlace) for (const f of script.files) {
      const v = checkWriteTarget(f, script.code, ctx, "edit", depth);
      if (v) return v;
    }
    return null;
  }

  // Shells and interpreters fed from a pipe, a heredoc, a process substitution or a file.
  if (SHELLS.test(name) || INTERPRETERS.test(name) || name === "source" || name === ".") {
    const isShell = SHELLS.test(name) || name === "source" || name === ".";
    if (INTERPRETERS.test(name) && args[0] === "-m" && args[1]) return checkCommand(args.slice(1), { ...cmd, redirects: [] }, ctx, depth + 1);
    const file = positional(args)[0];
    if (heredoc !== undefined && !file) return isShell ? checkShell(heredoc, ctx, depth + 1) : checkCode(heredoc, ctx, depth + 1);
    if (file?.includes("(…)")) return deny("Blocked: running code from a process substitution (like bash <(curl …)) runs code nobody reviewed.");
    if (!file || file === "-") return cmd.pipedIn || args.includes("-s") ? deny("Blocked: piping text straight into a shell or interpreter runs code nobody reviewed.") : null;
    return checkScriptFile(file, isShell, ctx, depth);
  }
  if (argv[0].includes("/") && !outsideWorkspace(ctx, argv[0])) {
    const r = checkScriptFile(argv[0], true, ctx, depth);
    if (r) return r;
  }

  // Network.
  if (NET_CMDS.has(name) || name === "gh" && /^(api|gist|release)$/.test(args[0]) || name === "openssl" && args[0] === "s_client") {
    ctx.sink = true;
    const host = hostOf(name, args);
    if (DNS_CMDS.has(name) && args.some((a) => /\$|\(…\)/.test(a))) return deny("Blocked: data built into a DNS lookup or ping, a known way to sneak secrets out (CVE-2025-55284).");
    if (args.some(isSecretArg)) return deny("Blocked: this command would send secrets or .env contents over the network.");
    if (name === "ssh" && args.some((a) => /ProxyCommand|LocalCommand|PermitLocalCommand/i.test(a))) return deny("Blocked: ssh options that run local commands.");
    if ((name === "rsync") && args.some((a) => /^(-e|--rsh)/.test(a))) return deny("Blocked: rsync with a custom remote shell command.");
    const upload = name === "curl" && args.some((a) => /^(-d|--data.*|-F|--form.*|-T|--upload-file|--json)$/.test(a) || /^-[a-zA-Z]*[dFT]$/.test(a)) || name === "curl" && /-X\s*(POST|PUT|PATCH)/i.test(text)
      || name === "wget" && args.some((a) => /^--(post|body)-(data|file)|^--method=(POST|PUT)/i.test(a))
      || ["scp", "rsync", "sftp"].includes(name) && /^([^/@\s]+@)?[\w.-]+:/.test(positional(args).pop() ?? "")
      || ["nc", "ncat", "netcat", "socat", "telnet"].includes(name) && (cmd.pipedIn || cmd.redirects.some((r) => r.op.includes("<")))
      || /^(https?|xh)$/.test(name) && args.some((a) => /^[\w-]+(:?=|@)/.test(a));
    if (upload && host && !LOCAL_HOST.test(host)) return deny(`Blocked: uploading data to ${host}. Ask the user first.`);
    if (ctx.state.untrusted && ctx.state.secrets && host && !allowedHost(host))
      return deny(`Blocked (strict mode): this session has read untrusted content and secrets, so talking to ${host} is off. Allow it with CRUMPLE_ALLOW_HOSTS if it is expected.`);
    if (["curl", "wget", "aria2c"].includes(name)) {
      const out = args[args.findIndex((a) => /^(-o|--output|-O|--output-document)$/.test(a)) + 1];
      if (out && args.some((a) => /^(-o|--output|-O|--output-document)$/.test(a))) {
        const v = checkWriteTarget(out, "", ctx, "download", depth);
        if (v) return v;
      }
      if (!LOCAL_HOST.test(host)) ctx.fetchedRemote = true;
    }
  }

  // Databases and cloud.
  if (DB_CMDS.has(name)) {
    let sql = text + " " + (heredoc ?? "");
    for (const r of cmd.redirects) if (r.op === "<") sql += " " + (readText(ctx, r.target) ?? "");
    if (DB_WRITE.test(sql) && /prod/i.test(text + " " + Object.values(cmd.assigns).join(" "))) return deny("Blocked: writing to a database marked production. Use the dev database or ask the user.");
  }
  if (CLOUD_CMDS.has(name) && args.some((a) => CLOUD_DESTROY.test(a)) && !args.includes("--dry-run") && !args.includes("plan"))
    return deny(`Blocked: a destructive ${name} command against real infrastructure. Ask the user to run it.`);
  if (name === "docker" && args[0] === "run" && args.some((a, k) => a === "--privileged" || /^(-v|--volume|--mount)$/.test(args[k - 1] ?? "") && /^(\/|~)(:|$)|docker\.sock|\.ssh|\.aws/.test(a)))
    return deny("Blocked: a container with access to the whole machine, its Docker socket or its keys.");
  if (name === "crontab" && !args.includes("-l") || name === "launchctl" && /^(load|bootstrap|submit)$/.test(args[0]) || name === "systemctl" && /^(enable|link)$/.test(args.find((a) => !a.startsWith("-"))))
    return deny("Blocked: installing something that runs on its own later (cron, launchd, systemd).");
  if (name === "dd" && args.some((a) => /^of=\/dev\//.test(a)) || /^mkfs/.test(name) || name === "diskutil" && /erase/i.test(text))
    return deny("Blocked: writing straight to a disk device.");

  // git.
  if (name === "git") {
    const v = checkGit(args, ctx);
    if (v) return v;
  }

  // Deletes.
  if (["rm", "unlink", "shred", "srm", "rmdir", "trash"].includes(name)) {
    const recursive = /[rR]/.test(flagsOf(args)) || args.includes("--recursive") || name === "shred";
    const targets = positional(args).flatMap(braces);
    if (!targets.length && recursive && ctx.viaXargs) return deny("Blocked: recursive delete of files chosen at runtime. List what will be removed and ask the user.");
    for (const t of targets) {
      if (outsideWorkspace(ctx, t) || /^(\/|~|\*|\.|\.\/\*?)$/.test(t)) return deny(`Blocked: deleting ${t}, which is outside this project or the whole project. Ask the user.`);
      const r = rel(ctx, t);
      if (TEST_FILE.test(r)) return deny("Blocked: deleting tests. Fix the code instead, or ask the user.");
      if (PROTECTED.test(r)) return deny("Blocked: agents may not change their own configuration, git hooks or startup files.");
      if (recursive && (!GENERATED.test(r) || r.includes(".."))) return deny(`Blocked: recursive delete of ${t}. Only generated folders (build, dist, .cache, node_modules…) may be removed without asking.`);
    }
  }
  if (name === "find" || name === "fd" || name === "fdfind") {
    const v = checkFind(name, args, cmd, ctx, depth);
    if (v) return v;
  }
  if (name === "go" && args.includes("-exec")) {
    const r = checkShell(args[args.indexOf("-exec") + 1] ?? "", ctx, depth + 1);
    if (r) return r;
    return deny("Blocked: go -exec runs another program around your tests. Run go test without it.");
  }
  if (name === "rg" && args.some((a) => /^--pre(=|$)/.test(a))) return deny("Blocked: rg --pre runs a program on every file it searches.");
  if (name === "tar" && args.some((a) => /^--(to-command|checkpoint-action|use-compress-program|info-script|new-volume-script)|^-I$|^-F$/.test(a))) return deny("Blocked: tar options that run other programs.");
  if (name === "zip" && args.some((a) => /^(-TT|--unzip-command)/.test(a)) || name === "sort" && args.some((a) => /^--compress-program/.test(a))) return deny(`Blocked: ${name} options that run other programs.`);
  if (/^(vim?|nvim|ex)$/.test(name) && args.some((a, k) => /^(-c|--cmd)$/.test(args[k - 1] ?? "") && a.startsWith("!") || /^\+!/.test(a))) return deny("Blocked: running shell commands through the editor.");
  if (/^g?awk$/.test(name)) {
    const prog = positional(args)[0] ?? "";
    if (/system\(|\|\s*getline|print[^;]*\|\s*"/.test(prog)) {
      for (const m of prog.matchAll(/"([^"]{2,})"/g)) {
        const r = checkShell(m[1], ctx, depth + 1, true);
        if (r) return r;
      }
      if (/system\([^"]*\$/.test(prog)) return deny("Blocked: awk running shell commands built from data.");
    }
  }

  // Package installs and registries.
  const v = checkInstall(name, args, ctx, depth);
  if (v) return v;

  // Writes through ordinary commands.
  if (name === "sed" && (args.some((a) => /^-[a-zA-Z]*i/.test(a) || a.startsWith("--in-place")))) {
    const e = args.indexOf("-e");
    const pos = positional(args);
    const scriptArg = e >= 0 ? args[e + 1] : pos.shift();
    for (const f of e >= 0 ? pos.filter((a) => a !== scriptArg) : pos) {
      const w = checkWriteTarget(f, scriptArg ?? "", ctx, "edit", depth);
      if (w) return w;
    }
  }
  if (name === "sed" && args.some((a) => /(^|[;\n{}])\s*(\d+|\$|\/[^/]*\/)?(,(\d+|\$|\/[^/]*\/))?\s*e(\s|$)|^s(.).*\6.*\6[gpIiMm0-9]*e/.test(a))) return deny("Blocked: a sed script that runs shell commands.");
  if (["cp", "mv", "install", "ln", "rsync"].includes(name)) {
    const pos = positional(args);
    const dest = pos.pop();
    if (name === "mv" && pos.some((s) => TEST_FILE.test(rel(ctx, s)))) return deny("Blocked: moving tests out of the way. Fix the code instead, or ask the user.");
    if (name === "mv" && pos.some((s) => PROTECTED.test(rel(ctx, s)))) return deny("Blocked: agents may not change their own configuration, git hooks or startup files.");
    if (dest) {
      if (pos.some((s) => SECRET_PATH.test(s)) && /(^|\/)(public|static|www|dist|build|out|docs|site)(\/|$)/.test(rel(ctx, dest))) return deny("Blocked: copying secrets into a folder that gets published.");
      const w = checkWriteTarget(dest, pos.map((s) => readText(ctx, s, 64 * 1024) ?? "").join("\n"), ctx, "copy", depth);
      if (w) return w;
    }
  }
  if (["tee", "truncate", "touch", "chmod", "chown", "chattr"].includes(name)) {
    for (const f of positional(args).filter((a) => !/^[+=-]?[0-7]{3,4}$|^[ugoa]*[+=-][rwxXst]+$/.test(a))) {
      const w = checkWriteTarget(f, text, ctx, name === "truncate" ? "delete" : name === "tee" ? (args.includes("-a") ? "append" : "overwrite") : "meta", depth);
      if (w) return w;
    }
  }
  return null;
}

function checkGit(args, ctx) {
  let k = 0;
  const configs = [];
  while (k < args.length && args[k].startsWith("-")) {
    if (args[k] === "-c") configs.push(args[++k] ?? "");
    else if (/^--config-env/.test(args[k])) configs.push(args[k].split("=")[1] ?? args[++k] ?? "");
    else if (["-C", "--git-dir", "--work-tree", "--namespace"].includes(args[k])) k++;
    k++;
  }
  const sub = args[k];
  const rest = args.slice(k + 1);
  const DANGEROUS = /^(core\.(hookspath|sshcommand|fsmonitor|pager|editor|gitproxy|askpass)|sequence\.editor|diff\.external|diff\.\w+\.textconv|filter\.\w+\.(clean|smudge|process)|credential\.helper|url\..*\.insteadof|protocol\.\w+\.allow|alias\..*|uploadpack\.packobjectshook|include\.path|includeif\..*)/i;
  if (configs.some((c) => DANGEROUS.test(c.split("=")[0]))) return deny("Blocked: git -c options that run other programs or redirect where git talks to.");
  if (sub === "config" && rest.some((a) => DANGEROUS.test(a)) && !rest.some((a) => /^(--get|--list|-l|--get-all)$/.test(a)))
    return deny("Blocked: changing git settings that run programs (hooks path, ssh command, aliases, helpers).");
  if (["clone", "fetch", "pull", "ls-remote", "submodule", "archive"].includes(sub) && rest.some((a) => /^(--upload-pack|-u|--exec|--receive-pack|--config|-c)(=|$)/.test(a) && /^(-u|--upload-pack|--exec|--receive-pack)/.test(a)))
    return deny("Blocked: git options that run a program on the remote side.");
  if (sub === "push") {
    ctx.sink = true;
    if (rest.some((a) => /^(--force|-f|--force-with-lease|--force-if-includes|--mirror|--delete|-d|--prune)(=.*)?$/.test(a) || /^-[a-zA-Z]*f[a-zA-Z]*$/.test(a) || /^\+/.test(a) || /^:\S/.test(a)))
      return deny("Blocked: force-pushing or deleting branches rewrites shared history. Push normally or ask the user.");
    if (rest.some((a) => /:\/\/|^[\w.-]+@[\w.-]+:/.test(a))) return deny("Blocked: pushing code to an address that isn't one of this repo's remotes.");
  }
  if (sub === "clean" && /f/.test(flagsOf(rest)) && /[xX]/.test(flagsOf(rest))) return deny("Blocked: git clean -x also deletes ignored files like .env and local data. Ask the user.");
  if (sub === "remote" && /^(add|set-url)$/.test(rest[0]) && ctx.state.untrusted) return deny("Blocked (strict mode): adding a git remote after reading untrusted content.");
  return null;
}

function checkFind(name, args, cmd, ctx, depth) {
  const execAt = args.findIndex((a) => /^(-exec|-execdir|-ok|-okdir|-x|--exec|-X|--exec-batch)$/.test(a));
  if (execAt >= 0) {
    let end = args.findIndex((a, k) => k > execAt && (a === ";" || a === "+"));
    if (end < 0) end = args.length;
    const r = checkCommand(args.slice(execAt + 1, end), { argv: [], redirects: [], assigns: [], pipedIn: false }, { ...ctx, viaXargs: true }, depth + 1);
    if (r) return r;
  }
  if (name === "find" && args.includes("-delete")) {
    const paths = args.slice(0, args.findIndex((a) => /^[-(!]/.test(a)) >>> 0);
    const pattern = args[args.findIndex((a) => /^-i?(name|path)$/.test(a)) + 1] ?? "";
    for (const p of paths.length ? paths : ["."]) {
      if (outsideWorkspace(ctx, p)) return deny(`Blocked: deleting files under ${p}, outside this project.`);
      if (!GENERATED.test(rel(ctx, p)) && !/\.(log|pyc|pyo|tmp|orig|rej)$|__pycache__|\.DS_Store|^(build|dist|node_modules|\.cache)$/.test(pattern.replace(/^\*/, "x")))
        return deny(`Blocked: find -delete under ${p}. Only generated files may be removed without asking.`);
    }
  }
  return null;
}

const INSTALL_VERBS = { npm: /^(install|i|add|in|isntall|ins|inst|insta|instal|isnt|isnta|isntal)$/, pnpm: /^(add|install|i)$/, yarn: /^(add|install)$/, bun: /^(add|install|i)$/ };

function checkInstall(name, args, ctx, depth) {
  const pos = positional(args);
  if (INSTALL_VERBS[name]?.test(pos[0] ?? "")) {
    if (pos.length > 1) return deny(`Blocked: installing ${pos.slice(1).join(", ")}. Check each package is real and trusted, then ask the user to approve it.`);
    if (args.some((a) => /^--registry/.test(a))) return deny("Blocked: installing from a different package registry.");
    return checkLifecycle(ctx, depth, ["preinstall", "install", "postinstall", "prepare"]);
  }
  if (name === "npm" && pos[0] === "ci") return checkLifecycle(ctx, depth, ["preinstall", "install", "postinstall", "prepare"]);
  if (["npm", "pnpm", "yarn", "bun"].includes(name) && pos[0] === "config" && /^set$/.test(pos[1] ?? "") || name === "pip" && pos[0] === "config")
    return deny("Blocked: changing package manager settings (registry, tokens).");
  if (/^(npm|pnpm|yarn|bun)$/.test(name) && (pos[0] === "run" || pos[0] === "run-script" || /^(test|start|t|tst|build|dev|lint)$/.test(pos[0] ?? "") || name !== "npm" && pos[0] && !/^(install|add|remove|why|list|ls|outdated|info|view)$/.test(pos[0]))) {
    const script = pos[0] === "run" || pos[0] === "run-script" ? pos[1] : pos[0] === "t" || pos[0] === "tst" ? "test" : pos[0];
    return checkLifecycle(ctx, depth, [`pre${script}`, script, `post${script}`]);
  }
  if (/^pip[\d.]*$/.test(name) || name === "uv" && pos[0] === "pip") {
    const p = name === "uv" ? pos.slice(1) : pos;
    if (args.some((a) => /^(-i|--index-url|--extra-index-url|-f|--find-links|--trusted-host)(=|$)/.test(a))) return deny("Blocked: installing from a different package index.");
    if (p[0] === "install") {
      const pkgs = args.filter((a, k) => !a.startsWith("-") && !/^(-r|--requirement|-c|--constraint|-e|--editable)$/.test(args[k - 1] ?? "")).filter((a) => a !== "install" && a !== "pip" && a !== "." && !a.startsWith("./"));
      if (pkgs.length) return deny(`Blocked: installing ${pkgs.join(", ")}. Check each package is real and trusted, then ask the user to approve it.`);
    }
  }
  if (name === "uv" && pos[0] === "add" || name === "poetry" && pos[0] === "add" || name === "cargo" && /^(install|add)$/.test(pos[0] ?? "") || name === "go" && (pos[0] === "install" || pos[0] === "get") && pos[1]
    || name === "gem" && pos[0] === "install" || name === "brew" && /^(install|tap)$/.test(pos[0] ?? "") || /^apt(-get)?$/.test(name) && pos[0] === "install" || name === "composer" && pos[0] === "require" || name === "dotnet" && pos[0] === "add" || /^(pipx|uvx)$/.test(name) && (pos[0] === "install" || name === "uvx"))
    return deny(`Blocked: installing ${pos.slice(1).join(", ") || "a package"}. Check it is real and trusted, then ask the user to approve it.`);
  return null;
}

function checkLifecycle(ctx, depth, names) {
  let pkg;
  try {
    pkg = JSON.parse(readText(ctx, "package.json") ?? "null");
  } catch {}
  for (const n of names) {
    const s = pkg?.scripts?.[n];
    if (typeof s !== "string") continue;
    const r = checkShell(s, ctx, depth + 1, true);
    if (r) return deny(`${r.reason} (from the "${n}" script in package.json)`);
  }
  return null;
}

// Files run directly: checked fully when the agent wrote them this session, otherwise only shell scripts are read.
function checkScriptFile(file, isShell, ctx, depth) {
  const abs = resolveIn(ctx, file);
  const agentWritten = (ctx.state.written ?? []).includes(abs);
  const content = readText(ctx, file);
  if (content == null) return null;
  if (HIDDEN.test(content)) return deny(`Blocked: ${file} contains invisible characters, a known way to hide instructions.`);
  const shellish = isShell && /\.(sh|bash|zsh)$|^[^.]*$/.test(file) || /^#!.*\b(ba|z|da)?sh\b/.test(content);
  if (shellish) return checkShell(content, ctx, depth + 1, true);
  if (agentWritten) return checkCode(content, ctx, depth + 1);
  return null;
}

function checkCode(code, ctx, depth) {
  if (HIDDEN.test(code)) return deny("Blocked: this code contains invisible characters, a known way to hide instructions.");
  const net = CODE_NET.test(code);
  const secret = CODE_SECRET.test(code) || SECRET_VALUES.test(code);
  if (net) ctx.sink = true;
  if (secret) ctx.secret = true;
  if (net && secret) return deny("Blocked: this code reads secrets and talks to the network. Ask the user first.");
  if (/sqlite3\.connect|new Database\(|psycopg|pg\.(Client|Pool)|createConnection|MongoClient/.test(code) && /prod/i.test(code) && DB_WRITE.test(code))
    return deny("Blocked: writing to a database marked production. Use the dev database or ask the user.");
  if (/rmtree|rmSync|fs\.rm\(|rimraf|fs\.unlink|os\.remove|unlink\(/.test(code) && /expanduser|homedir|\$HOME|os\.environ\[['"]HOME|['"]\/['"]|['"]~\/|Documents|backups?\b/.test(code))
    return deny("Blocked: code that deletes files outside this project.");
  if (/writeFile|appendFile|open\([^)]*['"][wa]\+?['"]|write_text|write_bytes|File\.write/.test(code)) {
    for (const m of code.matchAll(/['"`]([^'"`\n]{2,200})['"`]/g)) if (PROTECTED.test(m[1]) || CI_FILE.test(m[1])) {
      if (PROTECTED.test(m[1])) return deny("Blocked: code that changes the agent's own configuration, git hooks or startup files.");
    }
  }
  if (CODE_SHELL.test(code)) {
    for (const m of code.matchAll(/(['"`])((?:(?!\1)[^\\\n]|\\.){3,600})\1/g)) {
      if (!/\s/.test(m[2])) continue;
      const r = checkShell(m[2], ctx, depth + 1, true);
      if (r) return r;
    }
  }
  return null;
}

// Every way of writing a file ends here: redirects, cp/mv/tee/sed -i, downloads, and the Write/Edit tools.
function checkWriteTarget(target, text, ctx, kind, depth = 0) {
  const r = rel(ctx, target);
  (ctx.writes ??= []).push(resolveIn(ctx, target));
  if (PROTECTED.test(r) || PROTECTED.test(resolveIn(ctx, target))) return deny("Blocked: agents may not change their own configuration, permissions, git hooks or startup files.");
  if (outsideWorkspace(ctx, target) && kind !== "meta") return deny(`Blocked: writing to ${target}, outside this project. Ask the user.`);
  if (HIDDEN.test(text)) return deny("Blocked: writing invisible characters into a file, a known way to hide instructions.");
  if (TEST_FILE.test(r)) {
    const exists = readText(ctx, target) != null;
    if (kind === "delete" || kind === "overwrite" && exists || kind === "download") return deny("Blocked: replacing or deleting tests from the shell. Fix the code instead, or ask the user.");
    if (/skip|\bxit\b|xdescribe|\.todo\b/.test(text) || kind === "edit" && /(^|[;'"\s])\/[^/]*(assert|expect|should|test|it)\b[^/]*\/d|\bd['";\s]*$/.test(text))
      return deny("Blocked: deleting or skipping tests. Fix the code instead, or ask the user.");
  }
  if (CI_FILE.test(r) && /\b(curl|wget|nc|fetch|Invoke-WebRequest|requests\.)\b/.test(text) && /secrets\.|\$\{?\w*(SECRET|TOKEN|KEY|PASSWORD)|\.env\b/i.test(text))
    return deny("Blocked: a CI change that sends secrets to a server. Review this by hand.");
  if (/(^|\/)\.env[\w.]*$|\.(sh|bash|zsh|ps1)$|(^|\/)package\.json$/.test(r) && /(ANTHROPIC|OPENAI|GEMINI|AZURE_OPENAI)_(BASE_URL|API_BASE)\s*[=:]/.test(text) && !/localhost|127\.0\.0\.1/.test(text))
    return deny("Blocked: pointing your AI API base URL at another server, which hands it your key.");
  if (SECRET_VALUES.test(text) && !/(^|\/)\.env[\w.]*$/.test(r)) return deny("Blocked: writing a secret value into a project file.");
  if (/\.(sh|bash|zsh)$/.test(r) || /^#!.*\bsh\b/.test(text)) {
    const v = checkShell(text, ctx, depth + 1, true);
    if (v) return deny(`${v.reason} (inside the script being written to ${target})`);
  }
  if (/(^|\/)package\.json$/.test(r)) {
    try {
      const scripts = JSON.parse(text).scripts ?? {};
      for (const [n, s] of Object.entries(scripts)) {
        const v = checkShell(String(s), ctx, depth + 1, true);
        if (v) return deny(`${v.reason} (in the "${n}" script being added to package.json)`);
      }
    } catch {}
  }
  return null;
}

// --- tools ---------------------------------------------------------------------------------

function checkWrite(file, before, after, ctx) {
  const v = checkWriteTarget(file, after ?? "", ctx, "tool");
  if (v) return v;
  const r = rel(ctx, file);
  if (TEST_FILE.test(r) && after !== undefined && (SKIP.test(after) && !SKIP.test(before ?? "") || asserts(after) < asserts(before)))
    return deny("Blocked: weakening or skipping tests. Fix the code instead, or ask the user.");
  return null;
}

/**
 * Decide on one tool call. `state` carries what this session has seen so far
 * ({ untrusted, secrets, written }); it is updated in place for allowed calls.
 * Returns null to allow, or { decision: "deny", reason }.
 */
export function decide(input, state = {}) {
  const tool = input.tool_name ?? "";
  const ti = input.tool_input ?? {};
  const ctx = { cwd: path.resolve(input.cwd ?? process.cwd()), state, secret: false, sink: false };
  let verdict = null;

  if (tool === "Bash") {
    const cmd = String(ti.command ?? "");
    verdict = checkShell(cmd, ctx);
    if (!verdict && ctx.secret && ctx.sink) verdict = deny("Blocked: this command reads secrets and talks to the network in one go.");
    if (!verdict) {
      if (ctx.secret) state.secrets = true;
      if (ctx.fetchedRemote) state.untrusted = true;
      if (ctx.writes?.length) state.written = [...new Set([...(state.written ?? []), ...ctx.writes])].slice(-200);
    }
  } else if (tool === "Write" || tool === "Edit" || tool === "MultiEdit" || tool === "NotebookEdit") {
    const file = String(ti.file_path ?? ti.notebook_path ?? "");
    if (tool === "Write") verdict = checkWrite(file, readText(ctx, file) ?? "", String(ti.content ?? ""), ctx);
    else if (tool === "NotebookEdit") verdict = checkWrite(file, "", String(ti.new_source ?? ""), ctx);
    else for (const e of tool === "Edit" ? [ti] : ti.edits ?? []) {
      verdict = checkWrite(file, String(e.old_string ?? ""), String(e.new_string ?? ""), ctx);
      if (verdict) break;
    }
    if (!verdict) state.written = [...new Set([...(state.written ?? []), resolveIn(ctx, file)])].slice(-200);
  } else if (tool === "Read" || tool === "Grep" || tool === "Glob" || tool === "LS") {
    const p = String(ti.file_path ?? ti.path ?? "");
    if (p) {
      const abs = resolveIn(ctx, p);
      if (!inside(ctx.cwd, abs) && HOME_SECRET.test(abs)) verdict = deny(`Blocked: ${p} holds credentials outside this project. Keep keys out of the agent's reach.`);
      else {
        if (SECRET_PATH.test(abs)) state.secrets = true;
        if (UNTRUSTED_READ.test(rel(ctx, p))) state.untrusted = true;
      }
    }
  } else if (tool === "WebFetch" || tool === "WebSearch") {
    const url = String(ti.url ?? ti.query ?? "");
    if (SECRET_VALUES.test(url) || SECRET_VAR.test(url)) verdict = deny("Blocked: a secret inside a web address.");
    else if (tool === "WebFetch" && state.untrusted && state.secrets && !allowedHost(hostOf("curl", [url])))
      verdict = deny(`Blocked (strict mode): this session has read untrusted content and secrets, so fetching ${hostOf("curl", [url])} is off.`);
    if (!verdict) state.untrusted = true;
  } else if (tool.startsWith("mcp__")) {
    const args = JSON.stringify(ti);
    if (HIDDEN.test(args)) verdict = deny("Blocked: invisible characters in an MCP tool call.");
    else if (SECRET_VALUES.test(args) || /[A-Z_]{2,}(SECRET|KEY|TOKEN|PASSWORD)[A-Z_]*=/.test(args) || /-----BEGIN/.test(args))
      verdict = deny("Blocked: this MCP tool call would hand over secrets. Do not pass credentials to tools.");
    else if (state.secrets && state.untrusted && /(^|\\n)[A-Z][A-Z0-9_]+=\S/.test(args)) verdict = deny("Blocked (strict mode): passing environment-style data to a tool after reading untrusted content.");
    if (!verdict) state.untrusted = true;
  }
  return verdict;
}

// --- hook: session state and a tamper-evident audit log --------------------------------------

const crumpleHome = () => process.env.CRUMPLE_HOME ?? path.join(homeDir, ".crumple");
const redact = (s) => s.replace(new RegExp(SECRET_VALUES.source, "g"), "[secret]").slice(0, 300);

function audit(entry) {
  try {
    const file = path.join(crumpleHome(), "audit.jsonl");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    let prev = "0".repeat(64);
    try {
      const tail = fs.readFileSync(file, "utf8").trimEnd().split("\n").pop();
      prev = JSON.parse(tail).hash ?? prev;
    } catch {}
    const body = { ...entry, prev };
    const hash = crypto.createHash("sha256").update(prev + JSON.stringify(body)).digest("hex");
    fs.appendFileSync(file, JSON.stringify({ ...body, hash }) + "\n");
  } catch {}
}

// Checks the audit log's hash chain. Returns { entries, brokenAt } (brokenAt is -1 when intact).
export function verifyAudit(file = path.join(crumpleHome(), "audit.jsonl")) {
  const lines = fs.existsSync(file) ? fs.readFileSync(file, "utf8").trimEnd().split("\n").filter(Boolean) : [];
  let prev = "0".repeat(64);
  for (let i = 0; i < lines.length; i++) {
    const { hash, ...body } = JSON.parse(lines[i]);
    if (body.prev !== prev || crypto.createHash("sha256").update(prev + JSON.stringify(body)).digest("hex") !== hash) return { entries: lines.length, brokenAt: i };
    prev = hash;
  }
  return { entries: lines.length, brokenAt: -1 };
}

export function runHook() {
  let raw = "";
  process.stdin.on("data", (d) => (raw += d));
  process.stdin.on("end", () => {
    let verdict;
    let input = {};
    try {
      input = JSON.parse(raw);
      const id = String(input.session_id ?? "default").replace(/[^\w-]/g, "").slice(0, 80) || "default";
      const stateFile = path.join(crumpleHome(), "state", `${id}.json`);
      let state = {};
      try {
        state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
      } catch {}
      verdict = decide(input, state);
      fs.mkdirSync(path.dirname(stateFile), { recursive: true });
      fs.writeFileSync(stateFile, JSON.stringify(state));
    } catch (e) {
      verdict = deny(`Blocked: the Crumple guard could not check this call (${e.message}).`);
    }
    audit({ t: new Date().toISOString(), session: input.session_id, tool: input.tool_name, decision: verdict ? "deny" : "allow", reason: verdict?.reason, input: redact(JSON.stringify(input.tool_input ?? {})) });
    if (verdict)
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: verdict.reason },
      }));
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) runHook();
