// A small shell reader for the guard. It splits a command line the way bash would
// (quotes, $'…', operators, redirects, heredocs, $(…), `…`, <(…)) so rules look at real
// commands and real arguments instead of matching text. What it can't read is reported as such.

const OPERATORS = ["&&", "||", ";;", "|&", ";", "|", "&", "\n", "(", ")"];

// Returns { commands: [{ argv, redirects, assigns, pipedIn }], substitutions: [string] } or { error }.
export function parse(input) {
  const tokens = [];
  const substitutions = [];
  const pendingHeredocs = [];
  let expectHeredocDelim = false;
  let word = null;
  let quotedPart = false;
  // The unquoted text a word starts with, so NAME="$x" still reads as an assignment.
  let lead = null;
  const markQuote = () => {
    if (!quotedPart && lead === null) lead = word ?? "";
  };
  let i = 0;
  const push = () => {
    if (word !== null) {
      tokens.push({ type: "word", value: word, quoted: quotedPart, lead: quotedPart ? lead : word });
      if (expectHeredocDelim) {
        pendingHeredocs.push({ tok: tokens[tokens.length - 2], delim: word });
        expectHeredocDelim = false;
      }
    }
    word = null;
    quotedPart = false;
    lead = null;
  };
  const add = (s) => (word = (word ?? "") + s);

  // Reads a $( … ), <( … ) or ` … ` body, honouring nesting and quotes, and returns its end index.
  const readSub = (start, close) => {
    let depth = 1;
    let q = null;
    for (let j = start; j < input.length; j++) {
      const ch = input[j];
      if (q) {
        if (ch === "\\" && q === '"') j++;
        else if (ch === q) q = null;
      } else if (ch === "\\") j++;
      else if (ch === "'" || ch === '"') q = ch;
      else if (close === ")" && ch === "(") depth++;
      else if (ch === close && --depth === 0) return j;
    }
    return -1;
  };
  const sub = (start, close, placeholder) => {
    const end = readSub(start, close);
    if (end < 0) return -1;
    substitutions.push(input.slice(start, end));
    add(placeholder);
    return end + 1;
  };

  while (i < input.length) {
    const ch = input[i];
    if (ch === "\\" && i + 1 < input.length) {
      if (input[i + 1] !== "\n") add(input[i + 1]);
      i += 2;
      continue;
    }
    if (ch === "'") {
      markQuote();
      const end = input.indexOf("'", i + 1);
      if (end < 0) return { error: "unclosed single quote" };
      add(input.slice(i + 1, end));
      quotedPart = true;
      i = end + 1;
      continue;
    }
    if (input.startsWith("$'", i)) {
      markQuote();
      let j = i + 2;
      let buf = "";
      while (j < input.length && input[j] !== "'") {
        if (input[j] === "\\" && j + 1 < input.length) {
          const m = input.slice(j).match(/^\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|.)/s);
          const e = m[1];
          buf += e[0] === "x" || e[0] === "u" || e[0] === "U" ? String.fromCodePoint(parseInt(e.slice(1), 16))
            : /^[0-7]/.test(e) ? String.fromCharCode(parseInt(e, 8))
            : { n: "\n", t: "\t", r: "\r", e: "\x1b", a: "\x07", b: "\b", f: "\f", v: "\v" }[e] ?? e;
          j += m[0].length;
          continue;
        }
        buf += input[j++];
      }
      if (j >= input.length) return { error: "unclosed $' quote" };
      add(buf);
      quotedPart = true;
      i = j + 1;
      continue;
    }
    if (input.startsWith('$"', i)) {
      i++;
      continue;
    }
    if (ch === '"') {
      markQuote();
      let j = i + 1;
      let buf = "";
      while (j < input.length && input[j] !== '"') {
        if (input[j] === "\\" && j + 1 < input.length) {
          buf += input[j + 1];
          j += 2;
          continue;
        }
        if (input.startsWith("$(", j) && !input.startsWith("$((", j)) {
          const end = readSub(j + 2, ")");
          if (end < 0) return { error: "unclosed $(" };
          substitutions.push(input.slice(j + 2, end));
          buf += "$(…)";
          j = end + 1;
          continue;
        }
        if (input[j] === "`") {
          const end = readSub(j + 1, "`");
          if (end < 0) return { error: "unclosed backtick" };
          substitutions.push(input.slice(j + 1, end));
          buf += "$(…)";
          j = end + 1;
          continue;
        }
        buf += input[j++];
      }
      if (j >= input.length) return { error: "unclosed double quote" };
      add(buf);
      quotedPart = true;
      i = j + 1;
      continue;
    }
    if (input.startsWith("$((", i)) {
      const end = input.indexOf("))", i + 3);
      if (end < 0) return { error: "unclosed $((" };
      add(input.slice(i, end + 2));
      i = end + 2;
      continue;
    }
    if (input.startsWith("$(", i)) {
      i = sub(i + 2, ")", "$(…)");
      if (i < 0) return { error: "unclosed $(" };
      continue;
    }
    if (ch === "`") {
      i = sub(i + 1, "`", "$(…)");
      if (i < 0) return { error: "unclosed backtick" };
      continue;
    }
    if ((input.startsWith("<(", i) || input.startsWith(">(", i)) && word === null) {
      i = sub(i + 2, ")", "<(…)");
      if (i < 0) return { error: "unclosed process substitution" };
      continue;
    }
    if (/[<>]/.test(ch) && (word === null || /^\d+$/.test(word))) {
      const m = input.slice(i).match(/^(>>|>&|<&|<<<|<<-|<<|>\||<>|>|<)/);
      const prefix = word ?? "";
      word = null;
      quotedPart = false;
      const op = m[1].replace(">|", ">");
      tokens.push({ type: "redir", value: prefix + op });
      if (op === "<<" || op === "<<-") expectHeredocDelim = true;
      i += m[1].length;
      continue;
    }
    if (ch === "&" && input[i + 1] === ">") {
      push();
      const op = input[i + 2] === ">" ? "&>>" : "&>";
      tokens.push({ type: "redir", value: op });
      i += op.length;
      continue;
    }
    if (ch === "\n") push();
    if (ch === "\n" && pendingHeredocs.length) {
      tokens.push({ type: "op", value: "\n" });
      i++;
      for (const h of pendingHeredocs.splice(0)) {
        const lines = [];
        while (i <= input.length) {
          const nl = input.indexOf("\n", i);
          const line = input.slice(i, nl < 0 ? input.length : nl);
          i = nl < 0 ? input.length + 1 : nl + 1;
          if (line.replace(/^\t+/, "") === h.delim) break;
          lines.push(line);
        }
        h.tok.body = lines.join("\n");
      }
      if (i > input.length) i = input.length;
      continue;
    }
    if (ch === "{" && word === null && /\s/.test(input[i + 1] ?? "")) {
      tokens.push({ type: "op", value: "{" });
      i++;
      continue;
    }
    if (ch === "}" && word === null) {
      tokens.push({ type: "op", value: "}" });
      i++;
      continue;
    }
    const op = OPERATORS.find((o) => input.startsWith(o, i));
    if (op) {
      push();
      tokens.push({ type: "op", value: op });
      i += op.length;
      continue;
    }
    if (/\s/.test(ch)) {
      push();
      i++;
      continue;
    }
    if (ch === "#" && word === null) {
      const nl = input.indexOf("\n", i);
      i = nl < 0 ? input.length : nl;
      continue;
    }
    add(ch);
    i++;
  }
  push();
  // A heredoc whose body never arrived (no newline after it) reads as empty.
  for (const h of pendingHeredocs) h.tok.body ??= "";

  const commands = [];
  let cur = { argv: [], redirects: [], assigns: [], pipedIn: false };
  const flush = (op) => {
    if (cur.argv.length || cur.redirects.length || cur.assigns.length) commands.push(cur);
    cur = { argv: [], redirects: [], assigns: [], pipedIn: op === "|" || op === "|&" };
  };
  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k];
    if (t.type === "op") flush(t.value);
    else if (t.type === "redir") {
      const target = tokens[k + 1];
      if (target?.type === "word") {
        cur.redirects.push({ op: t.value, target: target.value, body: t.body });
        k++;
      }
    } else if (!cur.argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(t.lead ?? "")) cur.assigns.push(t.value);
    else cur.argv.push(t.value);
  }
  flush();
  return { commands, substitutions };
}

const base = (s) => (s ?? "").split("/").pop();

// Wrappers that run another command. Returns the inner argv, or null if argv isn't a wrapper.
export function unwrap(argv) {
  const [cmd, ...rest] = argv;
  const name = base(cmd);
  const skip = (k, takesValue = /^$/) => {
    while (k < rest.length && rest[k].startsWith("-")) k += takesValue.test(rest[k]) ? 2 : 1;
    return rest.slice(k);
  };
  if (["sudo", "doas", "nohup", "command", "builtin", "exec", "stdbuf", "unbuffer", "caffeinate", "setsid", "time", "nocorrect", "noglob"].includes(name))
    return skip(0, /^-[ugCDhpr]$|^--(user|group)$/);
  if (name === "env") {
    let k = 0;
    while (k < rest.length && (rest[k].startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[k]))) k += /^-[uC]$/.test(rest[k]) ? 2 : 1;
    return rest.slice(k);
  }
  if (["nice", "timeout", "gtimeout", "ionice", "chrt", "taskset", "watch"].includes(name)) {
    let k = 0;
    while (k < rest.length && (rest[k].startsWith("-") || /^[\d.]+[smhd]?$/.test(rest[k]))) k += /^-[nscpk]$|^--(signal|kill-after|interval)$/.test(rest[k]) ? 2 : 1;
    return rest.slice(k);
  }
  if (name === "xargs") return skip(0, /^-[IdLnPsEa]$/);
  if (["npx", "bunx", "pnpx"].includes(name)) return skip(0, /^(-p|--package)$/);
  if (["pnpm", "yarn"].includes(name) && ["dlx", "exec"].includes(rest[0])) return rest.slice(1);
  if (name === "npm" && rest[0] === "exec") return rest.slice(1).filter((a) => a !== "--");
  return null;
}

// Inline scripts handed to a shell or interpreter: bash -c "…", eval …, python -c "…", perl -pe '…'.
export function inlineScript(argv) {
  const name = base(argv[0]);
  if (/^(ba|da|k|z|fi|c|tc)?sh$/.test(name) || name === "su" || name === "script") {
    const i = argv.findIndex((a, k) => k > 0 && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
    if (i >= 0 && argv[i + 1] !== undefined) return { kind: "shell", code: argv[i + 1] };
  }
  if (name === "eval") return { kind: "shell", code: argv.slice(1).join(" ") };
  if (name === "env") {
    const i = argv.findIndex((a) => a === "-S" || a === "--split-string");
    if (i >= 0 && argv[i + 1] !== undefined) return { kind: "shell", code: argv.slice(i + 1).join(" ") };
  }
  if (/^(python[\d.]*|node|nodejs|deno|bun|php|osascript|lua|Rscript|julia)$/.test(name)) {
    const i = argv.findIndex((a, k) => k > 0 && /^(-c|-e|--eval|-p|--print|-r|eval)$/.test(a));
    if (i >= 0 && argv[i + 1] !== undefined) return { kind: "code", code: argv[i + 1] };
  }
  if (/^(perl|ruby)$/.test(name)) {
    const i = argv.findIndex((a, k) => k > 0 && /^-[a-zA-Z]*e$/.test(a));
    if (i >= 0 && argv[i + 1] !== undefined) return { kind: "code", code: argv[i + 1], inPlace: argv.some((a) => /^-[a-zA-Z]*i/.test(a)), files: argv.slice(i + 2).filter((a) => !a.startsWith("-")) };
  }
  return null;
}

// "a{b,c}d" -> ["abd", "acd"], one level deep, which is all the guard needs.
export function braces(word) {
  const m = word.match(/^(.*?)\{([^{}]*,[^{}]*)\}(.*)$/);
  return m ? m[2].split(",").flatMap((p) => braces(m[1] + p + m[3])) : [word];
}
