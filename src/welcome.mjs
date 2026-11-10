// The welcome screen: a crash-test marker an instant before the wall, drawn in the terminal with half-block
// characters, two pixels to a character cell. Shown only to a real terminal that is wide enough; never in
// pipes, CI, or with NO_COLOR, where the plain usage is printed instead.

// --- a very small pixel painter ---------------------------------------------------------------------
const rgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
// 24-bit colour where the terminal says it has it; otherwise the nearest of the colours every terminal has.
const colour = (hex, layer, truecolor) => {
  const [r, g, b] = rgb(hex);
  if (truecolor) return `${layer};2;${r};${g};${b}`;
  // Near-greys go to the 24-step grey ramp, so a dark grey stays grey instead of turning teal.
  if (Math.max(r, g, b) - Math.min(r, g, b) < 24) return `${layer};5;${232 + Math.max(0, Math.min(23, Math.round(((r + g + b) / 3 - 8) / 10)))}`;
  const q = (v) => (v < 48 ? 0 : v < 115 ? 1 : Math.min(5, Math.round((v - 35) / 40)));
  return `${layer};5;${16 + 36 * q(r) + 6 * q(g) + q(b)}`;
};

export const canvas = (w, h) => Array.from({ length: h }, () => Array(w).fill("."));

// Each line of text holds two rows of pixels: the upper half-block takes the top pixel's colour as its
// foreground and the bottom pixel's as its background.
export function paint(c, palette, truecolor) {
  const lines = [];
  for (let y = 0; y < c.length; y += 2) {
    let line = "";
    for (let x = 0; x < c[0].length; x++) {
      const top = palette[c[y][x]];
      const bottom = palette[c[y + 1]?.[x]];
      if (!top && !bottom) line += "\x1b[0m ";
      else if (top && bottom) line += `\x1b[0;${colour(top, 38, truecolor)};${colour(bottom, 48, truecolor)}m▀`;
      else if (top) line += `\x1b[0;${colour(top, 38, truecolor)}m▀`;
      else line += `\x1b[0;${colour(bottom, 38, truecolor)}m▄`;
    }
    lines.push(`${line}\x1b[0m`);
  }
  return lines;
}

export const canShow = (stream, env, width) => Boolean(stream.isTTY && !env.NO_COLOR && !env.CI && env.TERM !== "dumb" && (stream.columns ?? 80) >= width);

// --- Crumple's scene --------------------------------------------------------------------------------
const PALETTE = { y: "#ffd23f", k: "#1b1d1c", w: "#f1f3f1", b: "#565c57", B: "#30352f", c: "#a7ada9", x: "#ffb547", X: "#fff2c2", q: "#1f8f4a", Q: "#6dff95", d: "#2f3430" };

export function scene() {
  const c = canvas(34, 24);
  // The marker every crash test carries: a disc in quarters, yellow against black, ringed in white.
  const cx = 12.5, cy = 11.5, R = 9.2;
  for (let y = 0; y < 23; y++)
    for (let x = 0; x < 24; x++) {
      const dx = x - cx, dy = y - cy, r = Math.hypot(dx, dy);
      if (r > R) continue;
      c[y][x] = r > R - 1.3 ? "w" : dx < 0 === dy < 0 ? "y" : "k";
    }
  // The wall it is about to meet: courses of brick, with the mortar a shade darker.
  for (let y = 1; y < 23; y++) for (let x = 28; x < 33; x++) c[y][x] = y % 4 === 0 || (x + (Math.floor(y / 4) % 2 ? 2 : 0)) % 5 === 0 ? "B" : "b";
  // First contact: a few sparks and the start of a crack.
  for (const [x, y, ch] of [[24, 6, "x"], [25, 9, "X"], [26, 11, "x"], [24, 13, "X"], [26, 15, "x"], [25, 17, "x"], [28, 10, "c"], [28, 11, "c"], [29, 12, "c"], [28, 13, "c"]]) c[y][x] = ch;
  // Speed, in three strokes of phosphor green.
  for (const [x, y, ch] of [[0, 6, "q"], [1, 6, "Q"], [0, 11, "Q"], [1, 11, "Q"], [2, 11, "Q"], [0, 16, "q"], [1, 16, "Q"]]) c[y][x] = ch;
  for (let x = 0; x < 34; x++) c[23][x] = "d";
  return c;
}

export function welcome({ version = "", stream = process.stdout, env = process.env } = {}) {
  if (!canShow(stream, env, 102)) return "";
  const truecolor = /truecolor|24bit/i.test(env.COLORTERM ?? "");
  const art = paint(scene(), PALETTE, truecolor);
  // The words use the terminal's own text colours, so they read on a dark or a light background.
  const off = "\x1b[0m", bold = "\x1b[1m", faint = "\x1b[2m", go = "\x1b[32m";
  const cmd = (c, note) => `${go}$${off} ${c}${" ".repeat(Math.max(2, 26 - c.length))}${faint}${note}${off}`;
  const text = {
    2: `${bold}${go}CRUMPLE${off}${version ? `  ${faint}v${version}${off}` : ""}`,
    3: "The crash test for AI coding agents.",
    5: cmd("npx crumplelab scan", "your agent's setup, in seconds"),
    6: cmd("npx crumplelab attack", "the real crash test, in a sandbox"),
    7: cmd("npx crumplelab fix", "harden it, then attack again"),
    9: `${faint}Fake keys, sealed container: nothing real is at risk.${off}`,
    10: `${faint}--help for everything  ·  crumple.priberry.com${off}`,
  };
  return ["", ...art.map((line, i) => `  ${line}   ${text[i] ?? ""}`.trimEnd()), ""].join("\n") + "\n";
}
