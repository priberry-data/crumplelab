// The start-up banner: CRUMPLE in block letters, shaded top to bottom like an old phosphor screen.
// Printed only to a real terminal that is wide enough, and never with --json, NO_COLOR or CI.
export const BANNER = [
  " ██████╗██████╗ ██╗   ██╗███╗   ███╗██████╗ ██╗     ███████╗",
  "██╔════╝██╔══██╗██║   ██║████╗ ████║██╔══██╗██║     ██╔════╝",
  "██║     ██████╔╝██║   ██║██╔████╔██║██████╔╝██║     █████╗  ",
  "██║     ██╔══██╗██║   ██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝  ",
  "╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║██║     ███████╗███████╗",
  " ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝",
];

// Bright phosphor green fading to a darker green, one shade per row.
const SHADES = [[124, 255, 158], [92, 240, 132], [64, 220, 110], [46, 196, 92], [34, 168, 76], [26, 132, 60]];

export function banner({ version, tagline, stream = process.stdout, env = process.env } = {}) {
  if (!stream.isTTY || env.NO_COLOR || env.CI || (stream.columns ?? 80) < BANNER[0].length + 4) return "";
  const truecolor = /truecolor|24bit/i.test(env.COLORTERM ?? "");
  const paint = (row, i) => {
    if (!truecolor) return `\x1b[${i < 3 ? "92" : "32"}m${row}\x1b[0m`;
    const [r, g, b] = SHADES[i];
    // The shadow strokes (╗ ║ ╚ ═) are drawn darker than the solid blocks, which gives the letters depth.
    return row.replace(/(█+)|([^█]+)/g, (_, solid, edge) =>
      solid ? `\x1b[38;2;${r};${g};${b}m${solid}` : `\x1b[38;2;${r >> 1};${g >> 1};${b >> 1}m${edge}`) + "\x1b[0m";
  };
  const dim = (s) => `\x1b[2m${s}\x1b[22m`;
  return ["", ...BANNER.map((row, i) => "  " + paint(row, i)), "", `  ${tagline}${version ? dim(`  v${version}`) : ""}`, ""].join("\n") + "\n";
}
