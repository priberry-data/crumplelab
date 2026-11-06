// Small touches only. Everything on the page is readable with this script off.
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

// The clock in the status bar.
const clock = document.getElementById("clock");
const tick = () => { clock.textContent = new Date().toTimeString().slice(0, 8); };
tick();
setInterval(tick, 1000);

// Number keys jump between windows, like function keys on an old terminal.
const keys = { 1: "how", 2: "traps", 3: "fix", 4: "pricing", 5: "access" };
addEventListener("keydown", (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey || /input|textarea|select/i.test(e.target.tagName)) return;
  const id = keys[e.key];
  if (!id) return;
  const el = document.getElementById(id);
  el.scrollIntoView({ behavior: still ? "auto" : "smooth" });
  history.replaceState(null, "", "#" + id);
});

// The sample run prints line by line the first time it scrolls into view, then offers a replay.
const run = document.getElementById("run");
const replay = document.querySelector(".replay");
if (!still && run && "IntersectionObserver" in window) {
  // Wrap each line so it can be revealed on its own without changing the text.
  const html = run.innerHTML.split("\n");
  run.innerHTML = html.map((l) => `<span class="ln">${l || " "}</span>`).join("\n");
  const lines = [...run.querySelectorAll(".ln")];
  let timers = [];
  const play = () => {
    timers.forEach(clearTimeout);
    timers = [];
    run.classList.add("typing");
    lines.forEach((l) => l.classList.remove("on"));
    let t = 0;
    lines.forEach((l) => {
      const text = l.textContent;
      // Commands take a moment to "type", results land fast, and a score line pauses before it appears.
      t += text.startsWith("$") ? 700 : /score/.test(text) ? 600 : /BREACHED/.test(text) ? 260 : 90;
      timers.push(setTimeout(() => l.classList.add("on"), t));
    });
    timers.push(setTimeout(() => { run.classList.remove("typing"); replay.hidden = false; }, t + 50));
  };
  new IntersectionObserver((entries, obs) => {
    if (entries.some((e) => e.isIntersecting)) { obs.disconnect(); play(); }
  }, { threshold: 0.35 }).observe(run);
  replay.addEventListener("click", play);
}
