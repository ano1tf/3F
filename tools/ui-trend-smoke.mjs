import { JSDOM, VirtualConsole } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(ROOT, "app/static/index.html"), "utf8");
const js = fs.readFileSync(path.join(ROOT, "app/static/app.js"), "utf8");
const errors = [];
const vc = new VirtualConsole();
vc.on("jsdomError", (e) => errors.push(e.message));

const calls = [];
function json(data) { return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(data), text: () => Promise.resolve(JSON.stringify(data)) }); }

const dom = new JSDOM(html, {
  url: "https://preview.test/", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc,
  beforeParse(window) {
    window.fetch = (url) => {
      const u = String(url);
      calls.push(u);
      if (u.includes("/api/stats")) return json({ total_scans: 2, average_score: 60, hosts: [{ host: "cible.test", scans: 2 }], severity: { critical: 0, high: 1 }, series: [{ score: 50 }, { score: 70 }], watches: 0, watches_enabled: 0 });
      if (u.includes("/api/scans?limit")) return json({ scans: [] });
      if (u.includes("/api/trend/cible.test")) return json({ host: "cible.test", points: [{ date: "2026-04-01T10:00:00+00:00", score: 50 }, { date: "2026-04-02T10:00:00+00:00", score: 70 }] });
      if (u.includes("/api/watch")) return json({ scheduler: false, tick_seconds: 300, items: [] });
      if (u.includes("/api/meta")) return json({ app: "VulnLens", version: "5.0.0", profiles: [], scope: [], limits: [], watch: { enabled: false } });
      return json({});
    };
    window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    window.scrollTo = () => {};
    window.requestAnimationFrame = (cb) => setTimeout(cb, 0);
  },
});
dom.window.eval(js);
dom.window.document.querySelector("#nav-dashboard").click();

setTimeout(() => {
  const problems = [];
  const trend = dom.window.document.querySelector("#trend");
  if (trend.querySelectorAll("svg").length !== 1) problems.push("tendance non rendue");
  if (!calls.some((c) => c.includes("/api/trend/cible.test"))) problems.push("mauvais appel de tendance : " + calls.filter(c => c.includes("trend")).join(", "));
  if (errors.length) problems.push(...errors);
  console.log(problems.length ? "PROBLÈMES : " + problems.join(" | ") : "OK — tendance alimentée par le bon hôte");
  process.exit(problems.length ? 1 : 0);
}, 500);
