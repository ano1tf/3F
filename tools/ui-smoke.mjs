import { JSDOM, VirtualConsole } from "jsdom";
import fs from "node:fs";

const html = fs.readFileSync("/home/user/3F/app/static/index.html", "utf8");
const js = fs.readFileSync("/home/user/3F/app/static/app.js", "utf8");

const errors = [];
const virtualConsole = new VirtualConsole();
virtualConsole.on("jsdomError", (e) => errors.push(`jsdomError: ${e.message}`));

const findings = [
  { id: "exposure.git", title: "Dépôt Git exposé", severity: "critical", severity_label: "Critique",
    category: "Exposition de fichiers", description: "Dépôt public.", evidence: "GET /.git/HEAD → 200",
    remediation: "Bloquez .git/", reference: "https://owasp.org", confidence: "certain",
    danger: 10, danger_label: "Critique — exploitable immédiatement, impact majeur",
    access: ["Ouvrir https://cible.test/.git/HEAD sans authentification.", "Le serveur renvoie la branche courante."],
    reveals: "Le code source complet et les secrets de l'historique.", skill: "faible" },
  { id: "content.comments-leak", title: "Commentaire sensible", severity: "low", severity_label: "Faible",
    category: "Fuite d'information", description: "Mot de passe en commentaire.", evidence: "<!-- pwd -->",
    remediation: "Nettoyez le HTML.", reference: "", confidence: "a-confirmer",
    danger: 2, danger_label: "Faible — signal de durcissement",
    access: ["Lire le code source de la page.", "Repérer le commentaire."],
    reveals: "Une information interne résiduelle.", skill: "aucune" },
];

const report = {
  target: "https://cible.test/", final_url: "https://cible.test/", score: 42, grade: "E",
  started_at: "2026-05-01T10:00:00+00:00", duration_ms: 1200, profile: "standard", scan_id: "abc123",
  verified: true,
  pages: [{ url: "https://cible.test/", status: 200, title: "Accueil" }, { url: "https://cible.test/a", status: 200, title: "A" }],
  third_parties: [{ host: "cdn.x.test", role: "CDN & polices", resources: ["script"], pages: 2 },
                  { host: "forms.crm.test", role: "E-mail & marketing", resources: ["formulaire"], pages: 1 }],
  counts: { critical: 1, high: 0, medium: 0, low: 1, info: 0 },
  score_breakdown: { "Exposition de fichiers": 20, "Fuite d'information": 1 },
  priorities: ["exposure.git"], fingerprint: { serveur: "nginx", waf: "Cloudflare", cms: "WordPress" },
  checks: [{ key: "headers", label: "En-têtes", status: "ok", findings: [] },
           { key: "secrets", label: "Secrets & scripts", status: "ok", findings: [] }],
  findings,
  executive: {
    risk_level: "élevé", headline: "1 faille critique donne un accès immédiat.",
    paragraph: "Analyse de 2 pages et de 11 familles de contrôles.",
    key_risks: [{ id: "exposure.git", title: "Dépôt Git exposé", severity: "critical", severity_label: "Critique",
                  impact: "Le code source fuit.", action: "Bloquez .git/" }],
    strengths: ["HTTPS actif", "SPF publié"],
    danger_max: 10,
    radar: [{ label: "Exposition de fichiers", value: 100 }, { label: "Fuite d'information", value: 5 },
            { label: "Configuration HTTP", value: 0 }],
  },
};

const plan = { available: true, current_score: 42, projected_score: 88, potential_gain: 46,
  counts: { quick: 1, sprint: 0, project: 0 },
  buckets: { quick: { label: "Aujourd'hui — moins d'une heure", detail: "réglages",
                      items: [{ id: "exposure.git", title: "Dépôt Git exposé", severity: "critical", severity_label: "Critique", action: "Bloquez .git/" }] },
             sprint: { label: "Ce sprint", detail: "code", items: [] },
             project: { label: "Projet", detail: "refonte", items: [] } } };

function streamOf(lines) {
  return new ReadableStream({
    start(controller) {
      const encoder = new TextEncoder();
      lines.forEach((line) => controller.enqueue(encoder.encode(JSON.stringify(line) + "\n")));
      controller.close();
    },
  });
}

function jsonResponse(data) {
  return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(data), text: () => Promise.resolve(JSON.stringify(data)) });
}

const dom = new JSDOM(html, {
  url: "https://preview.test/", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole,
  beforeParse(window) {
    window.fetch = (url, options = {}) => {
      const u = String(url);
      if (u === "/api/scan") {
        return Promise.resolve({
          ok: true, status: 200,
          body: streamOf([
            { type: "progress", step: "transport", label: "Transport", message: "Connexion", percent: 20 },
            { type: "progress", step: "secrets", label: "Secrets", message: "Scripts", percent: 80 },
            { type: "result", percent: 100, report },
            { type: "saved", scan_id: "abc123", verified: true },
          ]),
        });
      }
      if (u.includes("/api/scans/abc123/plan")) return jsonResponse(plan);
      if (u.includes("/api/scans/abc123/diff")) return jsonResponse({ available: true, previous_score: 60, score_delta: -18,
        previous_at: "2026-04-01T10:00:00+00:00", new: [{ id: "exposure.git", title: "Dépôt Git exposé", severity: "critical", severity_label: "Critique" }],
        fixed: [], summary: { new: 1, fixed: 0, persistent: 1 } });
      if (u.includes("/api/meta")) return jsonResponse({ app: "VulnLens", version: "5.0.0", profiles: [], scope: [], limits: [], watch: { enabled: true } });
      if (u.includes("/api/stats")) return jsonResponse({ total_scans: 1, average_score: 42, hosts: [], severity: {}, series: [], watches: 1, watches_enabled: 1 });
      if (u.includes("/api/watch")) return jsonResponse({ scheduler: true, tick_seconds: 90, items: [] });
      if (u.includes("/api/trend")) return jsonResponse({ points: [] });
      return jsonResponse({});
    };
    window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    window.scrollTo = () => {};
    window.requestAnimationFrame = (cb) => setTimeout(cb, 0);
    window.HTMLElement.prototype.scrollIntoView = () => {};
  },
});

dom.window.eval(js);
const { document } = dom.window;
const problems = [];
const check = (name, condition) => { if (!condition) problems.push(name); };

const form = document.querySelector("#scan-form");
document.querySelector("#target").value = "https://cible.test/";
document.querySelector(".consent input").checked = true;
form.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));

setTimeout(() => {
  check("résultats visibles", document.querySelector("#results").hidden === false);
  check("score affiché", document.querySelector("#score").textContent === "42");
  check("synthèse visible", document.querySelector("#exec-panel").hidden === false);
  check("titre de synthèse", document.querySelector("#exec-headline").textContent.includes("faille critique"));
  check("radar tracé", document.querySelectorAll("#radar svg polygon").length === 1);
  check("3 risques listés", document.querySelectorAll("#exec-risks li").length === 1);
  check("forces listées", document.querySelectorAll("#exec-strengths li").length === 2);
  check("ruban de sévérités", document.querySelectorAll("#sev-ribbon span").length === 2);
  check("constats rendus", document.querySelectorAll("#findings .finding").length === 2);
  check("chip à confirmer", [...document.querySelectorAll(".confidence")].some((c) => !c.hidden && c.textContent === "à confirmer"));
  check("plan rempli", document.querySelectorAll("#plan-cols .plan-col").length === 3);
  check("diff rempli", document.querySelector("#diff-panel").hidden === false);
  check("pages listées", document.querySelectorAll("#pages-list li").length === 2);
  check("tiers listés", document.querySelectorAll("#third-list li").length === 2);

  // rapport de situation
  check("panneau situation visible", document.querySelector("#situation-panel").hidden === false);
  check("5 cartes max", document.querySelectorAll("#situation-list .situation-card").length === 2);
  check("danger affiché en carte", document.querySelectorAll("#situation-list .danger b")[0].textContent === "10/10");
  check("étapes en carte", document.querySelectorAll("#situation-list ol.access li").length >= 2);
  check("chip danger dans le constat", [...document.querySelectorAll(".danger-chip")].some((c) => !c.hidden && c.textContent.includes("10/10")));
  check("onglet situation compté", document.querySelector("#tab-count-situation").textContent === "2");

  // onglets
  const constatsTab = document.querySelector('.tab[data-tab="constats"]');
  constatsTab.click();
  check("onglet constats actif", constatsTab.classList.contains("is-active"));
  check("groupe constats visible", !document.querySelector('.tab-group[data-tab="constats"]').classList.contains("is-hidden"));
  check("situation masquée hors onglet", document.querySelector('#situation-panel').classList.contains("is-hidden"));
  check("synthèse masquée", document.querySelector('#priority-panel').classList.contains("is-hidden"));
  check("onglet lui-même visible", !constatsTab.classList.contains("is-hidden"));

  if (errors.length) problems.push(...errors.map((e) => `runtime: ${e}`));
  console.log(problems.length ? `PROBLÈMES (${problems.length}) :\n- ` + problems.join("\n- ") : "OK — parcours complet rendu sans erreur");
  process.exit(problems.length ? 1 : 0);
}, 800);
