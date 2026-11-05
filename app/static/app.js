/* VulnLens — logique d'interface : analyse en streaming, rendu du rapport. */
(() => {
  "use strict";

  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_LABEL = {
    critical: "Critique",
    high: "Élevée",
    medium: "Moyenne",
    low: "Faible",
    info: "Info",
  };

  const STEPS = [
    ["validation", "Validation de la cible"],
    ["transport", "Transport & TLS"],
    ["headers", "En-têtes de sécurité"],
    ["dns", "DNS, SPF, DMARC"],
    ["cors", "CORS & méthodes HTTP"],
    ["exposure", "Fichiers exposés"],
    ["content", "Contenu & formulaires"],
    ["score", "Calcul du score"],
  ];

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const form = $("#scan-form");
  const input = $("#target");
  const consent = $("#authorized");
  const button = $("#scan-btn");
  const progressPanel = $("#progress-panel");
  const progressBar = $("#progress-bar");
  const stepsList = $("#steps");
  const logEl = $("#log");
  const errorPanel = $("#error-panel");
  const errorMessage = $("#error-message");
  const results = $("#results");

  let currentReport = null;
  let activeFilter = "all";
  let searchTerm = "";
  let history = [];
  let dashboardLoaded = false;
  let dashboardData = { stats: null, scans: [], hosts: [] };

  const HISTORY_KEY = "vulnlens.history.v1";
  const HISTORY_MAX = 10;

  /* ----------------------------- Utilitaires ----------------------------- */

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function severityLabel(sev) {
    return SEVERITY_LABEL[sev] || sev;
  }

  function formatDate(iso) {
    if (!iso) return "";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return iso;
    return date.toLocaleString("fr-FR", {
      day: "2-digit",
      month: "long",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  function humanDuration(ms) {
    if (ms < 1000) return `${ms} ms`;
    return `${(ms / 1000).toFixed(1).replace(".", ",")} s`;
  }

  function toast(message, kind = "info") {
    const host = document.getElementById("toasts");
    if (!host) return;
    const node = el("div", "toast", message);
    node.dataset.kind = kind;
    host.appendChild(node);
    setTimeout(() => {
      node.style.transition = "opacity .25s ease";
      node.style.opacity = "0";
      setTimeout(() => node.remove(), 260);
    }, 3600);
  }

  /* --------------------------- Appels API / méta -------------------------- */

  async function loadMeta() {
    try {
      const response = await fetch("/api/meta");
      if (!response.ok) return;
      const meta = await response.json();
      const scope = $("#scope-list");
      const limits = $("#limits-list");
      meta.scope.forEach((item) => scope.appendChild(el("li", null, item)));
      meta.limits.forEach((item) => limits.appendChild(el("li", null, item)));
    } catch (_) {
      /* l'interface reste utilisable sans les métadonnées */
    }
  }

  /* ------------------------------ Progression ----------------------------- */

  function resetProgress() {
    stepsList.innerHTML = "";
    logEl.textContent = "";
    progressBar.style.width = "3%";
    STEPS.forEach(([key, label], index) => {
      const li = el("li");
      li.dataset.key = key;
      li.appendChild(el("span", "step-icon"));
      li.appendChild(el("span", null, label));
      if (index === 0) li.classList.add("active");
      stepsList.appendChild(li);
    });
  }

  function updateStep(stepKey, percent, message) {
    const items = $$("#steps li");
    let found = false;
    items.forEach((li) => {
      if (li.dataset.key === stepKey) {
        li.classList.remove("active");
        li.classList.add("done");
        found = true;
      } else if (found) {
        li.classList.remove("done");
      }
    });

    // marque l'étape suivante comme active
    const doneIdx = items.findIndex((li) => li.dataset.key === stepKey);
    const next = items[doneIdx + 1];
    if (next) next.classList.add("active");

    if (typeof percent === "number") {
      progressBar.style.width = `${Math.max(4, Math.min(100, percent))}%`;
    }
    if (message) {
      const line = el("div", null, `▸ ${message}`);
      logEl.appendChild(line);
      logEl.scrollTop = logEl.scrollHeight;
    }
  }

  function finishSteps() {
    $$("#steps li").forEach((li) => {
      li.classList.remove("active");
      li.classList.add("done");
    });
    progressBar.style.width = "100%";
  }

  /* -------------------------------- Analyse ------------------------------- */

  async function startScan(event) {
    event.preventDefault();
    const target = input.value.trim();

    if (!target) {
      input.focus();
      input.setAttribute("aria-invalid", "true");
      return;
    }
    input.removeAttribute("aria-invalid");

    if (!consent.checked) {
      consent.focus();
      consent.closest(".consent").style.animation = "none";
      void consent.closest(".consent").offsetWidth;
      consent.closest(".consent").animate(
        [
          { transform: "translateX(0)" },
          { transform: "translateX(-5px)" },
          { transform: "translateX(5px)" },
          { transform: "translateX(0)" },
        ],
        { duration: 260, iterations: 1 }
      );
      return;
    }

    errorPanel.hidden = true;
    results.hidden = true;
    progressPanel.hidden = false;
    progressPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    resetProgress();
    $("#progress-target").textContent = target;

    button.disabled = true;
    button.classList.add("is-busy");
    button.querySelector(".btn-label").textContent = "Analyse…";

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target, authorized: true, profile: selectedProfile() }),
      });

      if (!response.ok) {
        let detail = `HTTP ${response.status}`;
        try {
          const payload = await response.json();
          if (payload && payload.error) detail = payload.error;
        } catch (_) {}
        throw new Error(detail);
      }
      if (!response.body) throw new Error("Flux de réponse indisponible.");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let gotResult = false;

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (!line.trim()) continue;
          let event;
          try {
            event = JSON.parse(line);
          } catch (_) {
            continue;
          }
          if (event.type === "progress") {
            updateStep(event.step, event.percent, event.message);
          } else if (event.type === "result") {
            gotResult = true;
            finishSteps();
            renderReport(event.report);
          } else if (event.type === "saved") {
            if (currentReport && currentReport.scan_id === event.scan_id) {
              fetchDiff(currentReport);
              fetchPlan(currentReport);
            }
          } else if (event.type === "error") {
            showError(event.message || "Erreur inconnue.");
          }
        }
      }

      if (gotResult) {
        dashboardLoaded = false;
      }
      if (!gotResult) {
        if (errorPanel.hidden) {
          showError("L'analyse s'est interrompue sans produire de rapport. Réessaie.");
        } else {
          progressPanel.hidden = true;
        }
      }
    } catch (error) {
      showError(error.message || "Impossible de contacter le serveur d'analyse.");
    } finally {
      button.disabled = false;
      button.classList.remove("is-busy");
      button.querySelector(".btn-label").textContent = "Analyser";
    }
  }

  function showError(message) {
    progressPanel.hidden = true;
    errorPanel.hidden = false;
    errorMessage.textContent = message;
    errorPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  /* -------------------------------- Rapport ------------------------------- */

  function renderReport(report, options = {}) {
    currentReport = report;
    activeFilter = "all";
    searchTerm = "";
    $("#findings-search").value = "";

    progressPanel.hidden = true;
    errorPanel.hidden = true;
    results.hidden = false;

    // Gauge
    const score = Number(report.score) || 0;
    $("#score").textContent = score;
    $("#grade").textContent = `note ${report.grade}`;
    const circumference = 2 * Math.PI * 52;
    const fill = $("#gauge-fill");
    fill.style.strokeDasharray = `${circumference}`;
    fill.style.strokeDashoffset = `${circumference}`;
    requestAnimationFrame(() => {
      fill.style.strokeDashoffset = `${circumference * (1 - score / 100)}`;
    });
    fill.style.stroke =
      score >= 80 ? "#34d399" : score >= 60 ? "#ffd166" : score >= 35 ? "#ff8a3d" : "#ff3b5c";

    $("#result-target").textContent = report.final_url || report.target;
    const counts = report.counts || {};
    const total = SEVERITY_ORDER.reduce((sum, key) => sum + (counts[key] || 0), 0);
    $("#result-meta").textContent =
      `${total} constat${total > 1 ? "s" : ""} · ${humanDuration(report.duration_ms)} · ` +
      `${formatDate(report.started_at)}`;

    renderSeverityRibbon(counts);

    // Compteurs par sévérité
    const grid = $("#severity-grid");
    grid.innerHTML = "";
    SEVERITY_ORDER.forEach((sev) => {
      const cell = el("div", "sev-cell");
      cell.dataset.sev = sev;
      cell.appendChild(el("b", null, String(counts[sev] || 0)));
      cell.appendChild(el("span", null, severityLabel(sev)));
      grid.appendChild(cell);
    });

    renderExecutive(report);
    renderSituation(report);
    renderFilters(report.findings || []);
    renderFindings();
    renderPriorities(report);
    switchTab("synthese");
    renderBreakdown(report);
    renderFingerprint(report.fingerprint || {});
    renderChecks(report.checks || []);

    if (!options.fromHistory) {
      saveToHistory(report);
    }
    renderComparison(report);
    renderHistory();
    renderVerification(report);
    renderPages(report);
    renderThirdParties(report);
    $("#diff-panel").hidden = true;
    fetchPlan(report);
    updateTabCounts(report);

    results.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderSeverityRibbon(counts) {
    const ribbon = $("#sev-ribbon");
    if (!ribbon) return;
    ribbon.innerHTML = "";
    const total = SEVERITY_ORDER.reduce((sum, key) => sum + (counts[key] || 0), 0);
    ribbon.hidden = total === 0;
    if (!total) return;
    SEVERITY_ORDER.forEach((sev) => {
      const count = counts[sev] || 0;
      if (!count) return;
      const segment = el("span");
      segment.dataset.sev = sev;
      segment.style.flexGrow = String(count);
      segment.title = `${count} ${severityLabel(sev).toLowerCase()}`;
      ribbon.appendChild(segment);
    });
  }

  function executiveToText(report) {
    const executive = (report && report.executive) || {};
    const lines = [
      `Synthèse VulnLens — ${(report && (report.final_url || report.target)) || ""}`,
      `Risque ${executive.risk_level || "—"} · score ${report ? report.score : "—"}/100`,
      "",
      executive.headline || "",
      "",
      executive.paragraph || "",
      "",
    ];
    if ((executive.key_risks || []).length) {
      lines.push("Ce qui expose le plus :");
      executive.key_risks.forEach((risk) => {
        lines.push(`- [${risk.severity_label}] ${risk.title} — ${risk.impact}`);
      });
      lines.push("");
    }
    if ((executive.strengths || []).length) {
      lines.push("Ce qui tient déjà :");
      executive.strengths.forEach((item) => lines.push(`- ${item}`));
    }
    return lines.join("\n");
  }

  function renderFilters(findings) {
    const filters = $("#filters");
    filters.innerHTML = "";
    const options = [["all", `Tous (${findings.length})`]].concat(
      SEVERITY_ORDER.filter((sev) => findings.some((f) => f.severity === sev)).map((sev) => [
        sev,
        `${severityLabel(sev)} (${findings.filter((f) => f.severity === sev).length})`,
      ])
    );

    options.forEach(([key, label]) => {
      const chip = el("button", "chip", label);
      chip.type = "button";
      chip.dataset.filter = key;
      chip.setAttribute("aria-pressed", key === activeFilter ? "true" : "false");
      chip.addEventListener("click", () => {
        activeFilter = key;
        $$("#filters .chip").forEach((c) =>
          c.setAttribute("aria-pressed", c.dataset.filter === key ? "true" : "false")
        );
        renderFindings();
      });
      filters.appendChild(chip);
    });
  }

  function renderFindings() {
    const container = $("#findings");
    const template = $("#finding-template");
    container.innerHTML = "";

    const findings = (currentReport && currentReport.findings) || [];
    const term = searchTerm.toLowerCase();
    const visible = findings.filter((finding) => {
      const matchSeverity = activeFilter === "all" || finding.severity === activeFilter;
      const haystack = [
        finding.title,
        finding.category,
        finding.description,
        finding.evidence,
        finding.remediation,
        finding.id,
      ]
        .join(" ")
        .toLowerCase();
      return matchSeverity && (!term || haystack.includes(term));
    });

    $("#no-findings").hidden = visible.length > 0;

    visible.forEach((finding) => {
      const node = template.content.firstElementChild.cloneNode(true);
      node.dataset.sev = finding.severity;
      node.dataset.id = finding.id;
      $(".finding-title", node).textContent = finding.title;
      $(".finding-cat", node).textContent = finding.category;
      $(".sev-badge", node).textContent = finding.severity_label || severityLabel(finding.severity);
      if (finding.danger) {
        const chip = $(".danger-chip", node);
        chip.hidden = false;
        chip.textContent = `Danger ${finding.danger}/10`;
        chip.dataset.tier = finding.danger >= 9 ? "high" : finding.danger >= 6 ? "mid" : "low";
        chip.title = finding.danger_label || "";
        node.dataset.danger = String(finding.danger);
      }

      const access = $(".access", node);
      (finding.access || []).forEach((step) => access.appendChild(el("li", null, step)));
      if (!(finding.access || []).length) {
        access.appendChild(el("li", null, "Chemin d'accès non détaillé pour ce constat."));
      }
      $(".reveals", node).textContent = finding.reveals || "Impact non détaillé.";

      const confidence = $(".confidence", node);
      if (finding.confidence && finding.confidence !== "certain") {
        confidence.hidden = false;
        confidence.dataset.level = finding.confidence;
        confidence.textContent =
          finding.confidence === "probable" ? "à vérifier" : "à confirmer";
      }
      $(".finding-desc", node).textContent = finding.description;
      $(".evidence", node).textContent = finding.evidence || "—";
      $(".finding-fix", node).textContent =
        finding.remediation || "Aucune remédiation spécifique fournie.";

      const reference = $(".reference", node);
      if (finding.reference) {
        reference.href = finding.reference;
        reference.hidden = false;
      } else {
        reference.hidden = true;
      }

      const head = $(".finding-head", node);
      head.addEventListener("click", () => {
        const open = node.classList.toggle("open");
        head.setAttribute("aria-expanded", open ? "true" : "false");
      });

      $(".copy-finding", node).addEventListener("click", async (event) => {
        event.stopPropagation();
        const button = event.currentTarget;
        await copyText(findingToText(finding));
        button.textContent = "Copié ✓";
        setTimeout(() => {
          button.textContent = "Copier ce constat";
        }, 1600);
      });

      container.appendChild(node);
    });
  }

  function renderFingerprint(fingerprint) {
    const dl = $("#fingerprint");
    dl.innerHTML = "";
    const entries = Object.entries(fingerprint).filter(([, value]) => value);
    if (!entries.length) {
      dl.appendChild(el("p", "empty", "Aucune empreinte technique collectée."));
      return;
    }
    entries.forEach(([key, value]) => {
      const row = el("div");
      const dt = el("dt", null, key.replace(/_/g, " "));
      const dd = el("dd", null, String(value));
      row.appendChild(dt);
      row.appendChild(dd);
      dl.appendChild(row);
    });
  }

  function renderChecks(checks) {
    const list = $("#checks");
    list.innerHTML = "";
    if (!checks.length) {
      list.appendChild(el("li", null, "Aucun contrôle exécuté."));
      return;
    }
    checks.forEach((check) => {
      const li = el("li");
      const status = el(
        "span",
        `check-status ${check.status === "error" ? "error" : "ok"}`,
        check.status === "error" ? "!" : "✓"
      );
      li.appendChild(status);
      li.appendChild(el("span", null, check.label));
      const detail =
        check.status === "error" && check.detail
          ? "indisponible"
          : `${check.findings ? check.findings.length : 0} constat${
              check.findings && check.findings.length > 1 ? "s" : ""
            }`;
      li.appendChild(el("span", "check-detail", detail));
      if (check.detail) li.title = check.detail;
      list.appendChild(li);
    });
  }


  /* ------------------------- Priorités & composition ---------------------- */

  function findingById(id) {
    return ((currentReport && currentReport.findings) || []).find((f) => f.id === id);
  }

  function renderPriorities(report) {
    const panel = $("#priority-panel");
    const list = $("#priority-list");
    list.innerHTML = "";
    const ids = report.priorities || [];
    const items = ids.map(findingById).filter(Boolean);
    if (!items.length) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;
    items.forEach((finding, index) => {
      const card = el("button", "priority-card");
      card.type = "button";
      card.dataset.sev = finding.severity;
      card.dataset.id = finding.id;

      card.appendChild(el("span", "priority-rank", String(index + 1)));

      const main = el("span", "priority-main");
      main.appendChild(el("span", "priority-title", finding.title));
      main.appendChild(
        el(
          "span",
          "priority-fix",
          (finding.remediation || "").slice(0, 160) +
            ((finding.remediation || "").length > 160 ? "…" : "")
        )
      );
      card.appendChild(main);
      card.appendChild(el("span", "priority-go", "Voir le détail →"));

      card.addEventListener("click", () => {
        const target = document.querySelector(`.finding[data-id="${finding.id}"]`);
        if (!target) return;
        target.classList.add("open");
        $(".finding-head", target).setAttribute("aria-expanded", "true");
        target.scrollIntoView({ behavior: "smooth", block: "center" });
        target.animate(
          [
            { boxShadow: "0 0 0 0 rgba(34,211,238,0)" },
            { boxShadow: "0 0 0 4px rgba(34,211,238,.35)" },
            { boxShadow: "0 0 0 0 rgba(34,211,238,0)" },
          ],
          { duration: 1400 }
        );
      });

      list.appendChild(card);
    });
  }

  function renderBreakdown(report) {
    const panel = $("#breakdown-panel");
    const list = $("#breakdown");
    list.innerHTML = "";
    if (!report.score_breakdown) {
      // Rapport archivé par une version antérieure : pas de décomposition connue.
      panel.hidden = true;
      return;
    }
    panel.hidden = false;
    const breakdown = report.score_breakdown;
    const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]);

    if (!entries.length) {
      $("#breakdown-total").textContent = "aucune pénalité";
      list.appendChild(el("li", "muted small", "Aucun point perdu : tous les contrôles sont au vert."));
      return;
    }

    const total = entries.reduce((sum, [, points]) => sum + points, 0);
    $("#breakdown-total").textContent = `−${total} points sur 100`;
    const max = Math.max(...entries.map(([, points]) => points));

    entries.forEach(([category, points]) => {
      const li = el("li");
      const head = el("div", "bd-head");
      head.appendChild(el("span", null, category));
      head.appendChild(el("span", "bd-points", `−${points}`));
      const track = el("div", "bd-track");
      const fill = el("div", "bd-fill");
      track.appendChild(fill);
      li.appendChild(head);
      li.appendChild(track);
      list.appendChild(li);
      requestAnimationFrame(() => {
        fill.style.width = `${Math.max(4, (points / max) * 100)}%`;
      });
    });
  }

  /* ------------------------------- Historique ----------------------------- */

  function hostOf(report) {
    const value = report.final_url || report.target || "";
    try {
      return new URL(value).hostname;
    } catch (_) {
      return value.replace(/^https?:\/\//, "").split("/")[0];
    }
  }

  function loadHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      history = raw ? JSON.parse(raw) : [];
      if (!Array.isArray(history)) history = [];
    } catch (_) {
      history = [];
    }
  }

  function persistHistory() {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, HISTORY_MAX)));
    } catch (_) {
      // Quota dépassé : on garde les analyses les plus récentes uniquement.
      history = history.slice(0, 3);
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
      } catch (_) {
        /* stockage indisponible : l'interface continue de fonctionner */
      }
    }
  }

  function saveToHistory(report) {
    history = history.filter((entry) => entry.report.scan_id !== report.scan_id);
    history.unshift({ savedAt: new Date().toISOString(), report });
    history = history.slice(0, HISTORY_MAX);
    persistHistory();
  }

  function findPrevious(report) {
    const host = hostOf(report);
    return (
      history.find(
        (entry) => entry.report.scan_id !== report.scan_id && hostOf(entry.report) === host
      ) || null
    );
  }

  function renderComparison(report) {
    const node = $("#comparison");
    const previous = findPrevious(report);
    if (!previous) {
      node.hidden = true;
      return;
    }

    const previousIds = new Set((previous.report.findings || []).map((f) => f.id));
    const currentIds = new Set((report.findings || []).map((f) => f.id));
    const fixed = [...previousIds].filter((id) => !currentIds.has(id)).length;
    const added = [...currentIds].filter((id) => !previousIds.has(id)).length;
    const delta = report.score - previous.report.score;

    const parts = [];
    const dateLabel = formatDate(previous.report.started_at);
    const deltaText =
      delta > 0
        ? `<span class="up">+${delta} points</span>`
        : delta < 0
        ? `<span class="down">${delta} points</span>`
        : "score identique";

    parts.push(`<span>vs ${dateLabel} (score ${previous.report.score}) : ${deltaText}</span>`);
    if (fixed) parts.push(`<span>${fixed} constat${fixed > 1 ? "s" : ""} corrigé${fixed > 1 ? "s" : ""}</span>`);
    if (added) parts.push(`<span>${added} nouveau${added > 1 ? "x" : ""} constat${added > 1 ? "s" : ""}</span>`);

    node.innerHTML = parts.join(" · ");
    node.hidden = false;
  }

  function renderHistory() {
    const panel = $("#history-panel");
    const list = $("#history");
    list.innerHTML = "";
    if (!history.length) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;

    history.forEach((entry) => {
      const report = entry.report;
      const item = el("button", "history-item");
      item.type = "button";
      if (currentReport && report.scan_id === currentReport.scan_id) {
        item.classList.add("current");
      }
      item.appendChild(el("span", "history-host", hostOf(report)));
      item.appendChild(el("span", "history-date", formatDate(report.started_at)));
      const score = el("span", "history-score", `${report.score}/100`);
      score.style.color =
        report.score >= 80 ? "#34d399" : report.score >= 60 ? "#ffd166" : "#ff8a3d";
      item.appendChild(score);
      item.appendChild(el("span", "history-score", report.grade));
      item.addEventListener("click", () => {
        renderReport(report, { fromHistory: true });
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
      list.appendChild(item);
    });
  }

  function clearHistory() {
    history = [];
    try {
      localStorage.removeItem(HISTORY_KEY);
    } catch (_) {}
    renderHistory();
    $("#comparison").hidden = true;
  }

  /* --------------------------------- Copie -------------------------------- */

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      const area = document.createElement("textarea");
      area.value = text;
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
      return false;
    }
  }

  function findingToText(finding) {
    return [
      `[${finding.severity_label || severityLabel(finding.severity)}] ${finding.title}`,
      `Catégorie : ${finding.category}`,
      "",
      finding.description,
      "",
      "Preuve :",
      finding.evidence || "—",
      "",
      "Remédiation :",
      finding.remediation || "—",
      finding.reference ? `\nRéférence : ${finding.reference}` : "",
    ].join("\n");
  }

  /* ------------------------------- Profil -------------------------------- */

  function selectedProfile() {
    const checked = document.querySelector('input[name="profile"]:checked');
    return checked ? checked.value : "quick";
  }

  /* ------------------------------ Tableau de bord ------------------------- */

  function showView(view) {
    const isDashboard = view === "dashboard";
    $("#dashboard").hidden = !isDashboard;
    document.querySelector(".hero").hidden = isDashboard;
    $("#method").hidden = isDashboard;

    $("#nav-analyzer").setAttribute("aria-pressed", isDashboard ? "false" : "true");
    $("#nav-dashboard").setAttribute("aria-pressed", isDashboard ? "true" : "false");
    $("#nav-watch").setAttribute("aria-pressed", "false");

    if (isDashboard) {
      results.hidden = true;
      progressPanel.hidden = true;
      errorPanel.hidden = true;
      refreshDashboard();
    } else if (currentReport) {
      results.hidden = false;
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function renderDashboardSkeleton() {
    const kpis = $("#kpis");
    if (kpis && !kpis.children.length) {
      kpis.innerHTML = "";
      for (let index = 0; index < 5; index += 1) {
        const card = el("div", "kpi is-loading");
        card.appendChild(el("div", "kpi-label skeleton", "Chargement"));
        card.appendChild(el("div", "kpi-value skeleton", "—"));
        kpis.appendChild(card);
      }
    }
  }

  async function refreshDashboard() {
    renderDashboardSkeleton();
    if (dashboardLoaded) {
      renderDashboard();
      return;
    }
    try {
      const [statsResponse, scansResponse] = await Promise.all([
        fetch("/api/stats"),
        fetch("/api/scans?limit=50"),
      ]);
      if (!statsResponse.ok || !scansResponse.ok) throw new Error("API indisponible");
      dashboardData.stats = await statsResponse.json();
      dashboardData.scans = (await scansResponse.json()).scans || [];
      dashboardLoaded = true;
      dashboardData.hosts = ((dashboardData.stats || {}).hosts || []).map(
        (item) => (typeof item === "string" ? item : item.host)
      ).filter(Boolean);
      renderDashboard();
      loadWatch();
      loadTrend();
    } catch (error) {
      $("#kpis").innerHTML = "";
      $("#scans-body").innerHTML = "";
      $("#dash-empty").hidden = false;
      $("#dash-empty").textContent = `Historique indisponible : ${error.message}`;
    }
  }

  function renderDashboard() {
    renderKpis(dashboardData.stats || {});
    renderChart((dashboardData.stats || {}).series || []);
    renderScansTable(dashboardData.scans || []);
  }

  function renderKpis(stats) {
    const kpis = $("#kpis");
    kpis.innerHTML = "";
    const severity = stats.severity || {};
    const cards = [
      {
        label: "Analyses",
        value: String(stats.total_scans || 0),
        hint: `${(stats.hosts || []).length} cible(s) suivie(s)`,
      },
      {
        label: "Score moyen",
        value: stats.total_scans ? `${stats.average_score}` : "—",
        hint: "sur 100, toutes analyses confondues",
      },
      {
        label: "Critiques cumulés",
        value: String(severity.critical || 0),
        hint: "à traiter en premier",
      },
      {
        label: "Constats élevés",
        value: String(severity.high || 0),
        hint: "durcissement à planifier",
      },
      {
        label: "Cibles surveillées",
        value: String(stats.watches_enabled || 0),
        hint: stats.watches ? `${stats.watches} configurée(s)` : "aucune surveillance active",
      },
    ];
    cards.forEach((card) => {
      const node = el("div", "kpi");
      node.appendChild(el("div", "kpi-label", card.label));
      node.appendChild(el("div", "kpi-value", card.value));
      node.appendChild(el("div", "kpi-hint", card.hint));
      kpis.appendChild(node);
    });
  }

  function renderChart(series) {
    const panel = $("#chart-panel");
    const container = $("#chart");
    container.innerHTML = "";
    if (!series || series.length < 2) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;

    const W = 640;
    const H = 180;
    const pad = 26;
    const n = series.length;
    const x = (i) => pad + (i / (n - 1)) * (W - pad * 2);
    const y = (score) => pad + ((100 - score) / 100) * (H - pad * 2);

    const points = series.map((item, index) => [x(index), y(item.score)]);
    const line = points.map(([px, py], index) => `${index === 0 ? "M" : "L"}${px.toFixed(1)},${py.toFixed(1)}`).join(" ");
    const area = `${line} L${x(n - 1).toFixed(1)},${H - pad} L${pad},${H - pad} Z`;

    const grid = [0, 25, 50, 75, 100]
      .map(
        (value) =>
          `<line x1="${pad}" y1="${y(value)}" x2="${W - pad}" y2="${y(value)}" stroke="rgba(140,170,210,.14)" stroke-width="1"/>` +
          `<text x="4" y="${y(value) + 4}" fill="#66788f" font-size="9" font-family="ui-monospace,monospace">${value}</text>`
      )
      .join("");

    const dots = series
      .map(
        (item, index) =>
          `<circle cx="${x(index).toFixed(1)}" cy="${y(item.score).toFixed(1)}" r="3.4" fill="#22d3ee" stroke="#0a1120" stroke-width="1.5">` +
          `<title>${escapeHtml(item.host)} — ${item.score}/100</title></circle>`
      )
      .join("");

    container.innerHTML = `
      <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Évolution du score">
        <defs>
          <linearGradient id="chart-line" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stop-color="#22d3ee"/><stop offset="1" stop-color="#a78bfa"/>
          </linearGradient>
          <linearGradient id="chart-area" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="rgba(34,211,238,.28)"/><stop offset="1" stop-color="rgba(34,211,238,0)"/>
          </linearGradient>
        </defs>
        ${grid}
        <path d="${area}" fill="url(#chart-area)" />
        <path d="${line}" fill="none" stroke="url(#chart-line)" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"/>
        ${dots}
      </svg>`;

    const last = series[series.length - 1];
    const first = series[0];
    const delta = last.score - first.score;
    const sign = delta > 0 ? "+" : "";
    $("#chart-caption").textContent =
      `${n} analyses · dernier score ${last.score}/100 · ${sign}${delta} pts depuis la première`;
  }

  function renderScansTable(scans) {
    const body = $("#scans-body");
    body.innerHTML = "";
    $("#scans-count").textContent = `${scans.length} analyse(s)`;
    $("#dash-empty").hidden = scans.length > 0;

    scans.forEach((scan) => {
      const row = document.createElement("tr");
      const hostCell = el("td", "scan-host", scan.host);
      if (scan.verified) {
        const badge = el("span", "verified-mini", "✓");
        badge.title = "Domaine vérifié";
        hostCell.appendChild(badge);
      }
      row.appendChild(hostCell);
      row.appendChild(el("td", "scan-date", formatDate(scan.created_at)));
      const profile = el("td");
      profile.appendChild(el("span", `scan-profile ${scan.profile === "deep" ? "deep" : ""}`, scan.profile));
      row.appendChild(profile);

      const scoreCell = el("td");
      const pill = el("span", "score-pill", `${scan.score}/100`);
      pill.style.color =
        scan.score >= 80 ? "#34d399" : scan.score >= 60 ? "#ffd166" : scan.score >= 35 ? "#ff8a3d" : "#ff5c78";
      scoreCell.appendChild(pill);
      row.appendChild(scoreCell);

      const counts = scan.counts || {};
      const critical = counts.critical || 0;
      const summary = `${scan.findings_count} constat(s)` + (critical ? ` · ${critical} critique(s)` : "");
      row.appendChild(el("td", "scan-date", summary));

      const actions = el("td");
      const wrapper = el("div", "row-actions");
      const open = el("button", "icon-btn", "Ouvrir");
      open.type = "button";
      open.addEventListener("click", () => openStoredScan(scan.id));
      const html = el("button", "icon-btn", "HTML");
      html.type = "button";
      html.addEventListener("click", () => window.open(`/api/scans/${scan.id}/report.html`, "_blank"));
      const sarif = el("button", "icon-btn", "SARIF");
      sarif.type = "button";
      sarif.addEventListener("click", () => window.open(`/api/scans/${scan.id}/sarif`, "_blank"));
      const remove = el("button", "icon-btn danger", "Suppr.");
      remove.type = "button";
      remove.addEventListener("click", () => deleteScan(scan.id));
      wrapper.append(open, html, sarif, remove);
      actions.appendChild(wrapper);
      row.appendChild(actions);

      body.appendChild(row);
    });
  }

  async function openStoredScan(scanId) {
    try {
      const response = await fetch(`/api/scans/${scanId}`);
      if (!response.ok) throw new Error("Analyse introuvable");
      const report = await response.json();
      showView("analyzer");
      renderReport(report, { fromHistory: true });
    } catch (error) {
      alert(error.message);
    }
  }

  async function deleteScan(scanId) {
    if (!window.confirm("Supprimer définitivement cette analyse de l'historique ?")) return;
    try {
      const response = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
      if (!response.ok) throw new Error("Suppression impossible");
      dashboardLoaded = false;
      await refreshDashboard();
    } catch (error) {
      alert(error.message);
    }
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[char]);
  }

  /* --------------------- Vérification de propriété ------------------------ */

  let verifyHost = null;

  function renderVerification(report) {
    const verified = Boolean(report.verified);
    $("#verify-badge").hidden = !verified;
    $("#verify-open").textContent = verified ? "Voir la preuve" : "Vérifier la propriété";
  }

  async function openVerifyDialog() {
    const host = hostOf(currentReport || { target: input.value, final_url: "" });
    if (!host) return;
    verifyHost = host;
    const status = $("#verify-status");
    status.textContent = "Chargement du jeton…";
    status.className = "muted small";
    $("#verify-dns").textContent = "";
    $("#verify-file").textContent = "";
    const dialog = $("#verify-dialog");
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");

    try {
      const response = await fetch(`/api/verify/${encodeURIComponent(host)}`);
      if (!response.ok) throw new Error("Domaine invalide");
      const data = await response.json();
      $("#verify-dns").textContent =
        `${data.instructions.record_name}  TXT  ${data.instructions.record_value}`;
      $("#verify-file").textContent =
        `${data.instructions.file_url}\n\n${data.token}`;
      if (data.verified) {
        status.className = "small ok";
        status.textContent = `Déjà vérifié (${data.method}) le ${formatDate(data.verified_at)}.`;
      } else {
        status.className = "muted small";
        status.textContent = "Aucune preuve enregistrée pour ce domaine.";
      }
    } catch (error) {
      status.className = "small ko";
      status.textContent = error.message;
    }
  }

  function closeVerifyDialog() {
    const dialog = $("#verify-dialog");
    if (typeof dialog.close === "function") dialog.close();
    else dialog.removeAttribute("open");
  }

  async function runVerify() {
    if (!verifyHost) return;
    const button = $("#verify-now");
    const status = $("#verify-status");
    button.disabled = true;
    button.querySelector(".btn-label").textContent = "Vérification…";
    status.className = "muted small";
    status.textContent = "Interrogation du DNS et du fichier .well-known…";

    try {
      const response = await fetch(`/api/verify/${encodeURIComponent(verifyHost)}/check`, {
        method: "POST",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Vérification impossible");
      if (data.verified) {
        status.className = "small ok";
        status.textContent = `Vérifié ✓ (${data.method}) — ${data.detail}`;
        $("#verify-badge").hidden = false;
        $("#verify-open").textContent = "Voir la preuve";
        if (currentReport) currentReport.verified = true;
      } else {
        status.className = "small ko";
        status.textContent = data.detail;
      }
    } catch (error) {
      status.className = "small ko";
      status.textContent = error.message;
    } finally {
      button.disabled = false;
      button.querySelector(".btn-label").textContent = "Vérifier maintenant";
    }
  }

  /* ---------------------------- Plan d'action ----------------------------- */

  async function fetchPlan(report) {
    const panel = $("#plan-panel");
    if (!report || !report.scan_id) {
      panel.hidden = true;
      return;
    }
    try {
      const response = await fetch(`/api/scans/${report.scan_id}/plan`);
      if (!response.ok) {
        panel.hidden = true;
        return;
      }
      renderPlan(await response.json());
    } catch (_) {
      panel.hidden = true;
    }
  }

  function renderPlan(plan) {
    const panel = $("#plan-panel");
    if (!plan || !plan.available) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;
    $("#plan-caption").textContent =
      `${plan.current_score}/100 → ${plan.projected_score}/100 (+${plan.potential_gain} pts)`;

    const host = $("#plan-cols");
    host.innerHTML = "";
    ["quick", "sprint", "project"].forEach((key) => {
      const bucket = plan.buckets[key];
      const column = el("div", "plan-col");
      const title = el("h3", null, bucket.label);
      title.appendChild(el("span", "plan-count", String(bucket.items.length)));
      column.appendChild(title);
      column.appendChild(el("p", "plan-detail", bucket.detail));

      const list = el("ul", "plan-items");
      if (!bucket.items.length) {
        list.appendChild(el("li", "empty", "Rien à faire ici 🎉"));
      }
      bucket.items.slice(0, 8).forEach((item) => {
        const li = el("li");
        const sev = el("span", "diff-sev", item.severity_label);
        sev.dataset.sev = item.severity;
        li.appendChild(sev);
        const body = el("div", "plan-body");
        body.appendChild(el("strong", null, item.title));
        if (item.action) body.appendChild(el("em", null, item.action));
        li.appendChild(body);
        list.appendChild(li);
      });
      column.appendChild(list);
      host.appendChild(column);
    });
  }

  /* ------------------------- Dépendances tierces -------------------------- */

  function renderThirdParties(report) {
    const panel = $("#third-panel");
    const list = $("#third-list");
    const items = report.third_parties || [];
    list.innerHTML = "";
    if (!items.length) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;
    $("#third-count").textContent = `${items.length} domaine(s) tiers`;
    items.slice(0, 15).forEach((item) => {
      const li = el("li");
      li.appendChild(el("span", "host", item.host));
      li.appendChild(el("span", "role", item.role));
      li.appendChild(el("span", "res", (item.resources || []).join(" · ")));
      list.appendChild(li);
    });
  }

  /* -------------------------------- Onglets ------------------------------- */

  const TABS = ["synthese", "situation", "constats", "technique"];

  function switchTab(name) {
    if (!TABS.includes(name)) return;
    document.querySelectorAll(".tab").forEach((tab) => {
      const active = tab.dataset.tab === name;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
    });
    document.querySelectorAll("[data-tab]").forEach((node) => {
      if (node.classList.contains("tab") || !TABS.includes(node.dataset.tab)) return;
      node.classList.toggle("is-hidden", node.dataset.tab !== name);
    });
  }

  function updateTabCounts(report) {
    const findings = (report.findings || []).length;
    const technical = (report.checks || []).length + (report.pages || []).length;
    $("#tab-count-constats").textContent = findings || "";
    $("#tab-count-situation").textContent = Math.min(5, findings) || "";
    $("#tab-count-technique").textContent = technical || "";
    $("#tab-count-synthese").textContent = (report.priorities || []).length || "";
  }

  /* --------------------------- Synthèse exécutive -------------------------- */

  function radarSvg(axes, size = 240) {
    if (!axes || !axes.length) return "";
    const count = axes.length;
    const center = size / 2;
    const radius = center - 34;
    let inner = "";
    [0.25, 0.5, 0.75, 1].forEach((ratio) => {
      inner += `<circle cx="${center}" cy="${center}" r="${(radius * ratio).toFixed(1)}" fill="none" stroke="rgba(139,157,186,.18)"/>`;
    });
    const points = [];
    axes.forEach((axis, index) => {
      const angle = (2 * Math.PI * index) / count - Math.PI / 2;
      const ratio = Math.max(0.04, Math.min(1, (axis.value || 0) / 100));
      points.push(
        `${(center + radius * ratio * Math.cos(angle)).toFixed(1)},${(center + radius * ratio * Math.sin(angle)).toFixed(1)}`
      );
      const ex = center + radius * Math.cos(angle);
      const ey = center + radius * Math.sin(angle);
      inner += `<line x1="${center}" y1="${center}" x2="${ex.toFixed(1)}" y2="${ey.toFixed(1)}" stroke="rgba(139,157,186,.16)"/>`;
      const lx = center + (radius + 16) * Math.cos(angle);
      const ly = center + (radius + 16) * Math.sin(angle);
      const anchor = Math.abs(Math.cos(angle)) < 0.3 ? "middle" : Math.cos(angle) > 0 ? "start" : "end";
      inner += `<text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="${anchor}" dominant-baseline="middle" font-size="9.5">${escapeHtml((axis.label || "").slice(0, 18))}</text>`;
    });
    return `<svg viewBox="0 0 ${size} ${size}" role="img" aria-label="Exposition relative par catégorie">${inner}<polygon points="${points.join(" ")}" fill="rgba(34,211,238,.14)" stroke="#22d3ee" stroke-width="1.8"/></svg>`;
  }

  function renderExecutive(report) {
    const executive = report.executive;
    const panel = $("#exec-panel");
    if (!executive) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;

    const pill = $("#exec-risk");
    pill.textContent = `Risque ${executive.risk_level || "—"}`;
    pill.dataset.risk = executive.risk_level || "";

    const summaryRisk = $("#summary-risk");
    if (summaryRisk) {
      summaryRisk.hidden = false;
      summaryRisk.textContent = `Risque ${executive.risk_level || "—"}`;
      summaryRisk.dataset.risk = executive.risk_level || "";
    }

    $("#exec-headline").textContent = executive.headline || "";
    const dangerText = executive.danger_max ? ` · danger max ${executive.danger_max}/10` : "";
    $("#exec-paragraph").textContent = (executive.paragraph || "") + dangerText;

    const risks = $("#exec-risks");
    risks.innerHTML = "";
    (executive.key_risks || []).forEach((risk) => {
      const li = el("li");
      li.style.borderLeftColor =
        { critical: "#ff3b5c", high: "#ff8a3d", medium: "#ffd166", low: "#4cc9f0", info: "#93a4bd" }[
          risk.severity
        ] || "var(--border-strong)";
      const sev = el("span", "sev", risk.severity_label);
      sev.dataset.sev = risk.severity;
      li.appendChild(sev);
      li.appendChild(el("strong", null, risk.title));
      li.appendChild(el("em", null, risk.impact));
      risks.appendChild(li);
    });
    if (!(executive.key_risks || []).length) {
      risks.appendChild(el("li", null, "Aucun risque majeur détecté."));
    }

    const strengths = $("#exec-strengths");
    strengths.innerHTML = "";
    (executive.strengths || []).forEach((item) => strengths.appendChild(el("li", null, item)));
    if (!(executive.strengths || []).length) {
      strengths.appendChild(el("li", null, "Rien de solide à mettre en avant pour l'instant."));
    }

    $("#radar").innerHTML = radarSvg(executive.radar || []);
  }

  /* --------------------------- Rapport de situation ------------------------ */

  function dangerMeter(value, label) {
    const wrapper = el("div", "danger");
    const blocks = el("div", "danger-blocks");
    for (let index = 0; index < 10; index += 1) {
      blocks.appendChild(el("span", index < value ? "on" : "off"));
    }
    wrapper.appendChild(blocks);
    wrapper.appendChild(el("b", null, `${value}/10`));
    if (label) wrapper.appendChild(el("em", null, label));
    return wrapper;
  }

  function renderSituation(report) {
    const panel = $("#situation-panel");
    const host = $("#situation-list");
    const findings = [...(report.findings || [])];
    if (!findings.length) {
      panel.hidden = true;
      host.innerHTML = "";
      return;
    }
    panel.hidden = false;
    host.innerHTML = "";

    findings
      .sort((a, b) => (b.danger || 0) - (a.danger || 0))
      .slice(0, 5)
      .forEach((finding) => {
        const card = el("article", "situation-card");
        const top = el("div", "sit-top");
        top.appendChild(el("h3", null, finding.title));
        top.appendChild(dangerMeter(finding.danger || 0, ""));
        card.appendChild(top);
        card.appendChild(
          el(
            "p",
            "sit-cat",
            `${finding.category || ""} · ${finding.severity_label || severityLabel(finding.severity)}` +
              (finding.skill ? ` · compétence ${finding.skill}` : "")
          )
        );

        card.appendChild(el("h4", null, "Comment y arriver"));
        const steps = el("ol", "access");
        (finding.access || []).forEach((step) => steps.appendChild(el("li", null, step)));
        if (!(finding.access || []).length) {
          steps.appendChild(el("li", null, "Chemin d'accès non détaillé."));
        }
        card.appendChild(steps);

        card.appendChild(el("h4", null, "Ce que ça révèle"));
        card.appendChild(el("p", "reveals", finding.reveals || "Impact non détaillé."));

        const fix = el("p", "sit-fix");
        fix.appendChild(el("strong", null, "Correction : "));
        fix.appendChild(document.createTextNode(finding.remediation || "À définir."));
        card.appendChild(fix);

        card.addEventListener("click", () => {
          switchTab("constats");
          const node = document.querySelector(`.finding[data-id="${finding.id}"]`);
          if (node) {
            node.classList.add("open");
            const head = node.querySelector(".finding-head");
            if (head) head.setAttribute("aria-expanded", "true");
            node.scrollIntoView({ behavior: "smooth", block: "center" });
          }
        });
        host.appendChild(card);
      });
  }

  /* ----------------------------- Surveillance ----------------------------- */

  async function loadWatch() {
    const list = $("#watch-list");
    const empty = $("#watch-empty");
    if (!list.children.length) {
      list.innerHTML = "";
      const placeholder = el("li", "is-loading skeleton");
      list.appendChild(placeholder);
    }
    try {
      const response = await fetch("/api/watch");
      if (!response.ok) throw new Error("API indisponible");
      const data = await response.json();
      $("#watch-status").textContent = data.scheduler
        ? `Planificateur actif · vérification toutes les ${Math.round(data.tick_seconds / 60)} min`
        : "Planificateur inactif (VULNLENS_WATCH=1 pour l'activer)";
      list.innerHTML = "";
      (data.items || []).forEach((item) => {
        const li = el("li");
        li.appendChild(el("span", "watch-host", item.host));
        const state = el("span", `watch-state ${item.enabled ? "on" : "off"}`, item.enabled ? "suivi" : "en pause");
        li.appendChild(state);
        li.appendChild(el("span", "watch-meta", `${item.profile} · ${item.interval_hours} h`));
        const scoreText = item.last_score === null || item.last_score === undefined ? "jamais analysé" : `score ${item.last_score}`;
        li.appendChild(el("span", "watch-meta", scoreText));
        const nextLabel = item.due
          ? "échéance atteinte"
          : item.next_run
          ? `prochain : ${formatDate(item.next_run)}`
          : "en pause";
        li.appendChild(el("span", "watch-meta", nextLabel));

        const actions = el("div", "watch-actions");
        if (item.last_scan_id) {
          const open = el("button", "btn-ghost btn-mini", "Voir");
          open.type = "button";
          open.addEventListener("click", () => openStoredScan(item.last_scan_id));
          actions.appendChild(open);
        }
        const run = el("button", "btn-ghost btn-mini", "Analyser");
        run.type = "button";
        run.addEventListener("click", () => runWatch(item.host, run));
        actions.appendChild(run);
        const toggle = el("button", "btn-ghost btn-mini", item.enabled ? "Pause" : "Reprendre");
        toggle.type = "button";
        toggle.addEventListener("click", () => toggleWatch(item, !item.enabled));
        actions.appendChild(toggle);
        const remove = el("button", "btn-ghost btn-mini", "Retirer");
        remove.type = "button";
        remove.addEventListener("click", () => deleteWatch(item.host));
        actions.appendChild(remove);
        li.appendChild(actions);
        list.appendChild(li);
      });
      empty.hidden = (data.items || []).length > 0;
    } catch (error) {
      list.innerHTML = "";
      empty.hidden = false;
      empty.textContent = `Surveillance indisponible : ${error.message}`;
    }
  }

  async function addWatch(event) {
    event.preventDefault();
    const host = $("#watch-host").value.trim();
    if (!host) return;
    const payload = {
      host,
      profile: $("#watch-profile").value,
      interval_hours: Number($("#watch-interval").value),
    };
    try {
      const response = await fetch("/api/watch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || "Ajout impossible");
      }
      $("#watch-host").value = "";
      toast(`${payload.host} ajouté à la surveillance`, "ok");
      await loadWatch();
    } catch (error) {
      $("#watch-status").textContent = error.message;
    }
  }

  async function toggleWatch(item, enabled) {
    await fetch("/api/watch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        host: item.host,
        profile: item.profile,
        interval_hours: item.interval_hours,
        enabled,
      }),
    });
    loadWatch();
  }

  async function deleteWatch(host) {
    const response = await fetch(`/api/watch/${encodeURIComponent(host)}`, { method: "DELETE" });
    if (response.ok) toast(`${host} retiré de la surveillance`);
    else toast("Retrait impossible", "ko");
    loadWatch();
  }

  async function runWatch(host, button) {
    button.disabled = true;
    button.textContent = "Analyse…";
    try {
      const response = await fetch(`/api/watch/${encodeURIComponent(host)}/run`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Analyse impossible");
      button.textContent = `Score ${data.score}`;
      toast(`${host} : score ${data.score}/100${data.previous_score != null ? ` (avant ${data.previous_score})` : ""}`, data.score < 50 ? "ko" : "ok");
      setTimeout(() => {
        button.textContent = "Analyser";
        button.disabled = false;
      }, 2200);
      loadWatch();
    } catch (error) {
      button.textContent = "Échec";
      toast(`Analyse impossible : ${error.message}`, "ko");
      setTimeout(() => {
        button.textContent = "Analyser";
        button.disabled = false;
      }, 2200);
    }
  }

  /* -------------------------------- Tendance ------------------------------ */

  async function loadTrend(host) {
    const panel = $("#trend-panel");
    const container = $("#trend");
    const select = $("#trend-host");
    let target = host;
    if (!target) {
      const hosts = dashboardData.hosts || [];
      target = hosts[0] || "";
    }
    if (!target) {
      panel.hidden = true;
      return;
    }
    try {
      const response = await fetch(`/api/trend/${encodeURIComponent(target)}`);
      if (!response.ok) {
        panel.hidden = true;
        return;
      }
      const data = await response.json();
      const points = data.points || [];
      if (points.length < 2) {
        panel.hidden = true;
        return;
      }
      panel.hidden = false;
      select.innerHTML = "";
      (dashboardData.hosts || [target]).forEach((option) => {
        const node = el("option", null, option);
        node.value = option;
        if (option === target) node.selected = true;
        select.appendChild(node);
      });
      container.innerHTML = sparkline(points);
    } catch (_) {
      panel.hidden = true;
    }
  }

  function sparkline(points) {
    const W = 720;
    const H = 150;
    const pad = 22;
    const scores = points.map((point) => point.score);
    const min = Math.min(...scores);
    const max = Math.max(...scores);
    const span = Math.max(12, max - min);
    const x = (index) => pad + (index / Math.max(1, points.length - 1)) * (W - pad * 2);
    const y = (score) => pad + (1 - (score - (max - span)) / span) * (H - pad * 2);
    const path = points.map((point, index) => `${index ? "L" : "M"}${x(index).toFixed(1)},${y(point.score).toFixed(1)}`).join(" ");
    const area = `${path} L${x(points.length - 1).toFixed(1)},${H - pad} L${pad},${H - pad} Z`;
    const dots = points
      .map(
        (point, index) =>
          `<circle cx="${x(index).toFixed(1)}" cy="${y(point.score).toFixed(1)}" r="3" fill="#0b1220" stroke="#22d3ee" stroke-width="1.6"><title>${point.score}/100 — ${formatDate(point.date)}</title></circle>`
      )
      .join("");
    return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Évolution du score">
      <defs><linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stop-color="rgba(34,211,238,.35)"/><stop offset="1" stop-color="rgba(34,211,238,0)"/>
      </linearGradient></defs>
      <path d="${area}" fill="url(#trendFill)"/>
      <path d="${path}" fill="none" stroke="#22d3ee" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"/>
      ${dots}
      <text x="${pad}" y="${H - 5}" font-size="10" fill="#8b9dba">${formatDate(points[0].date)}</text>
      <text x="${W - pad}" y="${H - 5}" font-size="10" fill="#8b9dba" text-anchor="end">${formatDate(points[points.length - 1].date)}</text>
    </svg>`;
  }

  /* --------------------------- Pages analysées ---------------------------- */

  function renderPages(report) {
    const panel = $("#pages-panel");
    const list = $("#pages-list");
    const pages = report.pages || [];
    list.innerHTML = "";
    if (pages.length <= 1) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;
    $("#pages-count").textContent = `${pages.length} page(s) explorée(s)`;

    pages.forEach((page) => {
      const li = el("li");
      const status = el("span", `page-status ${page.status && page.status < 400 ? "ok" : ""}`, String(page.status || "—"));
      li.appendChild(status);
      li.appendChild(el("span", null, page.url));
      if (page.title) li.appendChild(el("span", "page-title", page.title));
      list.appendChild(li);
    });
  }

  /* ------------------------------- Diff ---------------------------------- */

  async function fetchDiff(report) {
    const panel = $("#diff-panel");
    if (!report || !report.scan_id) {
      panel.hidden = true;
      return;
    }
    try {
      const response = await fetch(`/api/scans/${report.scan_id}/diff`);
      if (!response.ok) {
        panel.hidden = true;
        return;
      }
      renderDiff(await response.json());
    } catch (_) {
      panel.hidden = true;
    }
  }

  function renderDiff(diff) {
    const panel = $("#diff-panel");
    if (!diff || !diff.available) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;

    const delta = diff.score_delta || 0;
    const deltaLabel = delta > 0 ? `+${delta} pts` : delta < 0 ? `${delta} pts` : "stable";
    $("#diff-caption").textContent =
      `vs analyse du ${formatDate(diff.previous_at)} (score ${diff.previous_score}/100) · ${deltaLabel}`;

    const render = (items, target, emptyLabel) => {
      const list = $(target);
      list.innerHTML = "";
      if (!items.length) {
        list.appendChild(el("li", "empty", emptyLabel));
        return;
      }
      items.forEach((item) => {
        const li = el("li");
        const sev = el("span", "diff-sev", severityLabel(item.severity));
        sev.dataset.sev = item.severity;
        li.appendChild(sev);
        li.appendChild(el("span", null, item.title));
        list.appendChild(li);
      });
    };

    render(diff.new || [], "#diff-new", "Aucun nouveau constat");
    render(diff.fixed || [], "#diff-fixed", "Aucun constat corrigé");
    $("#diff-persistent").textContent =
      `${(diff.summary && diff.summary.persistent) || 0} constat(s) toujours présent(s).`;
  }

  /* --------------------------- Exports serveur ---------------------------- */

  function openServerExport(kind) {
    if (!currentReport || !currentReport.scan_id) {
      alert("Ce rapport n'est pas enregistré : relance l'analyse pour obtenir les exports serveur.");
      return;
    }
    const paths = {
      html: `/api/scans/${currentReport.scan_id}/report.html`,
      sarif: `/api/scans/${currentReport.scan_id}/sarif`,
    };
    window.open(paths[kind], "_blank");
  }

  /* -------------------------------- Exports ------------------------------- */

  function downloadJson() {
    if (!currentReport) return;
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const host = new URL(currentReport.final_url || currentReport.target, location.href).hostname;
    link.href = url;
    link.download = `vulnlens-${host}-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function buildMarkdown(report) {
    const lines = [];
    lines.push(`# Rapport VulnLens — ${report.final_url || report.target}`);
    lines.push("");
    lines.push(`- Score : **${report.score}/100** (note ${report.grade})`);
    lines.push(`- Cible : ${report.final_url || report.target}`);
    lines.push(`- Date : ${formatDate(report.started_at)}`);
    lines.push(`- Durée : ${humanDuration(report.duration_ms)}`);
    const counts = report.counts || {};
    lines.push(
      `- Constats : ` +
        SEVERITY_ORDER.map((sev) => `${counts[sev] || 0} ${severityLabel(sev).toLowerCase()}`).join(
          " · "
        )
    );
    lines.push("");

    const findings = report.findings || [];
    if (!findings.length) {
      lines.push("Aucun problème détecté par les contrôles passifs. 🎉");
    }

    findings.forEach((finding, index) => {
      lines.push(`## ${index + 1}. [${severityLabel(finding.severity)}] ${finding.title}`);
      lines.push(`_${finding.category}_`);
      lines.push("");
      lines.push(finding.description);
      if (finding.evidence) {
        lines.push("");
        lines.push("```");
        lines.push(finding.evidence);
        lines.push("```");
      }
      if (finding.remediation) {
        lines.push("");
        lines.push(`**Remédiation :** ${finding.remediation}`);
      }
      if (finding.reference) {
        lines.push("");
        lines.push(`Référence : ${finding.reference}`);
      }
      lines.push("");
    });
    lines.push("---");
    lines.push("Généré par VulnLens — scanner passif, tests autorisés uniquement.");
    return lines.join("\n");
  }

  async function copyMarkdown() {
    if (!currentReport) return;
    const markdown = buildMarkdown(currentReport);
    const btn = $("#copy-md");
    try {
      await navigator.clipboard.writeText(markdown);
      btn.textContent = "Copié ✓";
    } catch (_) {
      const area = document.createElement("textarea");
      area.value = markdown;
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
      btn.textContent = "Copié ✓";
    }
    setTimeout(() => {
      btn.textContent = "Copier le rapport";
    }, 1800);
  }

  /* -------------------------------- Événements ---------------------------- */

  form.addEventListener("submit", startScan);
  $("#print-report").addEventListener("click", () => window.print());
  $("#nav-analyzer").addEventListener("click", () => showView("analyzer"));
  $("#nav-dashboard").addEventListener("click", () => showView("dashboard"));
  $("#nav-watch").addEventListener("click", () => {
    showView("dashboard");
    setTimeout(() => $("#watch-panel").scrollIntoView({ behavior: "smooth", block: "center" }), 120);
  });
  $("#dash-refresh").addEventListener("click", () => {
    dashboardLoaded = false;
    refreshDashboard();
  });
  $("#dash-new").addEventListener("click", () => {
    showView("analyzer");
    input.focus();
  });
  $("#export-html").addEventListener("click", () => openServerExport("html"));
  $("#verify-open").addEventListener("click", openVerifyDialog);
  $("#verify-close").addEventListener("click", closeVerifyDialog);
  $("#verify-now").addEventListener("click", runVerify);
  $("#copy-dns").addEventListener("click", async () => {
    await copyText($("#verify-dns").textContent);
    $("#copy-dns").textContent = "Copié ✓";
    setTimeout(() => ($("#copy-dns").textContent = "Copier"), 1500);
  });
  $("#copy-file").addEventListener("click", async () => {
    await copyText($("#verify-file").textContent);
    $("#copy-file").textContent = "Copié ✓";
    setTimeout(() => ($("#copy-file").textContent = "Copier"), 1500);
  });
  $("#export-sarif").addEventListener("click", () => openServerExport("sarif"));
  $("#clear-history").addEventListener("click", clearHistory);
  $("#export-json").addEventListener("click", downloadJson);
  $("#copy-md").addEventListener("click", copyMarkdown);
  $("#new-scan").addEventListener("click", () => {
    input.value = "";
    input.focus();
    results.hidden = true;
    errorPanel.hidden = true;
    progressPanel.hidden = true;
    window.scrollTo({ top: 0, behavior: "smooth" });
  });

  $("#findings-search").addEventListener("input", (event) => {
    searchTerm = event.target.value.trim();
    renderFindings();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
      if (results.hidden) return;
      event.preventDefault();
      $("#findings-search").focus();
    }
    if (event.key === "Escape" && document.activeElement === $("#findings-search")) {
      $("#findings-search").value = "";
      searchTerm = "";
      renderFindings();
      $("#findings-search").blur();
    }
  });

  document.querySelectorAll(".tab").forEach((tab, index, all) => {
    tab.addEventListener("click", () => switchTab(tab.dataset.tab));
    tab.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
      const next = (index + (event.key === "ArrowRight" ? 1 : all.length - 1)) % all.length;
      all[next].focus();
      switchTab(all[next].dataset.tab);
    });
  });
  $("#watch-form").addEventListener("submit", addWatch);
  $("#copy-exec").addEventListener("click", async (event) => {
    if (!currentReport) return;
    await copyText(executiveToText(currentReport));
    const button = event.currentTarget;
    button.textContent = "Copié ✓";
    toast("Synthèse copiée dans le presse-papiers", "ok");
    setTimeout(() => (button.textContent = "Copier la synthèse"), 1600);
  });
  $("#trend-host").addEventListener("change", (event) => loadTrend(event.target.value));

  loadHistory();
  renderHistory();
  loadMeta();
})();
