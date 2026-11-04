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
    button.querySelector(".btn-label").textContent = "Analyse…";

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target, authorized: true }),
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
          } else if (event.type === "error") {
            showError(event.message || "Erreur inconnue.");
          }
        }
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

  function renderReport(report) {
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

    renderFilters(report.findings || []);
    renderFindings();
    renderFingerprint(report.fingerprint || {});
    renderChecks(report.checks || []);

    results.scrollIntoView({ behavior: "smooth", block: "start" });
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

  loadMeta();
})();
