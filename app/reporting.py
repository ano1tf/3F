"""Formats d'export : SARIF (CI/IDE), rapport HTML autonome, Markdown."""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any

from . import attack, config, remediation
from .models import SEVERITY_LABELS_FR, Severity

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SARIF_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}

SEVERITY_COLORS = {
    "critical": "#c0223a",
    "high": "#c25a12",
    "medium": "#9a6b00",
    "low": "#0b6b8a",
    "info": "#5b6b7f",
}


def _iso_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """SARIF 2.1.0 : exploitable par GitHub Code Scanning, VS Code, GitLab…"""
    findings = report.get("findings") or []

    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        if finding["id"] in seen:
            continue
        seen.add(finding["id"])
        rules.append(
            {
                "id": finding["id"],
                "name": finding["title"],
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding.get("description", "")},
                "help": {
                    "text": finding.get("remediation") or "Aucune remédiation fournie.",
                    "markdown": (
                        f"**{(finding.get('remediation') or '').strip()}**\n\n"
                        f"[Documentation]({finding.get('reference')})"
                        if finding.get("reference")
                        else (finding.get("remediation") or "")
                    ),
                },
                "helpUri": finding.get("reference") or "",
                "defaultConfiguration": {"level": SARIF_LEVEL.get(finding["severity"], "note")},
                "properties": {
                    "security-severity": (
                        f"{float(finding['danger']):.1f}"
                        if finding.get("danger")
                        else SARIF_SECURITY_SEVERITY.get(finding["severity"], "0.0")
                    ),
                    "danger": finding.get("danger"),
                    "danger-label": finding.get("danger_label", ""),
                    "tags": ["security", finding.get("category", "web")],
                },
            }
        )

    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding["id"],
                "level": SARIF_LEVEL.get(finding["severity"], "note"),
                "message": {
                    "text": f"[{finding.get('severity_label', finding['severity'])}] "
                    f"{finding['title']} — {finding.get('description', '')}".strip()
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": report.get("final_url") or report.get("target", "")
                            }
                        }
                    }
                ],
                "properties": {
                    "severity": finding["severity"],
                    "danger": finding.get("danger"),
                    "danger-label": finding.get("danger_label", ""),
                    "category": finding.get("category", ""),
                    "evidence": finding.get("evidence", ""),
                    "remediation": finding.get("remediation", ""),
                    "access-grants": finding.get("grants", []),
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": config.APP_NAME,
                        "version": config.APP_VERSION,
                        "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": report.get("started_at") or _iso_now(),
                    }
                ],
                "results": results,
                "properties": {
                    "score": report.get("score"),
                    "grade": report.get("grade"),
                    "scanId": report.get("scan_id"),
                    "profile": report.get("profile", "quick"),
                    "riskLevel": (report.get("executive") or {}).get("risk_level", ""),
                    "domainVerified": bool(report.get("verified")),
                    "reachable": (report.get("executive") or {}).get("reachable", []),
                    "pagesAnalyzed": len(report.get("pages") or []),
                    "pages": [page.get("url") for page in (report.get("pages") or [])],
                },
            }
        ],
    }


def to_markdown(report: dict[str, Any]) -> str:
    counts = report.get("counts") or {}
    lines = [
        f"# Rapport VulnLens — {report.get('final_url') or report.get('target')}",
        "",
        f"- **Score** : {report.get('score')}/100 (note {report.get('grade')})",
        f"- **Cible** : {report.get('final_url') or report.get('target')}",
        f"- **Date** : {report.get('started_at', '')}",
        f"- **Durée** : {report.get('duration_ms', 0)} ms",
        f"- **Propriété** : {'vérifiée ✓' if report.get('verified') else 'non vérifiée (jeton DNS ou .well-known)'}",
        f"- **Pages analysées** : {len(report.get('pages') or [])}",
        "- **Constats** : "
        + " · ".join(f"{counts.get(key, 0)} {label.lower()}" for key, label in (
            ("critical", "Critiques"), ("high", "Élevés"), ("medium", "Moyens"),
            ("low", "Faibles"), ("info", "Info"),
        )),
        "",
    ]

    executive = report.get("executive") or {}
    if executive:
        lines += [
            f"**Risque {executive.get('risk_level', '')}** — {executive.get('headline', '')}",
            "",
            executive.get("paragraph", ""),
            "",
        ]
        if executive.get("key_risks"):
            lines.append("### Ce qui expose le plus")
            lines += [
                f"- **{item['title']}** ({item['severity_label']}) — {item['impact']}"
                for item in executive["key_risks"]
            ]
            lines.append("")
        if executive.get("strengths"):
            lines.append("### Ce qui tient déjà")
            lines += [f"- {item}" for item in executive["strengths"]]
            lines.append("")
        if executive.get("reachable"):
            lines.append("### Ce que l'attaquant peut atteindre")
            lines += [f"- {item}" for item in executive["reachable"]]
            lines.append("")

    plan = remediation.build_plan(report)
    if plan["available"]:
        lines += [
            "## Plan d'action",
            remediation.to_markdown(plan),
            "",
        ]

    third_parties = report.get("third_parties") or []
    if third_parties:
        lines.append("## Dépendances tierces")
        lines += [
            f"- `{item['host']}` — {item['role']} ({', '.join(item['resources'])})"
            for item in third_parties[:15]
        ]
        lines.append("")

    diff = report.get("diff") or {}
    if diff.get("available"):
        delta = int(diff.get("score_delta") or 0)
        lines += [
            f"**Évolution** : {int(diff.get('previous_score') or 0)} → {report.get('score')} "
            f"({delta:+d} pts) — {len(diff.get('new') or [])} nouveau(x), "
            f"{len(diff.get('fixed') or [])} corrigé(s), "
            f"{(diff.get('summary') or {}).get('persistent', 0)} persistant(s).",
            "",
        ]

    pages = report.get("pages") or []
    if len(pages) > 1:
        lines.append("## Pages analysées")
        lines += [f"- `{page.get('status')}` {page.get('url')}" for page in pages]
        lines.append("")

    situation = attack.situation_table(report.get("findings") or [], limit=5)
    if situation:
        lines += ["## Rapport de situation", ""]
        for index, item in enumerate(situation, start=1):
            lines.append(f"### {index}. {item['title']} — danger {item['danger']}/10 ({item['severity_label']})")
            lines.append("**Comment y arriver :**")
            lines += [f"{step_index}. {step}" for step_index, step in enumerate(item["access"], start=1)]
            lines.append("")
            lines.append(f"**Ce que ça révèle :** {item['reveals']}")
            if item.get("grants"):
                lines.append(f"**Donne accès à :** {' · '.join(item['grants'])}")
            lines.append(f"**Correction :** {item['remediation']}")
            lines.append("")

    findings = report.get("findings") or []
    if not findings:
        lines.append("Aucun problème détecté par les contrôles passifs. 🎉")
    for index, finding in enumerate(findings, start=1):
        lines += [
            f"## {index}. [{finding.get('severity_label', finding['severity'])}] {finding['title']}",
            f"_{finding.get('category', '')}_",
            "",
            finding.get("description", ""),
            "",
        ]
        if finding.get("access"):
            lines.append(
                f"**Comment y arriver** (danger {finding.get('danger', '?')}/10, "
                f"{finding.get('danger_label', '')}) :"
            )
            lines += [f"{idx}. {step}" for idx, step in enumerate(finding["access"], start=1)]
            lines.append("")
        if finding.get("reveals"):
            lines += [f"**Ce que ça révèle :** {finding['reveals']}", ""]
        if finding.get("grants"):
            lines += [f"**Donne accès à :** {' · '.join(finding['grants'])}", ""]
        if finding.get("evidence"):
            lines += ["```", finding["evidence"], "```", ""]
        if finding.get("remediation"):
            lines += [f"**Remédiation :** {finding['remediation']}", ""]
        if finding.get("reference"):
            lines += [f"Référence : {finding['reference']}", ""]

    lines += ["---", "Généré par VulnLens — tests de sécurité autorisés uniquement."]
    return "\n".join(lines)


def _radar_svg(radar: list[dict[str, Any]], size: int = 260) -> str:
    """Radar maison (aucune dépendance) : jusqu'à 6 axes, valeurs 0-100."""
    import math

    if not radar:
        return ""
    axes = radar[:6]
    count = len(axes)
    center = size / 2
    radius = center - 34
    rings = "".join(
        f'<circle cx="{center}" cy="{center}" r="{radius * ratio:.1f}" fill="none" '
        f'stroke="#e2e8f0" stroke-width="1"/>'
        for ratio in (0.25, 0.5, 0.75, 1.0)
    )
    points, labels, spokes = [], [], []
    for index, axis in enumerate(axes):
        angle = (2 * math.pi * index / count) - math.pi / 2
        ratio = max(0.04, min(1.0, (axis.get("value") or 0) / 100))
        points.append(f"{center + radius * ratio * math.cos(angle):.1f},{center + radius * ratio * math.sin(angle):.1f}")
        ex, ey = center + radius * math.cos(angle), center + radius * math.sin(angle)
        spokes.append(f'<line x1="{center}" y1="{center}" x2="{ex:.1f}" y2="{ey:.1f}" stroke="#e2e8f0"/>')
        lx, ly = center + (radius + 18) * math.cos(angle), center + (radius + 18) * math.sin(angle)
        anchor = "middle" if abs(math.cos(angle)) < 0.3 else ("start" if math.cos(angle) > 0 else "end")
        labels.append(
            f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="{anchor}" dominant-baseline="middle" '
            f'font-size="9.5" fill="#64748b">{_e(str(axis.get("label", ""))[:18])}</text>'
        )
    return (
        f'<svg viewBox="0 0 {size} {size}" width="100%" height="auto" role="img" '
        f'aria-label="Exposition relative par catégorie">'
        f"{rings}{''.join(spokes)}"
        f'<polygon points="{" ".join(points)}" fill="rgba(194,34,58,.16)" stroke="#c0223a" stroke-width="1.8"/>'
        f"{''.join(labels)}</svg>"
    )


def _danger_meter(value: int, label: str = "") -> str:
    value = max(0, min(10, int(value or 0)))
    blocks = "".join(
        f'<span class="{"on" if index < value else "off"}"></span>' for index in range(10)
    )
    return (
        f'<div class="danger" title="{_e(label)}"><div class="danger-blocks">{blocks}</div>'
        f'<b>{value}/10</b><em>{_e(label)}</em></div>'
    )


def _diff_items(items: Any) -> str:
    entries = items or []
    if not entries:
        return '<li class="empty">Aucun</li>'
    return "".join(
        f'<li><span class="sev">'
        f'{_e(item.get("severity_label") or item.get("severity", ""))}</span>'
        f'{_e(item.get("title", ""))}</li>'
        for item in entries[:12]
    )


def _e(value: Any) -> str:
    return html.escape(str(value or ""))


def to_html(report: dict[str, Any]) -> str:
    """Rapport HTML autonome (aucune ressource externe) : livrable client / PDF."""
    counts = report.get("counts") or {}
    findings = report.get("findings") or []
    fingerprint = report.get("fingerprint") or {}
    checks = report.get("checks") or []
    pages = report.get("pages") or []
    executive = report.get("executive") or {}
    verified = bool(report.get("verified"))
    diff = report.get("diff") or {}
    score = int(report.get("score") or 0)
    grade = _e(report.get("grade"))
    target = _e(report.get("final_url") or report.get("target"))

    gauge_color = "#1b8a5a" if score >= 80 else "#b8860b" if score >= 60 else "#c25a12" if score >= 35 else "#c0223a"

    summary_cells = "".join(
        f'<div class="cell"><b style="color:{SEVERITY_COLORS[key]}">{int(counts.get(key, 0))}</b>'
        f"<span>{_e(SEVERITY_LABELS_FR[Severity(key)])}</span></div>"
        for key in ("critical", "high", "medium", "low", "info")
    )

    priority_ids = report.get("priorities") or []
    priorities = [f for f in findings if f["id"] in priority_ids][:3]
    priority_html = "".join(
        f'<li><strong>{_e(item["title"])}</strong> — {_e(item.get("remediation", ""))}</li>'
        for item in priorities
    )

    findings_html = []
    for finding in findings:
        severity = finding.get("severity", "info")
        color = SEVERITY_COLORS.get(severity, "#5b6b7f")
        reference = finding.get("reference") or ""
        findings_html.append(
            f"""
        <article class="finding" style="border-left-color:{color}">
          <header>
            <span class="badge" style="color:{color};border-color:{color}">
              {_e(finding.get("severity_label", severity))}
            </span>
            <h3>{_e(finding["title"])}</h3>
            <span class="cat">{_e(finding.get("category", ""))}</span>
            {f'<span class="conf">{_e("à vérifier" if finding.get("confidence") == "probable" else "à confirmer")}</span>' if finding.get("confidence") not in (None, "certain") else ""}
          </header>
          <p class="desc">{_e(finding.get("description", ""))}</p>
          {f'''<div class="find-danger">{_danger_meter(finding.get("danger", 0), finding.get("danger_label", ""))}</div>
          <div class="block"><h4>Comment y arriver</h4><ol class="sit-steps">{"".join(f"<li>{_e(step)}</li>" for step in finding.get("access") or [])}</ol></div>
          <div class="block"><h4>Ce que ça révèle</h4><p class="sit-reveals">{_e(finding.get("reveals", ""))}</p>{f'<p class="sit-grants"><strong>Donne accès à :</strong> {_e(" · ".join(finding["grants"]))}</p>' if finding.get("grants") else ""}</div>''' if finding.get("danger") else ""}
          <div class="block"><h4>Preuve</h4><pre>{_e(finding.get("evidence") or "—")}</pre></div>
          <div class="block fix"><h4>Remédiation</h4><p>{_e(finding.get("remediation") or "—")}</p></div>
          {f'<a class="ref" href="{_e(reference)}">Documentation ↗</a>' if reference else ''}
        </article>"""
        )

    fingerprint_html = "".join(
        f"<tr><th>{_e(key.replace('_', ' '))}</th><td>{_e(value)}</td></tr>"
        for key, value in fingerprint.items()
        if value
    )
    verify_html = (
        '<span class="verified">✓ Domaine vérifié</span>'
        if verified
        else '<span class="unverified">Domaine non vérifié</span>'
    )

    diff_html = ""
    if diff.get("available"):
        delta = int(diff.get("score_delta") or 0)
        delta_label = f"+{delta}" if delta > 0 else str(delta)
        diff_html = f'''
  <h2>Évolution depuis la dernière analyse</h2>
  <div class="panel">
    <p class="delta">Score {int(diff.get("previous_score") or 0)} → {score}
      (<strong>{delta_label} pts</strong>) · analyse précédente du {_e(diff.get("previous_at", ""))}</p>
    <div class="diff-cols">
      <div><h4>Nouveaux constats ({len(diff.get("new") or [])})</h4>
        <ul class="diff">{_diff_items(diff.get("new"))}</ul></div>
      <div><h4>Constats corrigés ({len(diff.get("fixed") or [])})</h4>
        <ul class="diff fixed">{_diff_items(diff.get("fixed"))}</ul></div>
    </div>
    <p class="muted">{(diff.get("summary") or {}).get("persistent", 0)} constat(s) toujours présent(s).</p>
  </div>'''

    pages_html = ""
    if len(pages) > 1:
        rows = "".join(
            f'<li><span class="code">{int(page.get("status") or 0)}</span>'
            f'<span>{_e(page.get("url"))}</span>'
            f'<em>{_e(page.get("title", ""))}</em></li>'
            for page in pages
        )
        pages_html = f'''
  <h2>Pages analysées ({len(pages)})</h2>
  <div class="panel"><ul class="pages">{rows}</ul></div>'''

    plan = remediation.build_plan(report)

    plan_html = ""
    if plan["available"]:
        columns = []
        for key in ("quick", "sprint", "project"):
            bucket = plan["buckets"][key]
            items = "".join(
                f'<li><span class="sev" data-sev="{_e(item["severity"])}">'
                f'{_e(item["severity_label"])}</span>'
                f'<strong>{_e(item["title"])}</strong>'
                f'<em>{_e(item["action"])}</em></li>'
                for item in bucket["items"][:8]
            ) or '<li class="empty">Rien à planifier</li>'
            columns.append(
                f'<div class="plan-col"><h4>{_e(bucket["label"])} — '
                f'{len(bucket["items"])}</h4><p class="plan-detail">{_e(bucket["detail"])}</p>'
                f'<ul class="plan">{items}</ul></div>'
            )
        plan_html = (
            f'<h2>Plan d\'action</h2><div class="panel">'
            f'<p class="delta">Score {plan["current_score"]}/100 aujourd\'hui, '
            f'<strong>{plan["projected_score"]}/100</strong> une fois tout corrigé '
            f'(+{plan["potential_gain"]} pts).</p>'
            f'<div class="plan-cols">{"".join(columns)}</div></div>'
        )

    executive_html = ""
    if executive:
        risks = "".join(
            f'<li><span class="sev" data-sev="{_e(item["severity"])}">'
            f'{_e(item["severity_label"])}</span>'
            f'<strong>{_e(item["title"])}</strong><em>{_e(item["impact"])}</em></li>'
            for item in executive.get("key_risks", [])
        )
        strengths = "".join(f"<li>{_e(item)}</li>" for item in executive.get("strengths", []))
        radar_svg = _radar_svg(executive.get("radar") or [])
        reachable = executive.get("reachable") or []
        reach_html = (
            "<h4>Ce que l'attaquant peut atteindre</h4><ul class=\"reach-list\">"
            + "".join(f"<li>{_e(asset)}</li>" for asset in reachable)
            + "</ul>"
            if reachable
            else ""
        )
        executive_html = f'''
  <h2>Synthèse</h2>
  <div class="panel exec">
    <div class="exec-main">
      <span class="risk risk-{_e(executive.get("risk_level"))}">Risque {_e(executive.get("risk_level"))}</span>
      <p class="exec-headline">{_e(executive.get("headline"))}</p>
      <p class="exec-paragraph">{_e(executive.get("paragraph"))}</p>
      <h4>Ce qui expose le plus</h4>
      <ul class="exec-risks">{risks or "<li>Aucun risque majeur détecté.</li>"}</ul>
      {reach_html}
      <h4>Ce qui tient déjà</h4>
      <ul class="exec-strengths">{strengths or "<li>Pas encore d'élément solide à mettre en avant.</li>"}</ul>
    </div>
    <div class="exec-radar">{radar_svg}<p class="muted">Exposition relative par catégorie</p></div>
  </div>'''

    situation_items = attack.situation_table(findings, limit=5)
    situation_html = ""
    if situation_items:
        cards = []
        for item in situation_items:
            steps = "".join(f"<li>{_e(step)}</li>" for step in item["access"])
            cards.append(
                f'''<article class="situation-card">
          <header><h3>{_e(item["title"])}</h3>{_danger_meter(item["danger"], item["danger_label"])}</header>
          <p class="sit-cat">{_e(item["category"])} · {_e(item["severity_label"])} · compétence {_e(item["skill"])}</p>
          <h4>Comment y arriver</h4><ol class="sit-steps">{steps}</ol>
          <h4>Ce que ça révèle</h4><p class="sit-reveals">{_e(item["reveals"])}</p>
          {f'<p class="sit-grants"><strong>Donne accès à :</strong> {_e(" · ".join(item["grants"]))}</p>' if item.get("grants") else ""}
          <p class="sit-fix"><strong>Correction :</strong> {_e(item["remediation"])}</p>
        </article>'''
            )
        situation_html = (
            "<h2>Rapport de situation</h2>"
            '<p class="sit-intro">Les cinq failles les plus dangereuses : comment y arriver, '
            "ce qu'elles révèlent, et une cotation de 1 à 10.</p>"
            f'<div class="situation-grid">{"".join(cards)}</div>'
        )

    third_html = ""
    if report.get("third_parties"):
        rows = "".join(
            f'<li><span class="host">{_e(item["host"])}</span>'
            f'<span class="role">{_e(item["role"])}</span>'
            f'<span class="res">{_e(", ".join(item["resources"]))}</span></li>'
            for item in (report.get("third_parties") or [])[:15]
        )
        third_html = (
            f'<h2>Dépendances tierces ({len(report["third_parties"])})</h2>'
            f'<div class="panel"><ul class="third">{rows}</ul></div>'
        )

    checks_html = "".join(
        f'<li><span class="dot {_e(check.get("status", "ok"))}"></span>{_e(check.get("label", ""))}'
        f'<em>{len(check.get("findings") or [])} constat(s)</em></li>'
        for check in checks
    )

    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport VulnLens — {target}</title>
<style>
  :root {{ --ink:#12181f; --muted:#5b6b7f; --line:#dfe5ec; --bg:#f6f8fb; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
         font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:40px 24px 80px; }}
  header.top {{ display:flex; justify-content:space-between; align-items:center; gap:24px;
                flex-wrap:wrap; border-bottom:2px solid var(--ink); padding-bottom:18px; }}
  .brand {{ font-weight:800; letter-spacing:-.02em; font-size:20px; }}
  .brand small {{ display:block; font-weight:500; color:var(--muted); font-size:12px; letter-spacing:.08em; text-transform:uppercase; }}
  .score {{ display:flex; align-items:center; gap:14px; }}
  .ring {{ width:88px; height:88px; border-radius:50%;
           background:conic-gradient({gauge_color} {score}%, #e6ebf2 0);
           display:grid; place-items:center; }}
  .ring span {{ width:68px; height:68px; border-radius:50%; background:#fff; display:grid;
                place-items:center; font-size:22px; font-weight:800; }}
  .grade {{ font-size:13px; color:var(--muted); }}
  h1 {{ font-size:26px; margin:26px 0 6px; letter-spacing:-.02em; word-break:break-all; }}
  .meta {{ color:var(--muted); font-size:13px; margin:0 0 24px; }}
  .cells {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:0 0 28px; }}
  .cell {{ background:#fff; border:1px solid var(--line); border-radius:12px; padding:12px; text-align:center; }}
  .cell b {{ display:block; font-size:22px; }}
  .cell span {{ font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }}
  h2 {{ font-size:16px; text-transform:uppercase; letter-spacing:.08em; margin:34px 0 12px; color:var(--muted); }}
  .panel {{ background:#fff; border:1px solid var(--line); border-radius:14px; padding:18px 20px; }}
  .priority {{ margin:0; padding-left:18px; }}
  .priority li {{ margin:6px 0; }}
  .finding {{ background:#fff; border:1px solid var(--line); border-left:4px solid #999;
              border-radius:12px; padding:16px 18px; margin-bottom:12px;
              break-inside:avoid; page-break-inside:avoid; }}
  .finding header {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .finding h3 {{ font-size:15px; margin:0; flex:1; min-width:200px; }}
  .badge {{ font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.08em;
            border:1px solid; border-radius:999px; padding:2px 8px; }}
  .cat {{ font-size:11.5px; color:var(--muted); }}
  .conf {{ font-size:10px; text-transform:uppercase; letter-spacing:.06em; color:#8a5a12;
           background:#fdf3d7; border:1px solid #f0d79a; border-radius:999px; padding:1px 8px; }}
  .desc {{ margin:10px 0 0; font-size:14px; }}
  h4 {{ font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin:14px 0 6px; }}
  pre {{ background:#f3f6fa; border:1px solid var(--line); border-radius:8px; padding:10px 12px;
         font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; white-space:pre-wrap;
         word-break:break-word; margin:0; }}
  .fix p {{ margin:0; font-size:13.5px; color:#14532d; }}
  .ref {{ display:inline-block; margin-top:12px; font-size:12.5px; color:#0b5cad; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border:1px solid var(--line);
           border-radius:12px; overflow:hidden; font-size:13px; }}
  th, td {{ text-align:left; padding:8px 12px; border-bottom:1px solid var(--line); }}
  th {{ color:var(--muted); font-weight:600; width:210px; }}
  tr:last-child th, tr:last-child td {{ border-bottom:0; }}
  ul.checks {{ list-style:none; margin:0; padding:0; display:grid; gap:8px; }}
  ul.checks li {{ display:flex; align-items:center; gap:8px; font-size:13px; }}
  ul.checks em {{ margin-left:auto; color:var(--muted); font-style:normal; font-size:11.5px; }}
  .verified {{ display:inline-block; margin-left:8px; font-size:11px; font-weight:700; color:#1b8a5a;
               background:#e8f6ee; border:1px solid #9fd9b8; border-radius:999px; padding:1px 9px; }}
  .unverified {{ display:inline-block; margin-left:8px; font-size:11px; color:var(--muted);
                 border:1px dashed #c3cddb; border-radius:999px; padding:1px 9px; }}
  .delta {{ margin:0 0 12px; font-size:13.5px; }}
  .diff-cols {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
  ul.diff {{ margin:0; padding-left:18px; font-size:13px; }}
  ul.diff li {{ margin:4px 0; }}
  ul.diff li .sev {{ font-size:10.5px; text-transform:uppercase; letter-spacing:.06em; color:#c0223a; margin-right:6px; }}
  ul.diff.fixed li .sev {{ color:#1b8a5a; }}
  ul.diff li.empty {{ list-style:none; margin-left:-18px; color:var(--muted); font-style:italic; }}
  ul.pages {{ list-style:none; margin:0; padding:0; font-size:12.5px; }}
  ul.pages li {{ display:flex; gap:10px; align-items:baseline; padding:5px 0; border-bottom:1px dashed var(--line);
                 word-break:break-all; }}
  ul.pages li:last-child {{ border-bottom:0; }}
  ul.pages .code {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11px; color:#1b8a5a; }}
  ul.pages em {{ margin-left:auto; color:var(--muted); font-style:normal; font-size:11.5px; }}
  .muted {{ color:var(--muted); font-size:12.5px; }}
  .sit-intro {{ margin:-4px 0 14px; color:var(--muted); font-size:13px; }}
  .situation-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }}
  .situation-card {{ background:#fff; border:1px solid var(--line); border-radius:12px;
                     padding:14px 16px; break-inside:avoid; }}
  .situation-card header {{ display:flex; justify-content:space-between; gap:12px; align-items:flex-start; }}
  .situation-card h3 {{ margin:0; font-size:14px; flex:1; }}
  .situation-card h4 {{ margin:12px 0 4px; }}
  .sit-cat {{ margin:6px 0 0; color:var(--muted); font-size:11.5px; }}
  .sit-steps {{ margin:0; padding-left:18px; font-size:12.5px; color:#334155; }}
  .sit-steps li {{ margin:4px 0; }}
  .sit-reveals {{ margin:0; font-size:12.5px; color:#334155; }}
  .sit-grants {{ margin:6px 0 0; font-size:12.5px; color:#0b4f6c; }}
  .reach-list {{ list-style:none; padding:0; margin:4px 0 0; display:flex; flex-wrap:wrap; gap:6px; }}
  .reach-list li {{ background:#e6f4fa; border:1px solid #b6dced; color:#0b4f6c;
                    border-radius:999px; padding:2px 9px; font-size:11.5px; font-weight:600; }}
  .sit-fix {{ margin:8px 0 0; font-size:12px; color:#14532d; }}
  .find-danger {{ margin:12px 0 0; }}
  .danger {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; font-size:11px; color:var(--muted); }}
  .danger-blocks {{ display:flex; gap:2px; }}
  .danger-blocks span {{ width:8px; height:14px; border-radius:2px; background:#e6ebf2; }}
  .danger-blocks span.on {{ background:#c0223a; }}
  .danger-blocks span.on:nth-child(n+9) {{ background:#8f0f22; }}
  .danger b {{ font-size:12px; color:#12181f; }}
  .danger em {{ font-style:normal; color:var(--muted); }}
  @media (max-width: 760px) {{ .situation-grid {{ grid-template-columns:1fr; }} }}
  .exec {{ display:grid; grid-template-columns:1.6fr 1fr; gap:22px; align-items:start; }}
  .exec-headline {{ font-size:15px; font-weight:700; margin:10px 0 6px; }}
  .exec-paragraph {{ margin:0 0 14px; color:#334155; font-size:13.5px; }}
  .exec-risks {{ list-style:none; margin:0 0 14px; padding:0; }}
  .exec-risks li {{ padding:7px 0; border-bottom:1px dashed var(--line); font-size:12.5px; }}
  .exec-risks li:last-child {{ border-bottom:0; }}
  .exec-risks strong {{ display:block; }}
  .exec-risks em {{ display:block; color:var(--muted); font-style:normal; font-size:11.5px; }}
  .exec-risks .sev {{ font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; margin-right:6px; }}
  .exec-risks .sev[data-sev="critical"] {{ color:#c0223a; }}
  .exec-risks .sev[data-sev="high"] {{ color:#c25a12; }}
  .exec-risks .sev[data-sev="medium"] {{ color:#b8860b; }}
  .exec-strengths {{ margin:0; padding-left:18px; font-size:12.5px; color:#14532d; }}
  .exec-strengths li {{ margin:4px 0; }}
  .exec-radar {{ text-align:center; }}
  .risk {{ display:inline-block; font-size:11px; font-weight:700; text-transform:uppercase;
           letter-spacing:.08em; border-radius:999px; padding:3px 10px; }}
  .risk-critique {{ color:#7f1d1d; background:#fee2e2; border:1px solid #fca5a5; }}
  .risk-élevé {{ color:#7c2d12; background:#ffedd5; border:1px solid #fdba74; }}
  .risk-modéré {{ color:#713f12; background:#fef9c3; border:1px solid #fde047; }}
  .risk-faible {{ color:#14532d; background:#dcfce7; border:1px solid #86efac; }}
  @media (max-width: 820px) {{ .exec {{ grid-template-columns:1fr; }} }}
  .plan-cols {{ display:grid; grid-template-columns:repeat(3,1fr); gap:16px; }}
  .plan-col h4 {{ margin-top:0; }}
  .plan-detail {{ margin:0 0 10px; font-size:12px; color:var(--muted); }}
  ul.plan {{ list-style:none; margin:0; padding:0; font-size:12.5px; }}
  ul.plan li {{ padding:7px 0; border-bottom:1px dashed var(--line); }}
  ul.plan li:last-child {{ border-bottom:0; }}
  ul.plan li.empty {{ color:var(--muted); font-style:italic; }}
  ul.plan .sev {{ display:inline-block; font-size:10px; font-weight:700; text-transform:uppercase;
                  letter-spacing:.06em; margin-right:6px; }}
  ul.plan .sev[data-sev="critical"] {{ color:#c0223a; }}
  ul.plan .sev[data-sev="high"] {{ color:#c25a12; }}
  ul.plan .sev[data-sev="medium"] {{ color:#b8860b; }}
  ul.plan .sev[data-sev="low"] {{ color:#4a6fa5; }}
  ul.plan .sev[data-sev="info"] {{ color:#5b6b7f; }}
  ul.plan strong {{ display:block; font-size:12.5px; }}
  ul.plan em {{ display:block; color:var(--muted); font-style:normal; font-size:11.5px; margin-top:2px; }}
  ul.third {{ list-style:none; margin:0; padding:0; font-size:12.5px; }}
  ul.third li {{ display:flex; gap:10px; align-items:baseline; padding:5px 0;
                 border-bottom:1px dashed var(--line); flex-wrap:wrap; }}
  ul.third li:last-child {{ border-bottom:0; }}
  ul.third .host {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; }}
  ul.third .role {{ font-size:11px; color:#0b5cad; }}
  ul.third .res {{ margin-left:auto; color:var(--muted); font-size:11px; }}
  @media (max-width: 760px) {{ .plan-cols, .diff-cols {{ grid-template-columns:1fr; }} }}
  .dot {{ width:9px; height:9px; border-radius:50%; background:#1b8a5a; }}
  .dot.error {{ background:#c25a12; }}
  .dot.skipped {{ background:#98a6b8; }}
  footer {{ margin-top:40px; border-top:1px solid var(--line); padding-top:14px;
            color:var(--muted); font-size:12px; }}
  @media print {{ body {{ background:#fff; }} .wrap {{ padding:0; }} .panel,.finding,table {{ box-shadow:none; }} }}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">{_e(config.APP_NAME)}<small>Rapport d'analyse de sécurité</small></div>
    <div class="score">
      <div class="ring"><span>{score}</span></div>
      <div>
        <div class="grade">Note <strong>{grade}</strong> / 100<br>profil {_e(report.get("profile", "quick"))}</div>
      </div>
    </div>
  </header>

  <h1>{target}</h1>
  <p class="meta">
    Analyse du {_e(report.get("started_at", ""))} · durée {int(report.get("duration_ms") or 0)} ms ·
    {len(findings)} constat(s) · identifiant {_e(report.get("scan_id", ""))}
    {f"· {len(pages)} page(s) analysée(s)" if pages else ""}
    · {verify_html}
  </p>

  <div class="cells">{summary_cells}</div>

  {f'<h2>À corriger en priorité</h2><div class="panel"><ol class="priority">{priority_html}</ol></div>' if priority_html else ""}

  {executive_html}
{situation_html}
{plan_html}
{diff_html}
{pages_html}

  <h2>Constats ({len(findings)})</h2>
  {''.join(findings_html) if findings_html else '<div class="panel">Aucun problème détecté par les contrôles passifs.</div>'}

  <h2>Empreinte technique</h2>
  <table>{fingerprint_html or '<tr><td>Aucune donnée collectée.</td></tr>'}</table>

  {third_html}

  <h2>Contrôles exécutés</h2>
  <div class="panel"><ul class="checks">{checks_html}</ul></div>

  <footer>
    {_e(config.APP_NAME)} {_e(config.APP_VERSION)} — scanner passif, aucune exploitation.
    N'analysez que des systèmes pour lesquels vous disposez d'une autorisation écrite.
    Généré le {datetime.now().strftime("%d/%m/%Y à %H:%M")}.
  </footer>
</div>
</body>
</html>"""


def dumps_sarif(report: dict[str, Any]) -> str:
    return json.dumps(to_sarif(report), ensure_ascii=False, indent=2)
