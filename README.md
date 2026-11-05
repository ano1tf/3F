# VulnLens

**Audit de sécurité web en un clic — non intrusif, en français, avec preuves.**

VulnLens analyse une URL publique et rend un rapport hiérarchisé : ce qui est cassé, **pourquoi c'est
dangereux**, **comment le prouver** (requête exacte, en-tête, extrait) et **comment le corriger**.
Aucune exploitation, aucune injection, aucun contournement d'authentification : uniquement ce qu'un
visiteur peut observer.

```
┌ VulnLens v3.0 ─────────────────────────────────────────────────────────────┐
│  Score 33/100 — E      □□□□□□□□□□ 3 pages × 38 contrôles     ✓ vérifié     │
├────────────────────────────────────────────────────────────────────────────┤
│  Nouveaux depuis la dernière analyse : 2   Corrigés : 5   Persistants : 12 │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Ce que fait la v3 (le saut d'échelle)

| Capacité | Détail |
|---|---|
| **Analyse multi-pages** | Un site n'est pas jugé sur sa page d'accueil : jusqu'à 12 pages internes explorées, constats fusionnés avec la preuve « présent sur N des M pages ». |
| **Preuve de propriété** | Jeton à publier en DNS (`_vulnlens.<domaine>`) ou en fichier (`/.well-known/vulnlens.txt`). Le rapport est marqué **vérifié** : plus d'ambiguïté juridique. |
| **Subdomain takeover** | Sous-domaines résolus, CNAME comparés à 20 signatures de services (S3, GitHub Pages, Heroku, Azure, Netlify, Shopify…) + détection de page d'erreur orpheline. |
| **Diff entre analyses** | `nouveaux / corrigés / dégradés / persistants` + variation de score, dans l'UI, l'API et les exports. |
| **Alertes webhook** | Notification JSON envoyée à Slack/Teams/n8n quand le score passe sous un seuil, qu'un constat critique apparaît ou que le score chute de N points. |
| **Protection d'instance** | Jeton d'API optionnel (`VULNLENS_TOKEN`, en-tête `Authorization: Bearer` ou `X-API-Key`). |

Chaque constat porte : sévérité, catégorie, **description**, **preuve reproductible**, **remédiation**,
**référence** (OWASP, MDN, RFC).

---

## Démarrage

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt   # dev
.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
# → http://localhost:8000
```

Docker : `docker build -t vulnlens . && docker run -p 8000:8000 vulnlens`

### CLI

```bash
# rapport JSON vers stdout
python -m app.cli scan https://exemple.fr

# rapport HTML autonome, échec si le score est sous 70
python -m app.cli scan https://exemple.fr --profile deep --fail-under 70 \
                      --format html -o rapport.html

# format SARIF pour GitHub Code Scanning
python -m app.cli scan https://exemple.fr --format sarif -o vulnlens.sarif

# vérifier la propriété d'un domaine avant de scanner
python -m app.cli verify exemple.fr
```

Codes de sortie : `0` (ok), `1` (sous le seuil `--fail-under`), `2` (erreur d'analyse).

---

## Profils d'analyse

| Profil | Pages | Contrôles |
|---|---|---|
| `quick` | 1 | Transport, en-têtes, cookies, exposition de fichiers, contenu, DNS, TLS |
| `standard` (défaut) | 6 | + agrégation multi-pages, en-têtes et contenu page par page |
| `deep` | 12 | + transfert de zone AXFR, sous-domaines, **takeover**, redirections ouvertes, TLS détaillé |

Toujours **passif** : les requêtes sont des `GET`/`HEAD` sans charge utile, sans tentative de
connexion, sans force brute, sans exploitation. Une case « je suis autorisé à tester cette cible » est
obligatoire, et les cibles privées sont bloquées par défaut.

---

## Vérification de propriété

Sans preuve, le rapport est produit normalement mais marqué « non vérifié ». Pour obtenir le badge :

**Option A — DNS (recommandé)**

```
_vulnlens.exemple.fr.   TXT   "vulnlens-verification=<jeton>"
```

**Option B — fichier**

```
https://exemple.fr/.well-known/vulnlens.txt   →   vulnlens-verification=<jeton>
```

Le jeton est généré par `GET /api/verify/{hôte}`, la vérification se lance avec
`POST /api/verify/{hôte}/check`. Le résultat est persisté en base et reporté dans chaque scan suivant
(`verified: true`, badge dans l'UI, le HTML, le Markdown et les propriétés SARIF).

---

## Exports

- **HTML autonome** : rapport partageable (aucune dépendance, impression propre, priorisation en tête).
- **SARIF 2.1.0** : intégration GitHub Code Scanning, chaque constat rattaché à sa règle et à sa référence.
- **Markdown** : PR, wiki, ticket.
- **JSON** : tout le rapport, y compris `pages`, `verified`, `score_breakdown`, `fingerprint`.

Contenu du HTML : bandeau de score, **priorités d'action**, **évolution vs analyse précédente**,
constats détaillés (preuve + remédiation + référence), empreinte technique, **pages analysées**,
contrôles exécutés avec leur durée.

---

## API

| Méthode | Route | Rôle |
|---|---|---|
| `GET` | `/api/health` | Vivacité (toujours ouverte) |
| `GET` | `/api/meta` | Version, profils, contrôles disponibles |
| `POST` | `/api/scan` | Scan en NDJSON : événements `progress`, `check`, `result`, `saved`, `error` |
| `GET` | `/api/scans` | Historique (filtres `host`, `limit`) |
| `GET` | `/api/scans/{id}` | Rapport complet |
| `GET` | `/api/scans/{id}/diff` | Écart avec l'analyse précédente du même hôte |
| `GET` | `/api/scans/{id}/report.html` | Export HTML |
| `GET` | `/api/scans/{id}/sarif` | Export SARIF |
| `GET` | `/api/scans/{id}/markdown` | Export Markdown |
| `DELETE` | `/api/scans/{id}` | Suppression |
| `GET` | `/api/stats` | Agrégats du tableau de bord |
| `GET` | `/api/verify/{hôte}` | Jeton + instructions (sans requête réseau) |
| `POST` | `/api/verify/{hôte}/check` | Vérifie DNS puis fichier, persiste le résultat |

Si `VULNLENS_TOKEN` est défini, toutes les routes `/api/*` (sauf `/api/health`) exigent
`Authorization: Bearer <jeton>` ou `X-API-Key: <jeton>`.

---

## Configuration

| Variable | Défaut | Effet |
|---|---|---|
| `VULNLENS_ALLOW_PRIVATE` | `0` | Autorise les cibles privées (labo, `127.0.0.1`) |
| `VULNLENS_TOKEN` | vide | Protège l'API par jeton |
| `VULNLENS_WEBHOOK` | vide | URL recevant les alertes (JSON `POST`) |
| `VULNLENS_ALERT_THRESHOLD` | vide | Alerte si score `< seuil` |
| `VULNLENS_ALERT_MIN_DROP` | `10` | Alerte si le score chute de N points |
| `VULNLENS_ALERT_ON_CRITICAL` | `1` | Alerte à l'apparition d'un constat critique |
| `VULNLENS_CONTACT` | `security@example.org` | Contact dans le User-Agent |
| `VULNLENS_DB` | `data/vulnlens.db` | Base SQLite |

Charge utile d'alerte : `scan_id`, `host`, `score`, `previous_score`, `delta`, `reason`,
`counts`, `priorities` (3 premiers constats avec titre, sévérité, remédiation), `report_url`.

---

## Architecture

```
app/
├─ main.py            FastAPI, NDJSON, historique, exports, jeton, diff, vérification
├─ cli.py             scan / verify, formats, --fail-under
├─ config.py          réglages + version
├─ models.py          Finding, ScanReport (pages, verified, score_breakdown, priorities)
├─ safety.py          normalisation, refus des cibles privées
├─ verify.py          preuve de propriété (DNS TXT / .well-known)
├─ diffing.py         comparaison de deux rapports
├─ alerts.py          webhook best-effort
├─ db.py              SQLite, migrations, stats, analyse précédente
├─ reporting.py       HTML, SARIF, Markdown
├─ scanner/
│  ├─ engine.py       orchestration par profil, crawl, agrégation
│  ├─ crawl.py        exploration bornée (profondeur 2, exclusions)
│  ├─ aggregate.py    fusion des constats multi-pages
│  ├─ fetcher.py      HTTP poli (timeouts, UA, taille bornée), TLS
│  ├─ checks_http.py  en-têtes, cookies, méthodes, HSTS
│  ├─ checks_tls.py   certificat, protocoles, chaîne
│  ├─ checks_exposure.py  38 chemins sensibles (.git, .env, backups…)
│  ├─ checks_content.py   formulaires, CSP, SRI, iframes, commentaires
│  ├─ checks_dns.py   SPF, DMARC, DKIM, DNSSEC, CAA
│  ├─ checks_deep.py  AXFR, sous-domaines, takeover, redirections
│  └─ scoring.py      pénalités par sévérité, note A→F
└─ static/            interface (aucune dépendance, CSP stricte)
```

Une même catégorie de problème donne **un seul constat** : les occurrences sont fusionnées avec la
liste des pages concernées, pour éviter les rapports de 300 lignes répétitives.

---

## Tests

```bash
.venv/bin/python -m pytest        # 135 tests
.venv/bin/ruff check .
```

Couverture : normalisation et refus de cibles, scoring, en-têtes, contenu, DNS/deep, **crawl**,
**agrégation**, **diff**, **alertes**, **vérification**, **takeover**, persistance, API (historique,
exports, jeton, diff, verify), CLI, fixture serveur volontairement vulnérable (3 pages).

---

## Feuille de route

- [ ] Suivi planifié (cron) avec rapport hebdomadaire par e-mail
- [ ] Règles personnalisées (`*.yaml`) pour les contrôles maison
- [ ] Comparaison multi-sites (portefeuille)
- [ ] Export PDF côté serveur (sans dépendance navigateur)

## Licence

MIT — voir `LICENSE`. Utilisez VulnLens uniquement sur des cibles que vous êtes autorisé à tester.
