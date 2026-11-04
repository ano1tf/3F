# 🔍 VulnLens

**Plateforme d'audit de sécurité web — analyse en un clic, historique, rapports livrables.**

VulnLens scanne la surface d'attaque d'un site (transport, TLS, en-têtes, CSP, cookies, CORS,
fichiers oubliés, contenu, DNS), conserve un historique, compare les analyses entre elles et
produit des rapports exploitables : JSON, Markdown, **HTML autonome** et **SARIF** pour la CI.

> ⚖️ **Usage autorisé uniquement.** N'analysez que des systèmes dont vous êtes propriétaire ou pour
> lesquels vous disposez d'une autorisation écrite. L'outil refuse les cibles internes, ne tente
> aucune exploitation et n'envoie aucune charge destructive.

---

## Sommaire

- [Nouveautés v2](#nouveautés-v2)
- [Ce que l'outil détecte](#ce-que-loutil-détecte)
- [Profils d'analyse](#profils-danalyse)
- [Interface](#interface)
- [Exports & intégration CI](#exports--intégration-ci)
- [Ce qu'il ne fait pas](#ce-quil-ne-fait-pas)
- [Démarrage rapide](#démarrage-rapide)
- [Configuration](#configuration)
- [API](#api)
- [Architecture](#architecture)
- [Données & vie privée](#données--vie-privée)
- [Tests & qualité](#tests--qualité)
- [Roadmap](#roadmap)
- [Références](#références)

---

## Nouveautés v2

| Domaine | Apport |
| --- | --- |
| **Historique** | Persistance SQLite : chaque analyse est enregistrée, listable, rouvrable, supprimable. |
| **Tableau de bord** | KPI (volume, score moyen, critiques cumulés), courbe d'évolution du score, table des analyses, actions par ligne. |
| **Profils** | `Rapide` (passif) et `Approfondi` (+ transfert de zone DNS, sous-domaines, redirections ouvertes). |
| **Rapports** | HTML autonome prêt à livrer (aucune ressource externe), SARIF 2.1.0, Markdown, JSON. |
| **CI** | CLI `python -m app.cli scan … --fail-under 80 --format sarif` avec code de sortie exploitable. |
| **Fiabilité** | Test de non-régression sur la persistance, base SQLite initialisée paresseusement, 93 tests. |

---

## Ce que l'outil détecte

38 sondes de fichiers, une douzaine de familles de contrôles.

| Domaine | Contrôles |
| --- | --- |
| **Transport** | HTTPS obligatoire, redirection 301 depuis HTTP, chaîne de redirections |
| **TLS** | Validité et expiration du certificat, émetteur, domaines couverts, TLS 1.0/1.1 acceptés, TLS 1.3, HTTP/2 (ALPN), force des suites, validité > 398 jours |
| **En-têtes** | HSTS (durée, `max-age=0`), X-Frame-Options, `nosniff`, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP, divulgation de versions |
| **CSP** | Analyse directive par directive : `unsafe-inline`/`unsafe-eval`, joker `*`, schémas `http:` et `data:`, absence de `object-src`, `base-uri`, `frame-ancestors`, `upgrade-insecure-requests`, `report-to` |
| **Cookies** | `Secure`, `HttpOnly`, `SameSite`, `SameSite=None` sans `Secure`, préfixes `__Host-` / `__Secure-` contournés |
| **CORS** | Origine reflétée, joker `*`, `Allow-Credentials` dangereux |
| **Méthodes** | `OPTIONS`/`Allow` exposant PUT, DELETE, TRACE… · méthode TRACE activée |
| **Fichiers exposés** | `.git/` (HEAD, config, reflog), `.env*`, `.svn`, `.hg`, `.aws/credentials`, `.htaccess`, `web.config`, `appsettings.json`, `Dockerfile`, `docker-compose.yml`, `phpinfo`, `server-status`, `server-info`, `trace.axd`, Actuator, logs Laravel, `.DS_Store`, dumps SQL, archives ZIP/TAR, Composer, npm, Swagger, GraphQL, phpMyAdmin, `xmlrpc.php`, `wp-json/wp/v2/users`, `readme.html`, `.idea/`, `crossdomain.xml` |
| **Fuite d'information** | Versions serveur/CMS, traces d'erreur (Python, .NET, SQL, PHP, Spring), commentaires HTML sensibles, `robots.txt` bavard, listage de répertoires, `security.txt` absent ou expiré |
| **Contenu** | Contenu mixte, formulaires mot de passe non chiffrés, formulaires vers un domaine tiers, scripts sans SRI, `target=_blank` sans `noopener`, iframes sans `sandbox`, formulaires POST sans jeton anti-CSRF visible, pages d'authentification mises en cache |
| **DNS / e-mail** | SPF (absent, multiple, `+all`, `~all`, `?all`), DMARC (absent, `p=none`), CAA |
| **Approfondi** | Transfert de zone AXFR, énumération de 57 sous-domaines (avec détection de wildcard DNS), redirections ouvertes sur 7 paramètres courants |

Chaque brique produit un statut visible dans le rapport (`ok`, `indisponible`, `ignorée`), pour
qu'une analyse partielle ne soit jamais présentée comme complète.

### Notation

| Sévérité | Pénalité de base | Exemple |
| --- | --- | --- |
| Critique | 20 | Dépôt Git, `.env`, clés AWS, AXFR, CORS + credentials |
| Élevée | 8 | CSP absente, certificat invalide, redirection ouverte |
| Moyenne | 3 | Cookies sans flags, clickjacking, traces d'erreur |
| Faible | 1 | Referrer-Policy absente, commentaire bavard |
| Info | 0 | Contexte utile, pas une vulnérabilité |

**Rendements décroissants** : dans une même catégorie, le 1<sup>er</sup> constat coûte 100 % de sa
pénalité, le 2<sup>e</sup> 60 %, le 3<sup>e</sup> 35 %, puis 20 %, 12 %, 8 %… Un site qui oublie huit
en-têtes n'est pas huit fois plus vulnérable qu'un site qui en oublie un. Le rapport affiche la
**composition du score** catégorie par catégorie, pour que le chiffre soit toujours explicable.

Score = `100 − Σ(pénalités)` borné à `[0, 100]` → note **A** (≥ 90) à **F** (< 30).

---

## Profils d'analyse

| Profil | Contenu | Durée typique |
| --- | --- | --- |
| **Rapide** (`quick`) | Transport, TLS, en-têtes, cookies, CORS, méthodes, 38 fichiers, contenu, DNS | 2–8 s |
| **Approfondi** (`deep`) | Tout le profil rapide **+** AXFR, 57 sous-domaines, redirections ouvertes | 15–40 s |

Le profil est sélectionnable dans l'interface ou via `--profile deep` en CLI.

---

## Interface

- **Analyse en un clic**, avec progression réelle en streaming (NDJSON) et journal d'étapes.
- **À corriger en priorité** : les trois constats décisifs, cliquables vers leur détail.
- **Composition du score** : points perdus par catégorie, en barres.
- **Tableau de bord** : analyses, score moyen, critiques cumulés, courbe d'évolution, table filtrable
  avec actions (ouvrir, HTML, SARIF, supprimer).
- **Comparaison automatique** avec l'analyse précédente du même hôte : delta de score, constats
  corrigés, nouveaux constats.
- **Exports** : JSON côté navigateur, HTML/SARIF/Markdown côté serveur, impression/PDF.
- Filtres + recherche, copie d'un constat, raccourcis `/` (recherche) et `Échap`.

---

## Exports & intégration CI

| Format | Usage | Où |
| --- | --- | --- |
| **HTML autonome** | Livrable client, impression PDF | `/api/scans/{id}/report.html` |
| **SARIF 2.1.0** | GitHub Code Scanning, VS Code, GitLab SAST | `/api/scans/{id}/sarif` |
| **Markdown** | Ticket, wiki, pull request | `/api/scans/{id}/markdown` |
| **JSON** | Automatisation, archivage | `/api/scans/{id}/json` |

### CLI (CI/CD)

```bash
# Seuil : échoue si le score est inférieur à 80
python -m app.cli scan https://exemple.fr --fail-under 80

# Rapport SARIF pour GitHub Code Scanning
python -m app.cli scan exemple.fr --profile deep --format sarif -o vulnlens.sarif.json

# Sortie HTML + résumé console
python -m app.cli scan exemple.fr --format html -o rapport.html -v
```

Codes de sortie : `0` succès · `1` seuil non atteint · `2` erreur d'analyse.

Exemple de job GitHub Actions :

```yaml
- name: Audit de surface
  run: |
    pip install -r requirements.txt
    python -m app.cli scan https://preprod.exemple.fr --fail-under 70 --format sarif -o results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Ce qu'il ne fait pas

- ❌ Aucune exploitation, aucun payload, aucun shell.
- ❌ Aucun test d'injection (SQLi, XSS, SSTI…), de force brute ou d'élévation de privilèges.
- ❌ Aucun test de déni de service ni de fuzzing agressif.
- ❌ Aucun contournement d'authentification.

C'est un outil de **durcissement et de reconnaissance défensive**, pas un outil d'attaque. Pour des
tests d'intrusion complets et authentifiés, utilisez OWASP ZAP, Burp Suite ou nuclei sur un périmètre
contractualisé.

---

## Démarrage rapide

Prérequis : Python 3.11+.

```bash
git clone <votre-url>/VulnLens && cd VulnLens
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Ouvrez <http://localhost:8000>, saisissez un domaine, choisissez le profil, cochez la confirmation
d'autorisation et cliquez sur **Analyser**. L'analyse est enregistrée automatiquement dans
`data/vulnlens.db` et apparaît dans le **Tableau de bord**.

Un script `./run.sh` fait la même chose (création du venv, installation, lancement).

### Démonstration locale

Un serveur volontairement mal configuré sert de bac à sable :

```bash
# terminal 1 — cible de test (HTTP, CSP permissive, .git et .env exposés…)
python tests/fixtures/bad_server.py

# terminal 2 — l'outil, avec autorisation des cibles locales
VULNLENS_ALLOW_PRIVATE=1 uvicorn app.main:app --port 8000
```

Puis analyser `http://127.0.0.1:<port affiché>/` : une trentaine de constats remontent, dont le
dépôt Git et le fichier `.env`.

---

## Docker

```bash
docker build -t vulnlens .
docker run --rm -p 8000:8000 -v "$PWD/data:/app/data" vulnlens
```

Le volume `data/` conserve l'historique entre deux conteneurs.

---

## Configuration

| Variable | Défaut | Rôle |
| --- | --- | --- |
| `VULNLENS_TIMEOUT` | `12` | Délai HTTP par requête (secondes) |
| `VULNLENS_SCAN_DEADLINE` | `120` | Durée maximale d'une analyse |
| `VULNLENS_MAX_SCANS` | `1` | Analyses simultanées (le reste est refusé proprement) |
| `VULNLENS_ALLOW_PRIVATE` | `0` | Autoriser les cibles privées/loopback (**dev uniquement**) |
| `VULNLENS_DB` | `data/vulnlens.db` | Chemin de la base SQLite |
| `VULNLENS_CONTACT` | `security@example.org` | Contact publié dans le User-Agent |
| `VULNLENS_USER_AGENT` | `VulnLens/2.0.0 (+…)` | User-Agent envoyé aux cibles |

Le refus des adresses internes (RFC 1918, loopback, link-local, métadonnées cloud) est volontaire :
il empêche l'outil de servir de relais SSRF.

---

## API

Documentation interactive : <http://localhost:8000/docs>.

| Méthode | Route | Description |
| --- | --- | --- |
| `GET` | `/api/meta` | Périmètre, limites, barème, profils |
| `POST` | `/api/scan` | Lance une analyse, flux NDJSON |
| `GET` | `/api/scans?host=&limit=` | Historique (50 max par défaut) |
| `GET` | `/api/scans/{id}` | Rapport complet |
| `DELETE` | `/api/scans/{id}` | Supprime une analyse |
| `GET` | `/api/stats` | KPI, sévérités cumulées, série temporelle |
| `GET` | `/api/scans/{id}/report.html` | Rapport HTML autonome |
| `GET` | `/api/scans/{id}/sarif` | SARIF 2.1.0 |
| `GET` | `/api/scans/{id}/markdown` | Markdown |
| `GET` | `/api/scans/{id}/json` | JSON brut |

```bash
curl -N -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://exemple.fr","authorized":true,"profile":"deep"}'
```

Événements émis, un JSON par ligne :

```jsonc
{"type":"accepted","target":"https://exemple.fr/"}
{"type":"progress","step":"headers","label":"Analyse des en-têtes de sécurité","percent":28,"message":"Contrôle des en-têtes (HSTS, CSP, cookies…)"}
{"type":"result","percent":100,"report":{"scan_id":"9ac365914609","score":72,"grade":"C","profile":"deep","findings":[…],"score_breakdown":{…},"priorities":[…]}}
{"type":"warning","message":"Rapport non enregistré dans l'historique : …"}
{"type":"error","code":"private_target","message":"Cible interne bloquée…"}
```

Codes d'erreur : `empty_target`, `bad_scheme`, `bad_host`, `bad_port`, `credentials_in_url`,
`dns_failure`, `private_target`, `unreachable`, `busy`, `timeout`, `internal`.

---

## Architecture

```
app/
├── main.py              # FastAPI : UI, streaming NDJSON, historique, exports
├── cli.py               # CLI CI : --fail-under, --format, --output
├── config.py            # réglages + variables d'environnement
├── models.py            # Finding / CheckResult / ScanReport, sévérités
├── safety.py            # normalisation des cibles, anti-SSRF, résolution DNS
├── db.py                # persistance SQLite (scans, stats, comparaison)
├── reporting.py         # SARIF 2.1.0, rapport HTML autonome, Markdown
├── scanner/
│   ├── engine.py        # orchestration, profils, progression, score
│   ├── fetcher.py       # client HTTP borné + sonde TLS (certificat, ALPN)
│   ├── checks_http.py   # transport, en-têtes, CSP, cookies, CORS, méthodes
│   ├── checks_tls.py    # certificat, expiration, protocoles obsolètes
│   ├── checks_exposure.py  # 38 sondes de fichiers, robots.txt, erreurs, listage
│   ├── checks_content.py   # analyse HTML (formulaires, iframes, SRI, cache)
│   ├── checks_dns.py    # SPF, DMARC, CAA
│   ├── checks_deep.py   # AXFR, sous-domaines, redirections ouvertes
│   └── scoring.py       # pénalités à rendements décroissants, note, priorités
└── static/              # UI (HTML/CSS/JS, zéro dépendance externe)
```

Principes :

1. **Tout est borné** : taille de réponse, redirections, délai global, concurrence, profondeur.
2. **Rien n'est caché** : chaque constat porte sa preuve brute et sa source.
3. **Pas de faux positifs gratuits** : une signature de fichier n'est validée que sur une réponse
   `200` et un contenu caractéristique, jamais sur une page d'erreur.
4. **Séparation stricte** : une brique fautive ne fait pas tomber l'analyse (statut `error`).
5. **Traçable** : chaque analyse a un `scan_id`, une date, un profil et un rapport immuable.

---

## Données & vie privée

- La base SQLite ne contient que des rapports d'analyse : cible, horodatage, constats, empreinte.
- Aucune donnée personnelle, aucun cookie de session, aucun secret collecté.
- Les exports HTML sont autonomes : aucun appel réseau, aucun script, aucune fuite vers un tiers.
- `DELETE /api/scans/{id}` supprime définitivement une analyse.

---

## Tests & qualité

```bash
pip install -r requirements-dev.txt
pytest          # 93 tests
ruff check .    # lint
```

Couverture fonctionnelle :

- normalisation des URL et blocage des cibles internes (SSRF) ;
- barème, rendements décroissants, décomposition du score, priorités ;
- CSP directive par directive, préfixes de cookies, en-têtes HSTS ;
- analyse HTML (contenu mixte, formulaires, iframes, CSRF, SRI, cache, commentaires) ;
- contrôles approfondis (redirections ouvertes, AXFR, sous-domaines) ;
- persistance SQLite (enregistrement, liste, stats, comparaison, suppression) ;
- exports SARIF / HTML / Markdown (structure, échappement, sérialisation) ;
- contrat d'API, y compris la persistance d'une analyse lancée depuis l'interface ;
- CLI (sorties, seuil CI, codes de retour).

La CI GitHub Actions (`.github/workflows/ci.yml`) exécute `ruff` puis `pytest` sur Python 3.11 et 3.12.

---

## Roadmap

- [x] Historique des analyses et comparaison entre deux scans
- [x] Tableau de bord (KPI, tendance, table des analyses)
- [x] Profil approfondi : AXFR, sous-domaines, redirections ouvertes
- [x] Exports HTML autonome, SARIF, Markdown + CLI avec seuil CI
- [ ] Vérification de propriété du domaine (fichier `.well-known` ou TXT DNS)
- [ ] Mode « API authentifiée » : cookies et en-têtes fournis par l'utilisateur
- [ ] Notifications (webhook Slack/Teams) quand un score chute
- [ ] Détection de sous-domaines via Certificate Transparency

---

## Références

- OWASP Web Security Testing Guide — <https://owasp.org/www-project-web-security-testing-guide/>
- OWASP Secure Headers Project — <https://owasp.org/www-project-secure-headers/>
- SARIF 2.1.0 — <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
- RFC 9116 (`security.txt`), RFC 7208 (SPF), RFC 7489 (DMARC), RFC 8659 (CAA), RFC 6797 (HSTS), RFC 5936 (AXFR)
- MDN — Sécurité web — <https://developer.mozilla.org/fr/docs/Web/Security>

---

## Licence

MIT. Voir [LICENSE](LICENSE).
