# 🔍 VulnLens

**Scanner de vulnérabilités web passif — une analyse complète en un clic.**

VulnLens analyse la surface d'attaque exposée par un site : transport, TLS, en-têtes, cookies,
CORS, fichiers oubliés, fuites d'information et configuration DNS. Chaque constat arrive avec une
**preuve**, une **remédiation** et une **référence**, classé par sévérité, avec un score sur 100.

> ⚖️ **Usage autorisé uniquement.** N'analysez que des systèmes dont vous êtes propriétaire ou pour
> lesquels vous disposez d'une autorisation écrite. L'outil refuse les cibles internes, ne tente
> aucune exploitation et n'envoie aucune charge destructive.

---

## Sommaire

- [Ce que l'outil détecte](#ce-que-loutil-détecte)
- [Interface](#interface)
- [Ce qu'il ne fait pas](#ce-quil-ne-fait-pas)
- [Démarrage rapide](#démarrage-rapide)
- [Docker](#docker)
- [Configuration](#configuration)
- [API](#api)
- [Architecture](#architecture)
- [Tests & qualité](#tests--qualité)
- [Roadmap](#roadmap)
- [Références](#références)

---

## Ce que l'outil détecte

38 sondes de fichiers et une douzaine de familles de contrôles.

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

Chaque brique produit un statut visible dans le rapport (`ok`, `indisponible`, `ignorée`), pour
qu'une analyse partielle ne soit jamais présentée comme complète.

### Notation

| Sévérité | Pénalité de base | Exemple |
| --- | --- | --- |
| Critique | 20 | Dépôt Git, `.env`, clés AWS, CORS + credentials |
| Élevée | 8 | CSP absente, certificat invalide, formulaire non chiffré |
| Moyenne | 3 | Cookies sans flags, clickjacking, traces d'erreur |
| Faible | 1 | Referrer-Policy absente, commentaire bavard |
| Info | 0 | Contexte utile, pas une vulnérabilité |

**Rendements décroissants** : dans une même catégorie, le 1<sup>er</sup> constat coûte 100 % de sa
pénalité, le 2<sup>e</sup> 60 %, le 3<sup>e</sup> 35 %, puis 20 %, 12 %, 8 %… Un site qui oublie
huit en-têtes n'est pas huit fois plus vulnérable qu'un site qui en oublie un. Le rapport affiche la
**composition du score** catégorie par catégorie, pour que le chiffre soit toujours explicable.

Score = `100 − Σ(pénalités)` borné à `[0, 100]` → note **A** (≥ 90) à **F** (< 30).

---

## Interface

- **Un clic** : domaine → analyse en streaming (progression réelle, pas une barre décorative).
- **À corriger en priorité** : les trois constats qui comptent le plus, cliquables vers leur détail.
- **Composition du score** : combien de points chaque catégorie retire, en barres.
- **Historique local** : les 10 dernières analyses restent dans le navigateur (jamais sur le
  serveur) et peuvent être rouvertes.
- **Comparaison automatique** : face à l'analyse précédente du même hôte — delta de score, constats
  corrigés, nouveaux constats.
- **Filtres + recherche**, copie d'un constat, export JSON, **impression / PDF** (feuille de style
  dédiée), raccourcis `/` (recherche) et `Échap`.
- Empreinte technique (serveur, framework, CMS, version TLS, HTTP/2, certificat) et statut de
  chaque contrôle exécuté.

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

Ouvrez ensuite <http://localhost:8000>, saisissez un domaine, cochez la confirmation d'autorisation
et cliquez sur **Analyser**. Le rapport s'affiche en quelques secondes.

Un script `./run.sh` fait la même chose (création du venv, installation, lancement).

### Démonstration locale

Un serveur volontairement mal configuré sert de bac à sable :

```bash
# terminal 1 — cible de test (HTTP, CSP permissive, .git et .env exposés…)
python tests/fixtures/bad_server.py

# terminal 2 — l'outil, avec autorisation des cibles locales
VULNLENS_ALLOW_PRIVATE=1 uvicorn app.main:app --port 8000
```

Puis analyser `http://127.0.0.1:<port affiché par le terminal 1>/` : une trentaine de constats
remontent, dont le dépôt Git et le fichier `.env`.

---

## Docker

```bash
docker build -t vulnlens .
docker run --rm -p 8000:8000 vulnlens
```

---

## Configuration

Toutes les options passent par des variables d'environnement (voir `app/config.py`).

| Variable | Défaut | Rôle |
| --- | --- | --- |
| `VULNLENS_TIMEOUT` | `12` | Délai HTTP par requête (secondes) |
| `VULNLENS_SCAN_DEADLINE` | `120` | Durée maximale d'une analyse |
| `VULNLENS_MAX_SCANS` | `1` | Analyses simultanées (le reste est refusé proprement) |
| `VULNLENS_ALLOW_PRIVATE` | `0` | Autoriser les cibles privées/loopback (**dev uniquement**) |
| `VULNLENS_CONTACT` | `security@example.org` | Contact publié dans le User-Agent |
| `VULNLENS_USER_AGENT` | `VulnLens/1.1.0 (+…)` | User-Agent envoyé aux cibles |

Le refus des adresses internes (RFC 1918, loopback, link-local, métadonnées cloud) est volontaire :
il empêche l'outil de servir de relais SSRF.

---

## API

L'interface ne fait qu'appeler deux routes.

### `GET /api/meta`

Périmètre, limites et barème de sévérité — utilisés par l'UI.

### `POST /api/scan` → flux NDJSON

```bash
curl -N -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://exemple.fr","authorized":true}'
```

Événements émis, un JSON par ligne :

```jsonc
{"type":"accepted","target":"https://exemple.fr/"}
{"type":"progress","step":"headers","label":"Analyse des en-têtes de sécurité","percent":28,"message":"Contrôle des en-têtes (HSTS, CSP, cookies…)"}
{"type":"result","percent":100,"report":{"scan_id":"9ac365914609","score":72,"grade":"C","findings":[…],"checks":[…],"fingerprint":{…},"score_breakdown":{…},"priorities":["headers.missing.content-security-policy"]}}
{"type":"error","code":"private_target","message":"Cible interne bloquée…"}
```

Le rapport contient `score_breakdown` (pénalité par catégorie) et `priorities` (identifiants des trois
constats à traiter d'abord).

Codes d'erreur : `empty_target`, `bad_scheme`, `bad_host`, `bad_port`, `credentials_in_url`,
`dns_failure`, `private_target`, `unreachable`, `busy`, `timeout`, `internal`.

Documentation interactive : <http://localhost:8000/docs>.

---

## Architecture

```
app/
├── main.py              # FastAPI : UI statique, streaming NDJSON, quotas
├── config.py            # réglages + variables d'environnement
├── models.py            # Finding / CheckResult / ScanReport, sévérités
├── safety.py            # normalisation des cibles, anti-SSRF, résolution DNS
├── scanner/
│   ├── engine.py        # orchestration, progression, déduplication, score
│   ├── fetcher.py       # client HTTP borné + sonde TLS (certificat, ALPN, protocoles)
│   ├── checks_http.py   # transport, en-têtes, CSP, cookies, CORS, méthodes
│   ├── checks_tls.py    # certificat, expiration, protocoles obsolètes
│   ├── checks_exposure.py  # 38 sondes de fichiers, robots.txt, erreurs, listage
│   ├── checks_content.py   # analyse HTML (formulaires, iframes, SRI, contenu mixte)
│   ├── checks_dns.py    # SPF, DMARC, CAA
│   └── scoring.py       # pénalités à rendements décroissants, note, priorités
└── static/              # UI (HTML/CSS/JS, zéro dépendance externe)
```

Principes :

1. **Tout est borné** : taille de réponse, nombre de redirections, délai global, concurrence.
2. **Rien n'est caché** : chaque constat porte sa preuve brute et sa source.
3. **Pas de faux positifs gratuits** : une signature de fichier n'est validée que sur une réponse
   `200` et sur un contenu caractéristique, jamais sur une page d'erreur.
4. **Séparation stricte** : une brique fautive ne fait pas tomber l'analyse (statut `error` par contrôle).
5. **Vie privée** : les rapports restent dans le navigateur, rien n'est stocké côté serveur.

---

## Tests & qualité

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
```

**59 tests** couvrent :

- la normalisation des URL et le blocage des cibles internes (SSRF) ;
- le barème, les rendements décroissants, la décomposition du score et les priorités ;
- l'analyse CSP directive par directive, les préfixes de cookies, les en-têtes HSTS ;
- l'analyse HTML (contenu mixte, formulaires, iframes, CSRF, SRI, cache, commentaires) ;
- une analyse de bout en bout contre un serveur local volontairement vulnérable ;
- le contrat d'API (autorisation obligatoire, schémas refusés, métadonnées).

La CI GitHub Actions (`.github/workflows/ci.yml`) exécute `ruff` puis `pytest` sur Python 3.11 et 3.12.

---

## Roadmap

- [x] Historique local des analyses et comparaison entre deux scans
- [x] Export PDF (via impression) et copie d'un constat
- [x] Analyse CSP directive par directive et durcissement des cookies
- [ ] Vérification de propriété du domaine (fichier `.well-known` ou enregistrement DNS)
- [ ] Intégration CI (échec si note < seuil, sortie SARIF)
- [ ] Vérification des certificats via Certificate Transparency
- [ ] Mode « API authentifiée » : cookies et en-têtes fournis par l'utilisateur
- [ ] Détection de sous-domaines (énumération passive via CT logs et DNS)

---

## Références

- OWASP Web Security Testing Guide — <https://owasp.org/www-project-web-security-testing-guide/>
- OWASP Secure Headers Project — <https://owasp.org/www-project-secure-headers/>
- RFC 9116 (`security.txt`), RFC 7208 (SPF), RFC 7489 (DMARC), RFC 8659 (CAA), RFC 6797 (HSTS)
- MDN — Sécurité web — <https://developer.mozilla.org/fr/docs/Web/Security>

---

## Licence

MIT. Voir [LICENSE](LICENSE).
