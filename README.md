# 🔍 VulnLens

**Scanner de vulnérabilités web passif — une analyse complète en un clic.**

VulnLens analyse la surface d'attaque exposée par un site : transport, TLS, en-têtes de sécurité,
cookies, CORS, fichiers oubliés, fuites d'information et configuration DNS. Chaque constat arrive
avec une **preuve**, une **remédiation** et une **référence**, classé par sévérité, avec un score
global sur 100.

> ⚖️ **Usage autorisé uniquement.** N'analysez que des systèmes dont vous êtes propriétaire ou pour
> lesquels vous disposez d'une autorisation écrite. L'outil refuse les cibles internes, ne tente
> aucune exploitation et n'envoie aucune charge destructive.

---

## Sommaire

- [Ce que l'outil détecte](#ce-que-loutil-détecte)
- [Ce qu'il ne fait pas](#ce-quil-ne-fait-pas)
- [Démarrage rapide](#démarrage-rapide)
- [Docker](#docker)
- [Configuration](#configuration)
- [API](#api)
- [Architecture](#architecture)
- [Tests](#tests)
- [Roadmap](#roadmap)
- [Références](#références)

---

## Ce que l'outil détecte

| Domaine | Contrôles |
| --- | --- |
| **Transport** | HTTPS obligatoire, redirection 301 depuis HTTP, chaîne de redirections |
| **TLS** | Validité et expiration du certificat, émetteur, TLS 1.0/1.1 acceptés, TLS 1.3, force des suites |
| **En-têtes** | HSTS (durée, `max-age=0`), CSP (absente, `unsafe-inline`, joker, sans directive de script), X-Frame-Options, `nosniff`, Referrer-Policy, Permissions-Policy, COOP |
| **Cookies** | `Secure`, `HttpOnly`, `SameSite`, combinaison `SameSite=None` sans `Secure` |
| **CORS** | Origine reflétée, joker `*`, `Allow-Credentials` dangereux |
| **Méthodes** | `OPTIONS`/`Allow` exposant PUT, DELETE, TRACE… · méthode TRACE activée |
| **Fichiers exposés** | `.git/`, `.env*`, `.htaccess`, `web.config`, `Dockerfile`, `docker-compose.yml`, `phpinfo`, `server-status`, Actuator Spring, `.DS_Store`, dumps SQL/ZIP, Composer, npm, Swagger, GraphQL |
| **Fuite d'information** | Versions serveur/CMS, traces d'erreur (Python, .NET, SQL, PHP, Spring), commentaires HTML sensibles, `robots.txt` bavard, listage de répertoires, absence de `security.txt` |
| **Contenu** | Contenu mixte, formulaires mot de passe non chiffrés, formulaires vers un domaine tiers, scripts sans SRI, `target=_blank` sans `noopener` |
| **DNS / e-mail** | SPF (absent, multiple, `+all`, `~all`, `?all`), DMARC (absent, `p=none`), CAA |

Chaque brique produit un statut visible dans le rapport (`ok`, `indisponible`, `ignorée`), pour
qu'une analyse partielle ne soit jamais présentée comme complète.

### Notation

| Sévérité | Pénalité | Signification |
| --- | --- | --- |
| Critique | −20 | Exploitable presque directement (dépôt Git, `.env`, CORS + credentials) |
| Élevée | −8 | Faiblesse sérieuse, souvent exploitable en combinaison |
| Moyenne | −3 | Durcissement manquant, impact réel mais conditionné |
| Faible | −1 | Bonne pratique absente, impact limité |
| Info | 0 | Contexte utile, pas une vulnérabilité |

Score = `100 − Σ(pénalités)` borné à `[0, 100]` → note **A** (≥ 90) à **F** (< 30).

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
# terminal 1 — cible de test (HTTP, en-têtes absents, .git et .env exposés…)
python tests/fixtures/bad_server.py

# terminal 2 — l'outil, avec autorisation des cibles locales
VULNLENS_ALLOW_PRIVATE=1 uvicorn app.main:app --port 8000
```

Puis analyser `http://127.0.0.1:<port affiché par le terminal 1>/`.

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
| `VULNLENS_USER_AGENT` | `VulnLens/1.0.0 (+…)` | User-Agent envoyé aux cibles |

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
{"type":"result","percent":100,"report":{"score":72,"grade":"C","findings":[…],"checks":[…],"fingerprint":{…}}}
{"type":"error","code":"private_target","message":"Cible interne bloquée…"}
```

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
│   ├── fetcher.py       # client HTTP borné + sonde TLS (certificat, protocoles)
│   ├── checks_http.py   # transport, en-têtes, cookies, CORS, méthodes
│   ├── checks_tls.py    # certificat, expiration, protocoles obsolètes
│   ├── checks_exposure.py  # fichiers exposés, robots.txt, erreurs, listage
│   ├── checks_content.py   # analyse HTML (formulaires, SRI, contenu mixte)
│   ├── checks_dns.py    # SPF, DMARC, CAA
│   └── scoring.py       # pénalités, note, tri
└── static/              # UI (HTML/CSS/JS, zéro dépendance externe)
```

Principes :

1. **Tout est borné** : taille de réponse, nombre de redirections, délai global, concurrence.
2. **Rien n'est caché** : chaque constat porte sa preuve brute et sa source.
3. **Aucune donnée conservée** : les rapports vivent en mémoire du navigateur, rien n'est stocké côté serveur.
4. **Séparation stricte** : une brique fautive ne fait pas tomber l'analyse (statut `error` par contrôle).

---

## Tests

```bash
.venv/bin/python -m pytest -q
```

La suite couvre :

- la normalisation des URL et le blocage des cibles internes (SSRF) ;
- le barème et les notes ;
- l'analyse HTML (contenu mixte, formulaires, SRI, commentaires, `target=_blank`) ;
- une analyse de bout en bout contre un serveur local volontairement vulnérable
  (`.git`, `.env`, en-têtes absents, cookies, `robots.txt`, traces d'erreur…) ;
- le contrat d'API (autorisation obligatoire, schémas refusés, métadonnées).

---

## Roadmap

- [ ] Vérification de propriété du domaine (fichier `.well-known` ou enregistrement DNS)
- [ ] Historique local des analyses et comparaison entre deux scans
- [ ] Export PDF et intégration CI (échec si note < seuil)
- [ ] Vérification de l'expiration des certificats via Certificate Transparency
- [ ] Mode « API authentifiée » : cookies et en-têtes fournis par l'utilisateur pour scanner derrière un login
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
