# VulnLens

**Audit de sécurité web en un clic — non intrusif, en français, avec preuves.**

VulnLens analyse une URL publique et rend un rapport hiérarchisé : ce qui est cassé, **pourquoi c'est
dangereux**, **comment le prouver** (requête exacte, en-tête, extrait) et **comment le corriger**.
Aucune exploitation, aucune injection, aucun contournement d'authentification : uniquement ce qu'un
visiteur peut observer.

```
┌ VulnLens v6.6 ─────────────────────────────────────────────────────────────┐
│  Risque critique · score 8/100     3 pages · 13 familles de contrôles      │
├────────────────────────────────────────────────────────────────────────────┤
│  « Des accès ou des données sont exposés : à traiter immédiatement. »      │
│  Ce qui expose : clé AWS dans app.js · .env public · source map publiée    │
│  Ce qui tient  : HTTPS · HSTS · CSP · SPF/DMARC · aucun takeover détecté   │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Ce que fait la v6.6 — une équipe d'agents red team, sans API

Sept spécialistes et un chef d'équipe raisonnent **localement** sur les preuves déjà collectées.
Aucun modèle de langage, aucun appel réseau, aucune dépendance : des règles explicites, donc un
raisonnement auditable, reproductible, et impossible à transformer en outil d'attaque.

| Capacité | Détail |
|---|---|
| **Sept spécialistes** | *Recon* (surface, versions, schémas d'API), *Exposition* (fichiers, sauvegardes, configuration), *Identifiants* (JWT, clés, sessions), *Accès* (IDOR, privilèges, traversée), *Client* (XSS, dépendances, CSP), *Transport* (TLS, CORS, formulaires en clair), *Chaîne logistique* (takeover, tiers, SRI). Chacun ne parle que de son domaine et cite **ses preuves** (identifiants de constats). |
| **Hypothèses, pas des alertes** | Chaque agent formule des affirmations d'attaque : identifiant stable (`agent:sujet:cible`), étape (reconnaissance → accès → élévation → exfiltration → persistance), confiance chiffrée, techniques MITRE ATT&CK, actif atteignable, et la **vérification manuelle non destructive** correspondante. |
| **Revue par les pairs** | Les agents se contredisent : une pile logicielle identifiée crédibilise les hypothèses serveur (+0,05), une CSP stricte tempère un XSS (−0,05), un vol de session sans XSS confirmé est dégradé (−0,10). Le journal garde la trace de chaque correction, avec sa raison. |
| **Arbitrage** | Le chef d'équipe écarte ce qui n'est pas étayé (confiance < 0,30, sauf actif critique ≥ 0,45), fusionne les doublons en gardant le plus solide, et conserve les désaccords (`dissent`) au lieu de les effacer. |
| **Chaînes d'exploitation** | Cinq scénarios assemblés à partir des étapes réelles : prise de contrôle de compte, exfiltration de données clients, compromission d'infrastructure, compromission du navigateur des visiteurs, cartographie de reconnaissance. Une chaîne n'existe que si elle a un **point d'entrée** ; sa confiance est celle de son **maillon le plus faible** ; son score combine l'impact de l'actif, la confiance et la difficulté. |
| **Restitution** | Panneau « Équipe red team » dans l'interface (score /10, étapes numérotées, confiance par étape, prochaines vérifications), section `## Lecture red team` en Markdown, cartes dans le rapport HTML, et `properties.attackChains` en SARIF pour la CI. Le rapport JSON expose `attack_plan` (hypothèses, chaînes, journal, désaccords, statistiques). |
| **Rejeu en CLI** | `vulnlens agents <id-analyse>` rejoue l'équipe sur une analyse enregistrée (ou `--json` pour la matière brute) : utile pour comparer deux versions d'un rapport sans rescanner. |
| **Doctrine, garantie technique** | Les agents n'ont **pas d'accès réseau** (c'est vérifié par un test qui rend `socket` inutilisable) et ne produisent **aucune charge** : pas de requête forgée, pas de jeton signé, pas de formulaire soumis, pas de fichier écrit sur la cible. Ce sont des règles de raisonnement sur des preuves, pas un exécuteur d'exploit. |

## Ce que fait la v6.5 — triage des constats

Un scanner produit des constats, un pentester produit un **verdict**. La v6.5 comble cet écart.

| Capacité | Détail |
|---|---|
| **Quatre verdicts** | *À vérifier*, *Confirmé*, *Faux positif*, *Risque accepté* — avec une note de justification (500 caractères) reprise telle quelle dans le rapport remis au client. |
| **Dans l'interface** | Chaque constat porte un sélecteur de verdict et un champ de justification, enregistrés immédiatement. La puce de verdict apparaît dans l'en-tête, une barre de triage affiche la répartition, et une case « Masquer les faux positifs » nettoie la liste. |
| **Score retenu** | Le score d'origine reste affiché (traçabilité) ; un **score après triage** est calculé en retirant les faux positifs et les risques acceptés. C'est celui que le client retient. |
| **Persistance** | Stocké par couple (analyse, constat) dans SQLite : le triage est rechargé à l'ouverture de l'historique, supprimé avec l'analyse. Aucune donnée sensible : un verdict et une note. |
| **SARIF / CI** | Un faux positif devient une `suppression` SARIF : GitHub Code Scanning et consorts cessent de l'afficher, sans casser le suivi des autres constats. |
| **API** | `GET /api/scans/{id}/triage`, `PUT` et `DELETE /api/scans/{id}/findings/{constat}/triage` : le triage peut être automatisé (import d'un tableur, script de revue). |

## Ce que fait la v6.4 — prêt pour un pentest

| Capacité | Détail |
|---|---|
| **Zone authentifiée** | Champ optionnel dans l'interface (`Authorization: Bearer …` ou `Cookie: session=…`), option `--auth` / `--auth-env` en CLI, champ `auth` dans l'API. L'en-tête n'est envoyé **qu'à l'hôte analysé** — jamais après une redirection vers un domaine tiers, jamais vers un CDN — et il n'apparaît ni dans le rapport, ni dans l'historique, ni dans le journal. Le rapport indique seulement `Scan authentifié (bearer/cookie)`. |
| **CWE + WSTG + CVSS 3.1** | Chaque constat cite le CWE (nature technique), le test OWASP WSTG correspondant et un **vecteur CVSS 3.1 dont le score est calculé** selon la spécification FIRST (jamais saisi à la main). Visible dans la fiche, le HTML, le Markdown et SARIF (`cwe`, `wstg`, `cvss`, `cvss-vector`). |
| **Journal des requêtes** | Annexe « preuve de non-intrusivité » : nombre de requêtes, méthodes utilisées, statuts, hôtes contactés, refus du garde-fou SSRF. Le journal détaillé est dans le HTML et le Markdown, la synthèse dans l'interface (onglet Technique). Une ligne confirme l'absence de toute méthode d'écriture. |
| **Périmètre élargi** | Le profil standard explore 8 pages (au lieu de 6) et 8 scripts : de quoi couvrir un espace client sans passer en « approfondi ». |
| **CLI de pentest** | `vulnlens scan cible --auth-env PENTEST_AUTH --profile deep --format sarif` : le secret reste hors de l'historique du shell, la sortie s'intègre au pipeline. |
| **Refus explicites** | En-têtes autorisés en liste blanche (`Authorization`, `Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-Access-Token`, `X-Csrf-Token`), rejet des retours à la ligne (anti-injection d'en-têtes), longueur bornée. |

## Ce que fait la v6.3 — contrôle d'accès et « ce que ça donne accès »

| Capacité | Détail |
|---|---|
| **Détection d'IDOR / BOLA** | Les identifiants d'objets sont repérés dans les URL explorées **et dans les liens publiés** (sans les ouvrir) : `/users/42`, `/factures/1024`, `?user_id=7`, UUID compris. Le constat explique la faille, cite OWASP (IDOR, API1:2023) et reste marqué **« à confirmer »** : la confirmation exige deux comptes de test, jamais un rejeu d'identifiant par l'outil. |
| **Champs cachés manipulables** | Un `<input type="hidden" name="user_id">` dans un formulaire est signalé : mass assignment, agissement sur les données d'autrui. |
| **Paramètres de privilège** | `admin`, `role`, `is_admin`, `impersonate`, `debug`, `internal`… dans l'URL : un changement de valeur ne doit jamais élever les droits. |
| **Paramètres de chemin et redirections** | `file`, `path`, `page`, `template`, `url`, `redirect`, `next`… : traversée de répertoire et redirection ouverte si aucune liste blanche ne les encadre. |
| **Paramètres reflétés** | Une valeur d'URL recopiée telle quelle dans le HTML (XSS réfléchi) est détectée **sans envoyer de charge** : on observe seulement la réflexion. |
| **Surface d'administration** | Les chemins `/admin`, `/internal`, `/backoffice`, `/staff`, `/console` cités par les scripts publics sont listés : vérifiez qu'ils ne sont pas protégés que par l'interface. |
| **« Ce que ça donne accès »** | Chaque constat porte désormais la liste des **actifs réellement atteignables** : comptes utilisateurs, sessions, console d'admin, données personnelles, paiements, base de données, code source, cloud, serveurs, secrets, intégrations SaaS, messagerie, navigateur des visiteurs, réseau interne. Affiché dans l'interface, le HTML, le Markdown et SARIF (`access-grants`). |
| **Synthèse « ce que l'attaquant peut atteindre »** | Le rapport agrège ces actifs, pondérés par la sévérité : la synthèse exécutive répond en une ligne à « si je ne corrige pas, qu'est-ce qui tombe ? ». |
| **Non destructif** | Aucun identifiant n'est incrémenté, aucun rôle forgé, aucun formulaire soumis, aucune suppression : le contrôle d'accès est **entièrement passif**, comme le reste du scanner. |

## Ce que fait la v6.2 — détection élargie

| Capacité | Détail |
|---|---|
| **Bibliothèques front-end vulnérables** | Nouveau contrôle : jQuery, jQuery UI, Bootstrap 3/4, AngularJS, Handlebars, Lodash, Underscore, Moment.js, DOMPurify, CryptoJS, Axios et Vue 2. La version détectée est comparée à la **version corrigée** ; le constat cite les CVE, la version à installer et regroupe la preuve dans l'empreinte technique. Les scripts téléchargés sont réutilisés : aucune requête en double. |
| **Analyse des JWT** | Un jeton public est décodé : `alg: none` (non signé) devient un constat **critique** de contournement d'authentification, et des revendications administratives en clair (`role: admin`, `is_admin: true`) un constat **élevé**. Le jeton reste masqué dans la preuve. |
| **33 signatures de secrets** | + Anthropic, GitHub à granularité fine, GitLab, Hugging Face, npm, PyPI, DigitalOcean, Twilio, Shopify, Airtable, OAuth Google, webhooks Slack et Discord, secret de webhook Stripe, URL de base de données avec identifiants. La clé Anthropic n'est plus confondue avec une clé OpenAI. |
| **50 fichiers exposés** | + état Terraform, clé privée SSH, `.git-credentials`, compte de service Google Cloud, heap dump Spring Actuator, profiler Symfony, `config/database.yml`, `.htpasswd`, schémas OpenAPI 3 et Swagger 2, console GraphiQL. |
| **En-têtes de débogage** | Détection d'un profiler de framework actif en production (`X-Debug-Token`, `X-Symfony-Cache`) : fuite des requêtes SQL, variables d'environnement et sessions. |
| **Restitution** | Les nouveaux constats ont leur propre rapport de situation (chemin d'accès, révélation, danger /10), leur vague de remédiation, et « bibliothèques à jour » apparaît dans les points forts quand le contrôle ne trouve rien. |

## Ce que fait la v6.1 — durcissement de l'instance

| Correctif | Détail |
|---|---|
| **SSRF par redirection** | Chaque saut de redirection est revalidé : un `302` vers `169.254.169.254` ou un service interne est refusé, plus aucun contenu interne ne remonte dans le rapport. |
| **SSRF dans la vérification de domaine** | `/api/verify/{hôte}/check` passe par le client gardé (fini le `allow_private=True` codé en dur). |
| **Limitation de débit fiable** | `X-Forwarded-For` n'est plus cru sur parole (`VULNLENS_TRUST_PROXY`), et `/api/verify/*/check` / `/api/watch/*/run` sont limités. |
| **Anti-CSRF** | Les `POST` sans corps sont refusés si l'origine ne correspond pas à l'instance. |
| **En-têtes de sécurité** | CSP stricte (`default-src 'self'`, `frame-ancestors 'none'`), `nosniff`, `Referrer-Policy`, COOP/CORP, HSTS, Permissions-Policy sur toutes les réponses. |
| **Exports neutralisés** | Rapport HTML servi en pièce jointe avec `CSP: sandbox` ; nom de fichier filtré. |
| **Moins de fuites** | Comparaison de jeton à temps constant, erreurs internes masquées au client, webhook sortant validé. |

Détail complet, preuves et risques résiduels : **[SECURITY.md](SECURITY.md)**.

## Ce que fait la v6

| Capacité | Détail |
|---|---|
| **Rapport de situation** | Pour chaque faille : **comment y arriver** (chemin d'accès en étapes, sans charge exploitable), **ce qu'elle révèle** (impact concret), et une **cotation de dangerosité de 1 à 10** — visible dans l'interface, le HTML, le Markdown et SARIF. |
| **Échelle de danger** | 1-2 signal de durcissement · 3-4 utile en combinaison · 5-6 scénario réaliste · 7-8 exploitable à distance sans effort · 9-10 accès immédiat. La note tient compte de la sévérité, de l'exposition réelle et du niveau de certitude. |
| **Niveau de compétence** | Chaque scénario indique s'il faut « aucune compétence », une compétence faible ou intermédiaire — utile pour arbitrer entre urgence et effort. |
| **Exports enrichis** | SARIF expose `danger` et aligne `security-severity` sur la note /10 ; le HTML ajoute un « Rapport de situation » en tête avec les cinq failles les plus dangereuses. |

## Ce que fait la v5

| Capacité | Détail |
|---|---|
| **Synthèse exécutive** | Une page lisible par un décideur : niveau de risque, phrase de verdict, trois risques majeurs avec leur impact réel (« le code source fuit »), ce qui tient déjà, et un radar d'exposition par catégorie. |
| **Surveillance planifiée** | Suivi par domaine (6 h / 24 h / hebdo) avec planificateur intégré, réanalyse automatique, alerte webhook en cas de régression et courbe de tendance. |
| **Sous-domaines Certificate Transparency** | Lecture des journaux de certificats publics (crt.sh) : les noms d'hôtes oubliés apparaissent, puis entrent dans la détection de takeover. |
| **Empreinte technique étendue** | WAF/CDN (Cloudflare, Akamai, Fastly, Imperva, Vercel…), CMS, frameworks, bibliothèques versionnées, analytique et langage serveur. |
| **Niveau de confiance** | Chaque constat indique s'il est *certain*, *à vérifier* ou *à confirmer* : plus de faux positifs présentés comme des certitudes. |
| **Refonte visuelle** | Onglets Synthèse / Constats / Technique, carte de risque, radar, courbe de tendance, micro-interactions et mode impression propres. |

## Ce que fait la v4

| Capacité | Détail |
|---|---|
| **Chasse aux secrets** | Les scripts JavaScript publics sont téléchargés et passés au crible de 33 signatures : clés AWS/Azure/Stripe/SendGrid/GitHub/GitLab/npm/Shopify, clés privées, JWT, identifiants en dur, `user:pass@` dans une URL. **Valeurs masquées** dans le rapport, source maps exposées signalées. |
| **Plan d'action** | Chaque constat est classé en trois vagues — *aujourd'hui*, *ce sprint*, *projet* — avec le gain de score potentiel chiffré (`+47 pts`), dans l'UI, les exports et `/api/scans/{id}/plan`. |
| **Sécurité e-mail avancée** | DMARC (`p=none`, absence de `sp=`), SPF au-delà de 10 résolutions DNS, DKIM par balayage de sélecteurs, MTA-STS et TLS-RPT. |
| **Surface tierce** | Cartographie des domaines chargés (CDN, analytique, paiement, vidéo, support…), avec leur rôle, et alerte sur les formulaires qui postent vers l'extérieur. |
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

# plan d'action seul (Markdown), idéal pour un ticket ou une revue de sprint
python -m app.cli scan https://exemple.fr --format plan

# surveillance : ajouter, lister, analyser à la demande
python -m app.cli watch add exemple.fr --interval 24
python -m app.cli watch list
python -m app.cli watch run exemple.fr

# vérifier la propriété d'un domaine avant de scanner
python -m app.cli verify exemple.fr
```

Codes de sortie : `0` (ok), `1` (sous le seuil `--fail-under`), `2` (erreur d'analyse).

---

## Profils d'analyse

| Profil | Pages | Scripts | Contrôles |
|---|---|---|---|
| `quick` | 1 | 3 | Transport, en-têtes, cookies, exposition, contenu, secrets, bibliothèques, DNS, TLS |
| `standard` (défaut) | 6 | 6 | + e-mail avancé, surface tierce, bibliothèques, agrégation multi-pages |
| `deep` | 12 | 10 | + AXFR, sous-domaines, **takeover**, redirections ouvertes, TLS détaillé |

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

Contenu du HTML : bandeau de score, **synthèse exécutive avec radar**, **rapport de situation**
(chemin d'accès, révélation, danger /10), **plan d'action en trois vagues**, **évolution vs analyse
précédente**, **dépendances tierces**, constats détaillés (preuve + remédiation + référence),
empreinte technique, **pages analysées**, contrôles exécutés avec leur durée.

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
| `GET` | `/api/scans/{id}/plan` | Plan de remédiation (quick / sprint / projet) + gain potentiel |
| `GET` | `/api/watch` | Cibles surveillées, échéances et état du planificateur |
| `POST` | `/api/watch` | Ajouter / mettre à jour une cible (`host`, `profile`, `interval_hours`) |
| `POST` | `/api/watch/{host}/run` | Réanalyser immédiatement une cible surveillée |
| `DELETE` | `/api/watch/{host}` | Retirer une cible |
| `GET` | `/api/trend/{host}` | Série de scores pour la courbe de tendance |
| `GET` | `/api/scans/{id}/report.html` | Export HTML |
| `GET` | `/api/scans/{id}/sarif` | Export SARIF |
| `GET` | `/api/scans/{id}/markdown` | Export Markdown |
| `DELETE` | `/api/scans/{id}` | Suppression |
| `GET` | `/api/stats` | Agrégats du tableau de bord |
| `GET` | `/api/verify/{hôte}` | Jeton + instructions (sans requête réseau) |
| `POST` | `/api/verify/{hôte}/check` | Vérifie DNS puis fichier, persiste le résultat |

Si `VULNLENS_TOKEN` est défini, toutes les routes `/api/*` (sauf `/api/health`) exigent
`Authorization: Bearer <jeton>` ou `X-API-Key: <jeton>`. Sans jeton, l'instance est
ouverte : un avertissement est écrit au démarrage. Toutes les réponses portent une CSP
stricte et les en-têtes de durcissement (`nosniff`, `frame-ancestors 'none'`, HSTS…).
Les méthodes d'écriture sont protégées contre le CSRF par contrôle d'origine.

---

## Configuration

| Variable | Défaut | Effet |
|---|---|---|
| `VULNLENS_ALLOW_PRIVATE` | `0` | Autorise les cibles privées (labo, `127.0.0.1`) |
| `VULNLENS_TOKEN` | vide | Protège l'API par jeton |
| `VULNLENS_WATCH` | `0` | Active le planificateur de surveillance |
| `VULNLENS_WATCH_TICK` | `300` | Fréquence de vérification des échéances (s) |
| `VULNLENS_WEBHOOK` | vide | URL recevant les alertes (JSON `POST`) |
| `VULNLENS_ALERT_THRESHOLD` | vide | Alerte si score `< seuil` |
| `VULNLENS_ALERT_MIN_DROP` | `10` | Alerte si le score chute de N points |
| `VULNLENS_ALERT_ON_CRITICAL` | `1` | Alerte à l'apparition d'un constat critique |
| `VULNLENS_CONTACT` | `security@example.org` | Contact dans le User-Agent |
| `VULNLENS_DB` | `data/vulnlens.db` | Base SQLite |
| `VULNLENS_TRUST_PROXY` | `0` | Fait confiance à `X-Forwarded-For` / `X-Forwarded-Host` (uniquement derrière un reverse proxy maîtrisé) |
| `VULNLENS_ALLOWED_ORIGINS` | vide | Origines supplémentaires autorisées à appeler l'API (liste séparée par des virgules) |

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
├─ remediation.py     plan d'action (effort, priorité, gain de score)
├─ narrative.py       synthèse exécutive, niveau de risque, radar, confiance
├─ attack.py          rapport de situation : chemin d'accès, révélation, danger 1-10
├─ impact.py          ce que chaque faille donne accès (comptes, base, paiements…)
├─ triage.py          verdicts du pentester, score retenu après triage
├─ standards.py       CWE, WSTG et calculateur CVSS 3.1
├─ credentials.py     en-tête d'authentification : validation, masquage
├─ watch.py           surveillance planifiée (échéances, réanalyse, alertes)
├─ alerts.py          webhook best-effort
├─ db.py              SQLite, migrations, stats, analyse précédente
├─ reporting.py       HTML, SARIF, Markdown
├─ scanner/
│  ├─ engine.py       orchestration par profil, crawl, agrégation
│  ├─ crawl.py        exploration bornée (profondeur 2, exclusions)
│  ├─ aggregate.py    fusion des constats multi-pages
│  ├─ fetcher.py      HTTP poli (timeouts, UA, taille bornée), TLS
│  ├─ checks_http.py  en-têtes, cookies, méthodes, HSTS
│  ├─ checks_secrets.py   33 signatures de secrets, JWT et source maps
│  ├─ checks_libs.py      bibliothèques front-end vs versions corrigées (CVE)
│  ├─ checks_access.py    IDOR/BOLA, champs cachés, paramètres de privilège (passif)
│  ├─ checks_email.py     DMARC, SPF, DKIM, MTA-STS, TLS-RPT
│  ├─ checks_thirdparty.py cartographie des dépendances tierces
│  ├─ recon_ct.py          sous-domaines via Certificate Transparency
│  ├─ tech.py              WAF, CDN, CMS, frameworks, analytique
│  ├─ checks_tls.py   certificat, protocoles, chaîne
│  ├─ checks_exposure.py  50 chemins sensibles (.git, .env, state Terraform, heap dump…)
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
.venv/bin/python -m pytest        # 339 tests (dont 30 de durcissement)
.venv/bin/ruff check .

# interface : rendu simulé (jsdom), aucune erreur JavaScript tolérée
npm install                       # une seule fois (dev)
npm run ui:check                  # parcours de scan + tableau de bord / tendance
```

Couverture : normalisation et refus de cibles, scoring, en-têtes, contenu, DNS/deep, **bibliothèques front-end**,
**analyse des JWT**, **contrôle d'accès (IDOR)**, **actifs atteignables**, **CWE/WSTG/CVSS**,
**en-tête d'authentification** (jamais envoyé aux tiers, jamais reporté), **journal des requêtes**,
**triage et score après triage**, **crawl**,
**agrégation**, **diff**, **alertes**, **vérification**, **takeover**, **secrets**, **e-mail**,
**surface tierce**, **plan de remédiation**, **synthèse exécutive**, **surveillance**, **Certificate
Transparency**, **empreinte technique**, **secrets et expositions élargis**, persistance, API (historique, exports, jeton, diff, plan,
watch, trend, verify), **sécurité de l'instance** (SSRF par redirection, SSRF de la
vérification, AXFR interne, contournement de débit, CSRF, en-têtes, fuite d'erreurs),
CLI (`scan`, `verify`, `watch`), et un **test de fumée de l'interface** sous jsdom. Fixture serveur volontairement vulnérable : 3 pages, clé AWS factice, source map exposée.

---

## Feuille de route

- [x] Plan d'action priorisé (quick / sprint / projet)
- [x] Synthèse exécutive et radar de risque
- [x] Surveillance planifiée avec alertes de régression
- [x] Rapport de situation avec cotation de dangerosité 1-10
- [x] Chasse aux secrets dans les bundles publics
- [x] Cartographie des dépendances tierces
- [x] CWE, WSTG et CVSS 3.1 sur chaque constat
- [x] Journal des requêtes (preuve de non-intrusivité)
- [x] Scan de la zone authentifiée sans jamais persister le secret
- [ ] Import d'une portée (`scope.txt`) et d'une liste d'URLs
- [x] Triage des constats (confirmé / faux positif / risque accepté) avant export client
- [ ] Rapport hebdomadaire par e-mail (digest de la surveillance)
- [ ] Règles personnalisées (`*.yaml`) pour les contrôles maison
- [ ] Comparaison multi-sites (portefeuille)
- [ ] Export PDF côté serveur (sans dépendance navigateur)

## Licence

MIT — voir `LICENSE`. Utilisez VulnLens uniquement sur des cibles que vous êtes autorisé à tester.
