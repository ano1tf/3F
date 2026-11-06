# Sécurité de VulnLens

VulnLens est un outil qui **envoie des requêtes vers l'extérieur** et rend des rapports
consultables : il doit donc être durci autant que les sites qu'il audite. Ce document
recense l'audit du code de l'instance (API, moteur de scan, exports, interface) et les
correctifs appliqués.

- **Date de l'audit** : novembre 2026
- **Périmètre** : `app/` (FastAPI, moteur, exports, interface), `run.sh`, `Dockerfile`
- **Méthode** : revue de code ciblée sur les frontières de confiance (entrées HTTP, cibles
  scannées, contenu distant, configuration) + tests de non-régression
- **Aucune cible tierce n'a été analysée** pour cet audit : tout a été reproduit sur des
  serveurs locaux de test.

## Résumé

| ID | Faille | Sévérité | État |
|---|---|---|---|
| VL-01 | SSRF par redirection HTTP (le scanner suivait un `302` vers le réseau interne) | **Critique** | Corrigé |
| VL-02 | SSRF dans la vérification de propriété de domaine | **Critique** | Corrigé |
| VL-03 | Transfert de zone DNS (AXFR) vers un serveur DNS interne | Élevée | Corrigé |
| VL-04 | Contournement de la limitation de débit via `X-Forwarded-For` | Élevée | Corrigé |
| VL-05 | CSRF sur les `POST` sans corps (`/api/watch/{h}/run`, `/api/verify/{h}/check`) | Moyenne | Corrigé |
| VL-06 | Absence d'en-têtes de sécurité et de CSP sur l'instance | Moyenne | Corrigé |
| VL-07 | Comparaison de jeton non constante (fuite de préfixe par latence) | Faible | Corrigé |
| VL-08 | Détails d'erreurs internes renvoyés au client | Faible | Corrigé |
| VL-09 | Identifiant de scan non filtré dans `Content-Disposition` + export HTML non neutralisé | Faible | Corrigé |
| VL-10 | Webhook sortant non validé (SSRF par mauvaise configuration) | Faible | Corrigé |
| VL-11 | Instance non authentifiée par défaut, exposée en `0.0.0.0` | Élevée (configuration) | Atténué + recommandé |

Les 21 tests ajoutés dans `tests/test_security.py` (30 cas avec les paramétrages)
verrouillent chaque correctif. Suite complète : **247 tests**.

---

## VL-01 — SSRF par redirection HTTP (critique)

**Composant** : `app/scanner/fetcher.py`

**Cause** : le client httpx était créé avec `follow_redirects=True`. Les garde-fous
(`safety.validate_target`) ne validaient que l'URL **de départ**. Un site public — donc
autorisé au scan — pouvait répondre :

```
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

et le scanner allait chercher la ressource interne, puis l'affichait dans le rapport
(`evidence`, contenu de page, secrets). Tous les appels passent par ce client :
exploration des pages, 38 chemins sensibles, scripts JS, vérification de domaine.

**Preuve** (serveur local, avant/après correctif) :

```
ANCIEN  status=200  fuite=True
NOUVEAU status=0    erreur="Redirection bloquée : elle vise une adresse interne (protection anti-SSRF)."  fuite=False
```

**Impact** : lecture de métadonnées cloud (jetons IAM), de panneaux d'administration
internes ou de tout service lié à `127.0.0.1` — c'est-à-dire un pivot depuis l'instance
VulnLens vers son réseau, avec restitution du contenu à l'attaquant.

**Correctif** :
- suivi **manuel** des redirections (`follow_redirects=False`), avec validation de
  **chaque saut** par `safety.validate_redirect_url` avant l'envoi ;
- refus des schémas autres que `http`/`https` (`file:`, `gopher:`, `data:`…) ;
- limite de 5 sauts, reprise correcte des codes 301/302/303/307/308 ;
- en complément, la garde s'applique aussi à la première requête (défense en profondeur).

**Tests** : `test_redirect_to_cloud_metadata_is_blocked`,
`test_redirect_to_internal_service_is_never_fetched` (le service interne reçoit
exactement 0 requête), `test_redirect_to_non_http_scheme_is_blocked`.

---

## VL-02 — SSRF dans la vérification de propriété (critique)

**Composant** : `app/verify.py::check_file`

**Cause** : la fonction forçait `validate_target(..., allow_private=True)` puis faisait un
`GET` avec `httpx` en `follow_redirects=True`. `POST /api/verify/<hôte>/check` déclenchait
donc deux requêtes sortantes vers **n'importe quel hôte**, y compris
`metadata.google.internal`, `127.0.0.1` ou une IP RFC1918, sur le port 80/443.

**Impact** : SSRF aveugle mais répétable et non authentifié quand `VULNLENS_TOKEN` n'est
pas défini (cas par défaut) ; utilisable aussi comme sonde de présence de services
internes via le champ `detail` de la réponse.

**Correctif** : la vérification passe désormais par le `Fetcher` gardé, avec
`config.ALLOW_PRIVATE_TARGETS` (désactivé par défaut) au lieu d'un `True` codé en dur ;
redirections revalidées comme en VL-01.

**Tests** : `test_verify_never_fetches_private_hosts`,
`test_api_verify_check_rejects_metadata_host`.

---

## VL-03 — AXFR vers un serveur DNS interne (élevée)

**Composant** : `app/scanner/checks_deep.py::_attempt_axfr`

**Cause** : les serveurs faisant autorité étaient résolus puis contactés en TCP **sans
vérification d'adresse**. Un domaine dont l'enregistrement `NS` pointe vers `10.0.0.5` ou
`127.0.0.1` faisait ouvrir une connexion depuis l'instance.

**Correctif** : les adresses des `NS` sont filtrées par `is_public_ip` (sauf mode
`VULNLENS_ALLOW_PRIVATE=1`).

**Test** : `test_axfr_skips_internal_nameservers`.

---

## VL-04 — Contournement de la limitation de débit (élevée)

**Composant** : `app/main.py::_client_key`

**Cause** : la clé de limitation était `X-Forwarded-For` **brut**, en premier élément.
N'importe qui pouvait envoyer un en-tête différent à chaque requête et lancer un nombre
illimité d'analyses. `POST /api/verify/{h}/check` et `POST /api/watch/{h}/run`, eux,
n'étaient pas limités du tout, malgré leurs requêtes sortantes.

**Correctif** :
- `X-Forwarded-For` ignoré par défaut ; pris en compte uniquement si
  `VULNLENS_TRUST_PROXY=1`, et alors l'entrée la plus à droite (celle ajoutée par notre
  proxy) est utilisée ;
- limitation ajoutée sur `/api/verify/{h}/check` (10 / 5 min) et `/api/watch/{h}/run`
  (10 / 5 min) ;
- paramètre `limit` de `/api/scans` borné (1–200).

**Tests** : `test_forwarded_for_is_ignored_by_default`,
`test_forwarded_for_used_only_behind_trusted_proxy`,
`test_verify_check_is_rate_limited` (changer l'en-tête ne réinitialise plus le compteur).

---

## VL-05 — CSRF sur les `POST` sans corps (moyenne)

**Composant** : `app/main.py`

**Cause** : `POST /api/watch/<hôte>/run` et `POST /api/verify/<hôte>/check` n'ont pas de
corps JSON. Ce sont donc des « simple requests » : une page ouverte dans le navigateur
d'un utilisateur ayant accès à l'instance pouvait les déclencher sans préflight CORS
(déclenchement de scans, interrogation DNS arbitraire). Les routes avec corps JSON
(`/api/scan`, `/api/watch`) sont protégées par le préflight, mais l'absence de contrôle
d'origine restait une faiblesse de conception.

**Correctif** : middleware qui refuse toute méthode d'écriture `/api/*` dont l'en-tête
`Origin` ne correspond pas à l'hôte de l'instance, ou marquée
`Sec-Fetch-Site: cross-site`. `VULNLENS_ALLOWED_ORIGINS` permet d'autoriser un frontal
servi depuis un autre domaine.

**Tests** : `test_cross_origin_post_is_refused`, `test_cross_site_fetch_metadata_is_refused`,
`test_same_origin_post_is_allowed`.

---

## VL-06 — Absence d'en-têtes de sécurité (moyenne)

**Cause** : l'interface et les exports étaient servis sans CSP ni en-têtes de durcissement.

**Correctif** : middleware appliqué à **toutes** les réponses :

```
Content-Security-Policy: default-src 'self'; base-uri 'none'; object-src 'none';
  frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; style-src 'self';
  script-src 'self'; connect-src 'self'; font-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()
Strict-Transport-Security (uniquement en HTTPS)
```

La CSP stricte est possible parce que l'interface n'a **ni script ni style en ligne**.
`/docs` et `/redoc` (Swagger UI) reçoivent une CSP dédiée autorisant le CDN, sans
affaiblir celle de l'application.

**Test** : `test_security_headers_on_ui`.

---

## VL-07 — Comparaison de jeton non constante (faible)

**Cause** : `token != config.AUTH_TOKEN` compare octet par octet et sort au premier écart,
ce qui laisse mesurer la longueur du préfixe correct.

**Correctif** : `secrets.compare_digest`, avec rejet des valeurs vides.

**Test** : `test_token_check_rejects_prefix_and_empty_values`.

---

## VL-08 — Fuite de détails d'erreurs internes (faible)

**Cause** : en cas d'exception, le flux NDJSON renvoyait
`type(exc).__name__: str(exc)` au client (chemins, noms de bibliothèques, parfois extraits
de données).

**Correctif** : message neutre côté client, trace complète dans les journaux serveur
(`logger.exception`).

**Test** : `test_internal_error_details_are_not_exposed`.

---

## VL-09 — Export : nom de fichier et HTML (faible)

**Cause** : `scan_id` (issu du chemin d'URL) était concaténé dans
`Content-Disposition: filename="vulnlens-{scan_id}.html"`. Les identifiants sont
normalement hexadécimaux, mais rien ne l'imposait ; un identifiant contenant `"` ou `;`
pouvait altérer l'en-tête. Le rapport HTML était aussi servi sur la même origine que
l'application.

**Correctif** : nom de fichier filtré (`[A-Za-z0-9_.-]`, 64 caractères) et export servi
avec `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` et
`Content-Security-Policy: sandbox; …` — un rapport ne peut pas exécuter de script sur
l'origine de VulnLens, même si un échappement venait à manquer.

**Tests** : `test_report_export_is_neutralised`, `test_export_filename_ignores_path_characters`.

---

## VL-10 — Webhook sortant non validé (faible)

**Cause** : `VULNLENS_WEBHOOK_URL` était utilisé tel quel. Une valeur mal configurée (ou
injectée via un déploiement automatisé) pouvait viser une cible interne.

**Correctif** : schéma `http`/`https` obligatoire, hôte interne refusé par défaut,
redirections non suivies. `VULNLENS_ALLOW_PRIVATE=1` reste possible pour les tests locaux.

---

## VL-11 — Instance non authentifiée par défaut (élevée en configuration)

**Constat** : sans `VULNLENS_TOKEN`, toutes les routes (scan, historique, exports,
suppression, vérification) sont ouvertes. `run.sh` et le `Dockerfile` écoutent sur
`0.0.0.0` : une instance exposée publiquement permet à quiconque de lancer des analyses
en votre nom, de lire l'historique et de supprimer des rapports.

**Atténuation appliquée** : avertissement explicite au démarrage (`logger.warning`) quand
aucun jeton n'est configuré, rappel dans le README et ici.

**Recommandation** : définir `VULNLENS_TOKEN` dès que l'instance quitte `localhost`, et
placer l'outil derrière un reverse proxy authentifiant si plusieurs personnes y accèdent.
Un déploiement type :

```bash
VULNLENS_TOKEN="$(openssl rand -hex 32)" \
VULNLENS_TRUST_PROXY=1 \
VULNLENS_ALLOWED_ORIGINS="https://audit.exemple.fr" \
docker run -p 127.0.0.1:8000:8000 -e VULNLENS_TOKEN -e VULNLENS_TRUST_PROXY vulnlens
```

---

## Ce qui a été vérifié et n'est pas vulnérable

- **Injection SQL** : toutes les requêtes de `app/db.py` sont paramétrées (aucune
  concaténation), y compris pour `host`, `scan_id` et les filtres d'historique.
- **XSS stocké dans le rapport HTML** : chaque valeur issue de la cible (titre, URL,
  en-tête, extrait de script, nom de tiers) passe par `html.escape` (`_e`) ; vérifié
  champ par champ dans `app/reporting.py`.
- **XSS dans l'interface** : le rendu utilise `textContent` / `createElement` ; les deux
  seules interpolations `innerHTML` (courbe de tendance, comparaison) passent par
  `escapeHtml` ou par des valeurs numériques.
- **Path traversal sur les exports** : l'identifiant est une clé de base, jamais un
  chemin de fichier.
- **Injection d'en-tête** : traitée en VL-09.
- **Secrets dans les rapports** : les valeurs détectées sont masquées avant stockage.
- **Jeton de vérification** : `secrets.token_hex(16)`, sans privilège particulier.

---

## Risques résiduels (assumés, documentés)

1. **DNS rebinding** : l'adresse est validée avant la requête (avec un cache de 30 s), mais
   la connexion TCP ne peut pas être épinglée sur l'IP validée avec les API publiques
   d'httpx. Un attaquant contrôlant un DNS à TTL très court pourrait, en théorie, faire
   basculer la résolution entre la validation et la connexion. Le vecteur pratique
   (redirection) est fermé en VL-01. Piste d'amélioration : `network_backend` d'httpcore
   pour épingler la connexion à l'adresse résolue.
2. **Scan de ports sur l'Internet public** : les ports non standard sont autorisés
   (`https://exemple.fr:8443`). Un utilisateur autorisé peut donc sonder des ports de
   cibles publiques. Limiter cela casserait des usages légitimes ; la limitation de débit
   et le jeton d'API restent les contrôles adaptés.
3. **Case « je suis autorisé »** : déclarative. Elle ne remplace pas un cadre contractuel
   ni la vérification de propriété (badge `verified`), qui reste la preuve recommandée.
4. **Auto-documentation `/docs`** : exposée par défaut. Si l'instance est publique,
   restreindre l'accès ou la désactiver (`--root-path`/proxy) est préférable.

---

## Vérifier soi-même

```bash
.venv/bin/python -m pytest tests/test_security.py -v   # 30 tests de durcissement
.venv/bin/python -m pytest                             # 339 tests
.venv/bin/ruff check .
npm run ui:check                                       # interface, sans erreur JS
```

Les tests `test_redirect_to_*` montent de vrais serveurs HTTP locaux : ils prouvent que la
redirection est refusée **et** que le service interne ne reçoit aucune requête.

## Secret d'authentification (v6.4)

Le scan de la zone connectée manipule un vrai secret : un jeton ou un cookie de session.
Traitement retenu, vérifié par `tests/test_credentials.py` :

| Risque | Mesure |
|---|---|
| Envoi à un domaine tiers | L'en-tête n'est injecté que si l'hôte de la requête est **exactement** celui de la cible. Un `302` vers un autre hôte repart sans lui (test dédié avec deux serveurs). |
| Fuite dans le rapport | Seuls `auth_used` et `auth_kind` (`bearer`, `cookie`…) sont conservés. Un test sérialise le rapport complet et vérifie que le jeton n'y figure pas. |
| Fuite dans le journal | Le journal n'enregistre que méthode, URL **sans chaîne de requête**, statut et durée. |
| Injection d'en-têtes | Retours à la ligne et NUL refusés ; nom en liste blanche (`Authorization`, `Cookie`, `X-Api-Key`…) ; valeur bornée à 4 096 caractères. |
| Fuite par l'historique | L'API et la CLI ne persistent jamais l'en-tête ; la CLI accepte `--auth-env` pour éviter la ligne de commande. |
| Fuite via les logs HTTP | Le client `httpx` est créé sans `logger` applicatif ; aucune trace du corps ou des en-têtes d'authentification. |

## Signaler une vulnérabilité

Ouvrez une *issue* privée (Security Advisory) sur le dépôt GitHub du projet, ou écrivez à
l'adresse configurée dans `VULNLENS_CONTACT`. Merci de ne pas publier de preuve
d'exploitation avant correction.
