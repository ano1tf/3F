"""Contrôle d'accès : IDOR, paramètres manipulables, surface d'administration.

Tout est **passif**. On ne rejoue jamais l'identifiant d'un autre utilisateur, on
n'incrémente aucun identifiant, on ne forge aucun rôle : on observe seulement ce
que le site publie déjà (URLs explorées, formulaires, scripts) pour signaler les
endroits où l'autorisation *doit* être vérifiée côté serveur.

Conséquence assumée : un constat IDOR est **« à confirmer »**. Confirmer
demanderait deux comptes et une requête croisée — ce que l'outil s'interdit.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from ..models import Finding, Severity

CATEGORY = "Contrôle d'accès"

REF_IDOR = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_"
    "Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"
)
REF_API1 = "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
REF_MASS = "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"

# Paramètres qui désignent un objet métier : c'est le terrain de l'IDOR.
OBJECT_PARAMS = {
    "id",
    "uid",
    "user",
    "userid",
    "user_id",
    "account",
    "accountid",
    "account_id",
    "customer",
    "customer_id",
    "client",
    "client_id",
    "order",
    "orderid",
    "order_id",
    "commande",
    "commande_id",
    "invoice",
    "invoiceid",
    "invoice_id",
    "facture",
    "facture_id",
    "doc",
    "doc_id",
    "document",
    "document_id",
    "file",
    "file_id",
    "fichier",
    "fichier_id",
    "tenant",
    "tenant_id",
    "org",
    "org_id",
    "organisation_id",
    "profile",
    "profile_id",
    "profil_id",
    "ticket",
    "ticket_id",
    "project",
    "project_id",
    "projet_id",
    "member_id",
    "member",
}

# Paramètres qui pilotent un privilège ou un mode interne depuis l'URL.
CONTROL_PARAMS = {
    "admin",
    "is_admin",
    "isadmin",
    "role",
    "roles",
    "debug",
    "test",
    "internal",
    "permission",
    "permissions",
    "access",
    "access_level",
    "scope",
    "impersonate",
    "as_user",
    "sudo",
    "superuser",
    "staff",
}

# Paramètres qui désignent un chemin ou une ressource côté serveur.
PATH_PARAMS = {
    "file",
    "filename",
    "filepath",
    "path",
    "dir",
    "folder",
    "template",
    "include",
    "page",
    "download",
    "doc",
    "document",
    "url",
    "uri",
    "redirect",
    "return",
    "next",
    "dest",
    "target",
    "continue",
}

# Segment d'URL qui introduit un objet (`/users/42`, `/factures/1024`).
OBJECT_SEGMENTS = {
    "user", "users", "utilisateur", "utilisateurs", "compte", "comptes",
    "account", "accounts", "client", "clients", "customer", "customers",
    "order", "orders", "commande", "commandes", "invoice", "invoices",
    "facture", "factures", "document", "documents", "fichier", "fichiers",
    "file", "files", "ticket", "tickets", "project", "projects", "projet",
    "projets", "profile", "profiles", "profil", "profils", "member", "members",
    "membre", "membres", "tenant", "tenants", "org", "organisation",
    "organization", "entreprise",
}  # fmt: skip

ID_VALUE = re.compile(
    r"^(?:\d{1,12}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)

# Endpoints d'administration référencés dans du contenu public.
ADMIN_ENDPOINT = re.compile(
    r"""["'`(]((?:https?://[^"'`\s]+)?/(?:admin|administrator|backoffice|back-office|internal|"""
    r"""intranet|staff|manage|management|superuser|console|_internal|private)(?:/[A-Za-z0-9_.\-]{0,40})*)["'`)]""",
    re.IGNORECASE,
)

# Liens publiés par les pages : on les lit sans jamais les ouvrir (mode rapide).
ANCHOR = re.compile(r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

MAX_EVIDENCE = 6


def _is_object_id(value: str) -> bool:
    return bool(ID_VALUE.match(value.strip()))


def _template(url: str) -> str:
    """URL avec ses identifiants remplacés, pour repérer plusieurs objets du même type."""
    parts = urlsplit(url)
    segments = ["{id}" if _is_object_id(seg) else seg for seg in parts.path.split("/") if seg]
    path = "/".join(segments)
    return f"{parts.netloc}/{path}" if path else parts.netloc


def _query_hits(url: str) -> dict[str, list[str]]:
    """Classe les paramètres d'URL : objets, privilèges, chemins."""
    hits: dict[str, list[str]] = {"object": [], "control": [], "path": []}
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        lowered = name.lower()
        if lowered in OBJECT_PARAMS and _is_object_id(value):
            hits["object"].append(f"{name}={value}")
        elif lowered in CONTROL_PARAMS:
            hits["control"].append(f"{name}={value}")
        elif lowered in PATH_PARAMS:
            hits["path"].append(f"{name}={value}")
    return hits


def _path_object_hits(url: str) -> list[str]:
    """`/users/42/edit` : segment objet suivi d'un identifiant."""
    segments = [seg for seg in urlsplit(url).path.split("/") if seg]
    hits: list[str] = []
    for previous, current in zip(segments, segments[1:], strict=False):
        if previous.lower() in OBJECT_SEGMENTS and _is_object_id(current):
            hits.append(f"/{previous}/{current}")
    return hits


def _form_hidden_hits(html: str) -> list[str]:
    """Champs cachés qui transportent l'identifiant d'un objet (mass assignment)."""
    names = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', html or "", re.IGNORECASE)
    hits: list[str] = []
    for tag in names:
        match = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if match and match.group(1).lower() in OBJECT_PARAMS:
            hits.append(f'<input type="hidden" name="{match.group(1)}">')
    return hits


def _reflected(html: str, value: str) -> bool:
    return len(value) >= 5 and value.isascii() and value.isalnum() and value in (html or "")


def _linked_urls(pages: list[tuple[str, str]]) -> list[str]:
    """URLs internes citées par les pages, sans requête réseau supplémentaire."""
    seen: set[str] = set()
    urls: list[str] = []
    for url, html in pages:
        host = urlsplit(url).netloc
        for href in ANCHOR.findall(html or ""):
            absolute = urljoin(url, href.strip())
            parts = urlsplit(absolute)
            if parts.scheme not in ("http", "https") or parts.netloc != host:
                continue
            if absolute not in seen:
                seen.add(absolute)
                urls.append(absolute)
    return urls


def inspect(pages: list[tuple[str, str]], scripts: list[tuple[str, str]] | None = None) -> list[Finding]:
    """Analyse les URLs explorées, les liens publiés, les formulaires et les scripts."""
    # Les liens ne sont pas ouverts : ils servent seulement à repérer les formes d'URL.
    observed = [(url, html) for url, html in pages] + [
        (url, "") for url in _linked_urls(pages) if url not in {page for page, _ in pages}
    ]

    object_ids: dict[str, set[str]] = {}
    control_hits: dict[str, set[str]] = {}
    path_hits: dict[str, set[str]] = {}
    hidden_hits: set[str] = set()
    reflected: set[str] = set()
    admin_endpoints: set[str] = set()

    for url, html in observed:
        for hit in _path_object_hits(url):
            object_ids.setdefault(_template(url), set()).add(hit)
        for kind, values in _query_hits(url).items():
            if not values:
                continue
            if kind == "object":
                object_ids.setdefault(_template(url), set()).update(values)
            elif kind == "control":
                control_hits.setdefault(urlsplit(url).path or "/", set()).update(values)
            else:
                path_hits.setdefault(urlsplit(url).path or "/", set()).update(values)
        hidden_hits.update(_form_hidden_hits(html))
        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if _reflected(html, value):
                reflected.add(f"{urlsplit(url).path or '/'}?{name}")

    for _source, text in scripts or []:
        for match in ADMIN_ENDPOINT.finditer(text or ""):
            endpoint = match.group(1)
            if "://" in endpoint:
                endpoint = urlsplit(endpoint).path
            admin_endpoints.add(endpoint[:80])

    findings: list[Finding] = []

    if object_ids:
        samples = []
        for template, hits in list(object_ids.items())[:MAX_EVIDENCE]:
            samples.append(f"  · {template} → {' , '.join(sorted(hits)[:3])}")
        total = sum(len(hits) for hits in object_ids.values())
        findings.append(
            Finding(
                id="access.idor-object-id",
                title="Identifiants d'objets exposés dans les URL (IDOR probable)",
                severity=Severity.HIGH,
                category=CATEGORY,
                description=(
                    "Les pages manipulent des identifiants d'objets lisibles (`/users/42`, "
                    "`?facture_id=1024`). Si le serveur ne vérifie pas, pour chaque requête, que "
                    "l'objet appartient bien à l'utilisateur connecté, il suffit de changer le "
                    "nombre pour lire ou modifier les données d'un autre compte (IDOR / BOLA). "
                    "C'est l'une des failles les plus fréquentes des API et des espaces clients."
                ),
                evidence=(
                    f"{total} identifiant(s) d'objet observé(s) dans {len(object_ids)} vue(s) :\n"
                    + "\n".join(samples)
                    + "\n\nAucun identifiant n'a été modifié, rejoué ni ouvert : ces URL "
                    "proviennent des pages analysées et des liens qu'elles publient. La "
                    "confirmation demande deux comptes de test (voir la remédiation)."
                ),
                remediation=(
                    "Vérifiez l'autorisation **côté serveur, objet par objet** "
                    "(l'objet appartient-il au principal authentifié ?), jamais côté client. "
                    "Utilisez des identifiants non devinables (UUID v4) plutôt que des séquences, "
                    "journalisez les refus et testez chaque route avec deux comptes distincts."
                ),
                reference=REF_IDOR,
                confidence="a-confirmer",
            )
        )

    if hidden_hits:
        findings.append(
            Finding(
                id="access.hidden-object-id",
                title="Identifiant d'objet dans un champ caché de formulaire",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description=(
                    "Un formulaire transporte l'identifiant d'un objet dans un champ `hidden`. "
                    "Ces valeurs sont modifiables en une seconde depuis les outils du navigateur : "
                    "si le serveur s'y fie sans vérifier les droits, un utilisateur peut agir sur "
                    "les données d'un autre (ou s'attribuer un rôle, mass assignment)."
                ),
                evidence="Champs observés :\n" + "\n".join(f"  · {hit}" for hit in sorted(hidden_hits)),
                remediation=(
                    "Déduisez l'identité et les droits de la session côté serveur, jamais d'un champ "
                    "caché. N'acceptez en écriture que les champs explicitement autorisés "
                    "(`DTO`/liste blanche) et rejetez tout champ inattendu."
                ),
                reference=REF_MASS,
                confidence="a-confirmer",
            )
        )

    if control_hits:
        details = [
            f"  · {path} → {' , '.join(sorted(values)[:3])}"
            for path, values in list(control_hits.items())[:MAX_EVIDENCE]
        ]
        findings.append(
            Finding(
                id="access.parameter-control",
                title="Paramètre de privilège pilotable depuis l'URL",
                severity=Severity.HIGH,
                category=CATEGORY,
                description=(
                    "Des paramètres nommés `admin`, `role`, `debug`, `internal` ou `impersonate` "
                    "apparaissent dans les URL publiques. S'ils sont interprétés par le serveur, "
                    "un simple changement de valeur suffit à élever ses droits ou à activer un "
                    "mode de débogage — un classique des back-offices bricolés."
                ),
                evidence="Paramètres observés :\n" + "\n".join(details),
                remediation=(
                    "N'acceptez jamais un rôle ou un privilège depuis la requête cliente : "
                    "lisez-le en base à partir de la session. Refusez explicitement les paramètres "
                    "inconnus et désactivez tout mode debug en production."
                ),
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
                confidence="a-confirmer",
            )
        )

    if path_hits:
        details = [
            f"  · {path} → {' , '.join(sorted(values)[:3])}"
            for path, values in list(path_hits.items())[:MAX_EVIDENCE]
        ]
        findings.append(
            Finding(
                id="access.path-parameter",
                title="Paramètre de chemin ou d'URL contrôlable",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description=(
                    "Des paramètres de type `file`, `path`, `page`, `template`, `url` ou `redirect` "
                    "sont exposés. S'ils ne sont pas validés par une liste blanche, ils ouvrent la "
                    "voie à une lecture de fichier arbitraire (traversée de répertoire) ou à une "
                    "redirection vers un domaine tiers."
                ),
                evidence="Paramètres observés :\n" + "\n".join(details),
                remediation=(
                    "Validez chaque valeur contre une liste blanche stricte (identifiant de gabarit, "
                    "chemin relatif connu), refusez `..`, les chemins absolus et les URL externes, "
                    "et servez les fichiers via une couche qui vérifie les droits."
                ),
                reference=(
                    "https://owasp.org/www-community/attacks/Path_Traversal"
                ),
                confidence="a-confirmer",
            )
        )

    if reflected:
        findings.append(
            Finding(
                id="access.reflected-parameter",
                title="Paramètre d'URL reflété tel quel dans la page",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description=(
                    "La valeur d'un paramètre d'URL est recopiée telle quelle dans le HTML. "
                    "Si elle n'est pas échappée selon le contexte d'insertion, un lien piégé suffit "
                    "à exécuter du script chez la victime (XSS réfléchi), avec accès à sa session."
                ),
                evidence=(
                    "Paramètres reflétés :\n"
                    + "\n".join(f"  · {item}" for item in sorted(reflected)[:MAX_EVIDENCE])
                    + "\n\nAucune charge n'a été envoyée : seule la réflexion d'une valeur déjà "
                    "présente dans l'URL a été observée."
                ),
                remediation=(
                    "Échappez chaque variable selon son contexte (HTML, attribut, JavaScript, URL) "
                    "et ajoutez une CSP sans `unsafe-inline`. Testez avec des caractères "
                    "`<`, `>`, `\"`, `'` dans chaque paramètre reflété."
                ),
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                confidence="a-confirmer",
            )
        )

    if admin_endpoints:
        findings.append(
            Finding(
                id="access.sensitive-endpoint",
                title="Endpoints d'administration référencés dans du contenu public",
                severity=Severity.LOW,
                category=CATEGORY,
                description=(
                    "Les scripts publics citent des chemins d'administration ou internes. Ils "
                    "donnent la carte des interfaces sensibles : vérifiez qu'elles exigent bien "
                    "une authentification et un rôle, et qu'elles ne sont pas seulement masquées "
                    "côté interface."
                ),
                evidence="Chemins cités :\n"
                + "\n".join(f"  · {item}" for item in sorted(admin_endpoints)[:MAX_EVIDENCE]),
                remediation=(
                    "Protégez ces routes côté serveur (authentification + contrôle de rôle), "
                    "journalisez les accès et ne comptez pas sur le fait qu'elles soient peu connues."
                ),
                reference="https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                confidence="certain",
            )
        )

    return findings
