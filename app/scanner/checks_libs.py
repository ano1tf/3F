"""Bibliothèques JavaScript obsolètes : versions à vulnérabilités connues.

Contrôle 100 % passif : on lit ce que le site sert déjà (HTML des pages et scripts
publics téléchargés par le contrôle « secrets ») et on compare la version détectée
à une table de versions corrigées. Aucune exploitation, aucune requête vers un
service tiers.

La sortie est alignée sur le reste du rapport : sévérité, preuve, remédiation,
référence et niveau de confiance (une version lue dans un nom de fichier est
certaine, une version devinée dans un bundle est « probable »).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Finding, Severity

CATEGORY = "Dépendances front-end"


@dataclass(frozen=True)
class Issue:
    """Version corrigée et conséquence d'une version antérieure."""

    below: tuple[int, ...]
    severity: Severity
    title: str
    cve: str
    description: str
    remediation: str
    reference: str


@dataclass(frozen=True)
class Library:
    key: str
    name: str
    marker: str
    issues: tuple[Issue, ...]

    @property
    def pattern(self) -> re.Pattern[str]:
        # On capture la première version qui suit le nom de la bibliothèque, en
        # tolérant les formes usuelles : `jquery-3.4.1`, `jquery.min.js?v=3.4.1`,
        # `jquery@3.4.1`, `jQuery v3.4.1`.
        return re.compile(
            rf"{self.marker}[^\s\"'<>()]{{0,80}}?(?:v=)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE
        )


JQUERY_REF = "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"

LIBRARIES: tuple[Library, ...] = (
    Library(
        key="jquery",
        name="jQuery",
        marker=r"jquery(?![-_.]?ui)",
        issues=(
            Issue(
                below=(3, 5, 0),
                severity=Severity.HIGH,
                title="jQuery {version} : XSS et pollution de prototype",
                cve="CVE-2019-11358, CVE-2020-11022, CVE-2020-11023",
                description=(
                    "Cette version de jQuery est vulnérable à la pollution de prototype "
                    "(`$.extend(true, …)`) et à des XSS lors du passage de HTML à des méthodes "
                    "comme `.html()` ou `$(…)`. Un contenu contrôlé par un attaquant (commentaire, "
                    "nom de profil, paramètre d'URL) peut alors exécuter du script dans le "
                    "navigateur des visiteurs authentifiés."
                ),
                remediation=(
                    "Mettez à jour vers jQuery ≥ 3.5.0 (idéalement la dernière version 3.x) ou "
                    "supprimez la dépendance si elle n'est plus nécessaire. Vérifiez aussi les "
                    "greffons jQuery UI, souvent bloqués sur d'anciennes versions."
                ),
                reference=JQUERY_REF,
            ),
        ),
    ),
    Library(
        key="jquery-ui",
        name="jQuery UI",
        marker=r"jquery[-_.]?ui",
        issues=(
            Issue(
                below=(1, 13, 2),
                severity=Severity.MEDIUM,
                title="jQuery UI {version} : XSS dans le composant tooltip",
                cve="CVE-2022-31160",
                description=(
                    "Le composant `tooltip` de jQuery UI échappe insuffisamment le contenu : "
                    "un attribut piégé peut exécuter du script dans la page."
                ),
                remediation="Mettez à jour vers jQuery UI ≥ 1.13.2.",
                reference="https://github.com/jquery/jquery-ui/security/advisories/GHSA-h6gj-6jjq-h8g9",
            ),
        ),
    ),
    Library(
        key="bootstrap3",
        name="Bootstrap",
        marker=r"bootstrap(?![-_.](?:datepicker|select|switch|table|validator|tagsinput|datetimepicker|markdown|wysihtml|tour|sweetalert))",
        issues=(
            Issue(
                below=(3, 4, 1),
                severity=Severity.HIGH,
                title="Bootstrap {version} : XSS via tooltip et popover",
                cve="CVE-2019-8331",
                description=(
                    "Les composants `tooltip`, `popover` et `data-target` de Bootstrap 3 "
                    "n'échappent pas correctement les attributs : un contenu contrôlé par "
                    "l'utilisateur peut y injecter du script."
                ),
                remediation="Mettez à jour vers Bootstrap ≥ 3.4.1 (ou migrez vers Bootstrap 5).",
                reference="https://blog.getbootstrap.com/2019/02/13/bootstrap-4-3-1-and-3-4-1/",
            ),
            Issue(
                below=(4, 3, 1),
                severity=Severity.MEDIUM,
                title="Bootstrap {version} : XSS via tooltip et popover",
                cve="CVE-2019-8331",
                description=(
                    "Cette version 4.x de Bootstrap est antérieure au correctif d'échappement "
                    "des attributs de tooltip et popover."
                ),
                remediation="Mettez à jour vers Bootstrap ≥ 4.3.1 (ou Bootstrap 5).",
                reference="https://blog.getbootstrap.com/2019/02/13/bootstrap-4-3-1-and-3-4-1/",
            ),
        ),
    ),
    Library(
        key="angularjs",
        name="AngularJS",
        marker=r"angular(?:\.min)?(?![-_.]?(?:router|ui|material|moment|sanitize))",
        issues=(
            Issue(
                below=(1, 8, 3),
                severity=Severity.HIGH,
                title="AngularJS {version} : XSS et fin de vie",
                cve="CVE-2020-7676, CVE-2019-14863",
                description=(
                    "Cette version d'AngularJS (1.x) est vulnérable à des XSS connues et la "
                    "branche n'est plus maintenue depuis décembre 2021 : aucune correction ne "
                    "sera publiée."
                ),
                remediation=(
                    "Migrez vers Angular (2+) ou un framework maintenu ; à défaut, isolez les "
                    "zones AngularJS et appliquez CSP + validation stricte."
                ),
                reference="https://docs.angularjs.org/misc/version-support-status",
            ),
            Issue(
                below=(2, 0, 0),
                severity=Severity.LOW,
                title="AngularJS {version} : branche en fin de vie",
                cve="—",
                description=(
                    "AngularJS 1.x n'est plus maintenu : plus de correctifs de sécurité depuis "
                    "décembre 2021, même sur la dernière version."
                ),
                remediation="Planifiez la migration vers Angular 2+ ou un framework maintenu.",
                reference="https://docs.angularjs.org/misc/version-support-status",
            ),
        ),
    ),
    Library(
        key="handlebars",
        name="Handlebars",
        marker=r"handlebars",
        issues=(
            Issue(
                below=(4, 7, 7),
                severity=Severity.CRITICAL,
                title="Handlebars {version} : exécution de code à distance",
                cve="CVE-2021-23369, CVE-2019-19919",
                description=(
                    "Le moteur de gabarits permet l'exécution de code arbitraire lorsqu'un "
                    "gabarit ou un contexte provient d'une source non fiable : un contenu "
                    "utilisateur peut aboutir à une exécution JavaScript dans le navigateur."
                ),
                remediation="Mettez à jour vers Handlebars ≥ 4.7.7 et ne compilez jamais de gabarit non fiable.",
                reference="https://github.com/handlebars-lang/handlebars.js/security/advisories",
            ),
        ),
    ),
    Library(
        key="lodash",
        name="Lodash",
        marker=r"lodash",
        issues=(
            Issue(
                below=(4, 17, 21),
                severity=Severity.HIGH,
                title="Lodash {version} : injection de commande et pollution de prototype",
                cve="CVE-2021-23337, CVE-2020-8203",
                description=(
                    "`_.template` permet l'injection de commande et `_.zipObjectDeep` la "
                    "pollution de prototype, deux chemins d'escalade classiques vers un XSS "
                    "ou une exécution de code."
                ),
                remediation="Mettez à jour vers Lodash ≥ 4.17.21 et évitez `_.template` sur des entrées non fiables.",
                reference="https://github.com/lodash/lodash/security/advisories",
            ),
        ),
    ),
    Library(
        key="underscore",
        name="Underscore.js",
        marker=r"underscore",
        issues=(
            Issue(
                below=(1, 13, 1),
                severity=Severity.HIGH,
                title="Underscore {version} : injection de code via template",
                cve="CVE-2021-23358",
                description=(
                    "La fonction `template` autorise l'exécution de code arbitraire lorsque le "
                    "gabarit provient d'une source non fiable."
                ),
                remediation="Mettez à jour vers Underscore ≥ 1.13.1.",
                reference="https://github.com/jashkenas/underscore/security/advisories",
            ),
        ),
    ),
    Library(
        key="moment",
        name="Moment.js",
        marker=r"moment(?:\.min)?(?![-_.]?timezone)",
        issues=(
            Issue(
                below=(2, 29, 4),
                severity=Severity.MEDIUM,
                title="Moment.js {version} : déni de service par expression régulière",
                cve="CVE-2022-31129, CVE-2022-24785",
                description=(
                    "Le parseur de chaînes de date accepte des entrées entraînant un ReDoS "
                    "(consommation CPU), et le chargeur de locales est vulnérable à un "
                    "chemin non maîtrisé."
                ),
                remediation=(
                    "Mettez à jour vers Moment ≥ 2.29.4 ; le projet est en maintenance, une "
                    "migration vers `date-fns`, `Luxon` ou `Temporal` est recommandée."
                ),
                reference="https://github.com/moment/moment/security/advisories",
            ),
        ),
    ),
    Library(
        key="dompurify",
        name="DOMPurify",
        marker=r"(?:dompurify|purify)(?:\.min)?",
        issues=(
            Issue(
                below=(2, 4, 0),
                severity=Severity.HIGH,
                title="DOMPurify {version} : contournement d'assainissement (mXSS)",
                cve="CVE-2022-36067",
                description=(
                    "L'assainisseur peut être contourné par mutation du DOM : du HTML "
                    "supposé nettoyé réintroduit finalement un vecteur XSS."
                ),
                remediation="Mettez à jour vers DOMPurify ≥ 2.4.0 (idéalement la version courante).",
                reference="https://github.com/cure53/DOMPurify/security/advisories/GHSA-9mb5-7mgv-9w5j",
            ),
        ),
    ),
    Library(
        key="crypto-js",
        name="CryptoJS",
        marker=r"crypto[-_.]?js",
        issues=(
            Issue(
                below=(4, 2, 0),
                severity=Severity.HIGH,
                title="CryptoJS {version} : dérivation de clé affaiblie",
                cve="CVE-2023-46233",
                description=(
                    "`PBKDF2` utilise un nombre d'itérations insuffisant et un HMAC-SHA1 : les "
                    "mots de passe dérivés côté navigateur sont plus faciles à casser hors ligne."
                ),
                remediation="Mettez à jour vers CryptoJS ≥ 4.2.0 et dérivez les mots de passe côté serveur.",
                reference="https://github.com/brix/crypto-js/security/advisories/GHSA-xwcq-pm8m-c4vf",
            ),
        ),
    ),
    Library(
        key="axios",
        name="Axios",
        marker=r"axios(?:\.min)?",
        issues=(
            Issue(
                below=(1, 6, 0),
                severity=Severity.MEDIUM,
                title="Axios {version} : fuite de jeton via XSRF",
                cve="CVE-2023-45857",
                description=(
                    "Le jeton `XSRF-TOKEN` peut être envoyé vers un domaine tiers lorsque "
                    "l'application appelle une URL absolue fournie par un utilisateur."
                ),
                remediation="Mettez à jour vers Axios ≥ 1.6.0.",
                reference="https://github.com/axios/axios/security/advisories/GHSA-wf5p-g6vw-rhxx",
            ),
        ),
    ),
    Library(
        key="vue2",
        name="Vue.js",
        marker=r"\bvue(?:\.runtime)?(?:\.min)?(?![-_.]?(?:router|x|cli|loader|test))",
        issues=(
            Issue(
                below=(3, 0, 0),
                severity=Severity.LOW,
                title="Vue {version} : branche 2.x en fin de vie",
                cve="—",
                description=(
                    "Vue 2 n'est plus maintenu depuis le 31 décembre 2023 : plus de correctifs "
                    "de sécurité pour cette branche."
                ),
                remediation="Migrez vers Vue 3 (ou utilisez la version 2.7 pendant la transition).",
                reference="https://v2.vuejs.org/eol/",
            ),
        ),
    ),
)


def parse_version(value: str) -> tuple[int, ...]:
    parts = [int(chunk) for chunk in re.findall(r"\d+", value)[:4]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _applicable(library: Library, version: tuple[int, ...]) -> Issue | None:
    """Retient l'atteinte la plus grave compatible avec la version détectée."""
    matches = [issue for issue in library.issues if version < issue.below]
    if not matches:
        return None
    return sorted(matches, key=lambda issue: (issue.severity.rank, issue.below))[0]


def _normalise(text: str) -> str:
    return text or ""


def detect_libraries(
    pages: list[tuple[str, str]],
    scripts: list[tuple[str, str]],
) -> tuple[list[Finding], dict[str, str]]:
    """Compare les bibliothèques détectées à la table des versions corrigées.

    :param pages: liste de (url de page, HTML).
    :param scripts: liste de (url de script, contenu téléchargé).
    :returns: constats + métadonnées d'empreinte (bibliothèques vues).
    """
    detected: dict[str, tuple[tuple[int, ...], str, bool]] = {}

    for label, text in scripts:
        for library in LIBRARIES:
            if library.key in detected:
                continue
            # Priorité au nom de fichier : la version y est explicite.
            for candidate, certain in ((label, True), (_normalise(text), False)):
                match = library.pattern.search(candidate)
                if match:
                    detected[library.key] = (parse_version(match.group(1)), label, certain)
                    break

    for label, html in pages:
        for library in LIBRARIES:
            if library.key in detected:
                continue
            match = library.pattern.search(_normalise(html))
            if match:
                detected[library.key] = (parse_version(match.group(1)), label, False)

    findings: list[Finding] = []
    seen: list[str] = []
    for library in LIBRARIES:
        entry = detected.get(library.key)
        if entry is None:
            continue
        version, source, certain = entry
        seen.append(f"{library.name} {'.'.join(str(part) for part in version)}")
        issue = _applicable(library, version)
        if issue is None:
            continue
        readable = ".".join(str(part) for part in version)
        fixed = ".".join(str(part) for part in issue.below)
        findings.append(
            Finding(
                id=f"libs.{library.key}",
                title=issue.title.format(version=readable),
                severity=issue.severity,
                category=CATEGORY,
                description=issue.description,
                evidence=(
                    f"{library.name} {readable} détecté dans {source}\n"
                    f"Version corrigée : {fixed} ou ultérieure\n"
                    f"Références : {issue.cve}"
                ),
                remediation=issue.remediation,
                reference=issue.reference,
                confidence="certain" if certain else "probable",
            )
        )

    meta: dict[str, str] = {}
    if seen:
        meta["bibliotheques"] = ", ".join(seen[:6])
    return findings, meta
