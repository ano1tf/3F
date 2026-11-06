"""Les spécialistes : un domaine chacun, un raisonnement explicite.

Chaque agent transforme des **preuves observées** en **hypothèses d'attaque**
datées d'une technique MITRE, d'un niveau de confiance et de la vérification
manuelle non destructive correspondante.

Convention de nommage des hypothèses : `<agent>:<sujet>:<cible>`.
"""

from __future__ import annotations

from collections.abc import Iterable

from .base import Agent, Blackboard, Hypothesis

SEVERITY_CONFIDENCE = {
    "critical": 0.85,
    "high": 0.72,
    "medium": 0.55,
    "low": 0.4,
    "info": 0.25,
}


def _confidence(finding: dict, bonus: float = 0.0) -> float:
    """Confiance de base : la sévérité donne l'ordre de grandeur, la certitude affine."""
    base = SEVERITY_CONFIDENCE.get(str(finding.get("severity", "info")), 0.3)
    certainty = finding.get("confidence", "certain")
    if certainty == "probable":
        base -= 0.08
    elif certainty == "a-confirmer":
        base -= 0.15
    return max(0.15, min(0.95, base + bonus))


def _evidence(*ids: str) -> list[str]:
    return [item for item in ids if item]


class ReconAgent(Agent):
    """Cartographie : ce que l'attaquant apprend sans rien forcer."""

    name = "recon"
    role = "Éclaireur — cartographie de la surface"
    domain = "reconnaissance"

    def analyse(self, board: Blackboard) -> Iterable[Hypothesis]:
        out: list[Hypothesis] = []

        versions = board.with_prefix("headers.version-disclosure", "content.generator-version")
        if versions:
            finding = versions[0]
            out.append(
                Hypothesis(
                    id="recon:version:stack",
                    claim="La pile serveur est identifiée : les CVE de cette version deviennent un mode d'entrée.",
                    asset="Serveurs et accès système",
                    stage="recon",
                    confidence=_confidence(finding),
                    evidence=[finding["id"]],
                    techniques=["T1592.002", "T1190"],
                    verification=(
                        "Relever les en-têtes et le générateur, puis comparer la version aux avis de "
                        "sécurité de l'éditeur (aucune sonde d'exploitation n'est nécessaire)."
                    ),
                    agent=self.name,
                    rationale="Une version exacte transforme une recherche générique en liste d'exploits applicables.",
                )
            )

        traces = board.with_prefix("errors.stack-trace")
        if traces:
            finding = traces[0]
            out.append(
                Hypothesis(
                    id="recon:trace:paths",
                    claim="Les traces d'erreur livrent des chemins, frameworks et requêtes : la carte interne du code.",
                    asset="Code source et historique Git",
                    stage="recon",
                    confidence=_confidence(finding),
                    evidence=[finding["id"]],
                    techniques=["T1592", "T1005"],
                    verification=(
                        "Provoquer une erreur sur une URL inexistante et lire la réponse : aucun "
                        "formulaire n'est soumis, aucune donnée n'est modifiée."
                    ),
                    agent=self.name,
                )
            )

        robots = board.with_prefix("robots.disclosure")
        if robots:
            finding = robots[0]
            out.append(
                Hypothesis(
                    id="recon:robots:endpoints",
                    claim="Le robots.txt énumère les zones à ne pas indexer — donc à regarder en premier.",
                    asset="Console d'administration",
                    stage="recon",
                    confidence=_confidence(finding, 0.05),
                    evidence=[finding["id"]],
                    techniques=["T1590.005"],
                    verification="Lire /robots.txt puis vérifier manuellement que chaque chemin listé exige une authentification.",
                    agent=self.name,
                )
            )

        schemas = board.with_prefix("exposure.openapi", "exposure.swagger", "exposure.graphql", "exposure.graphiql")
        if schemas:
            finding = schemas[0]
            out.append(
                Hypothesis(
                    id="recon:schema:api",
                    claim="Un schéma d'API est public : chaque route devient une cible documentée.",
                    asset="Comptes utilisateurs",
                    stage="recon",
                    confidence=_confidence(finding),
                    evidence=[item["id"] for item in schemas],
                    techniques=["T1595.002"],
                    verification="Télécharger le schéma et lister les routes sensibles ; les tester une par une avec deux comptes de test.",
                    agent=self.name,
                )
            )
        return out

    def review(self, board: Blackboard) -> list[Hypothesis]:
        # Une pile identifiée crédibilise les hypothèses d'accès aux serveurs.
        if board.has("headers.version-disclosure", "content.generator-version"):
            for hypothesis in board.hypotheses:
                if hypothesis.asset in {"Serveurs et accès système", "Infrastructure cloud"}:
                    board.adjust(hypothesis.id, 0.05, "pile logicielle identifiée", self.name)
        return []


class ExposureAgent(Agent):
    """Ce qui traîne à la racine : fichiers, sauvegardes, configuration."""

    name = "exposure"
    role = "Fouilleur — fichiers exposés"
    domain = "exposition"

    def analyse(self, board: Blackboard) -> Iterable[Hypothesis]:
        out: list[Hypothesis] = []

        git = board.with_prefix("exposure.git")
        if git:
            out.append(
                Hypothesis(
                    id="exposure:source:git",
                    claim="Le dépôt Git est récupérable : tout l'historique du code et ses secrets partent avec.",
                    asset="Code source et historique Git",
                    stage="access",
                    confidence=_confidence(git[0], 0.05),
                    evidence=[item["id"] for item in git],
                    techniques=["T1213.003", "T1552.001"],
                    verification=(
                        "Télécharger un objet inoffensif (.git/HEAD) pour prouver l'exposition ; "
                        "ne jamais reconstruire le dépôt complet sur une cible de production."
                    ),
                    agent=self.name,
                )
            )
            out.append(
                Hypothesis(
                    id="exposure:secrets:history",
                    claim="Les secrets d'hier (clés, mots de passe) restent dans l'historique Git.",
                    asset="Secrets de configuration",
                    stage="exfiltration",
                    confidence=0.7,
                    evidence=[item["id"] for item in git],
                    techniques=["T1552.001", "T1078"],
                    verification="Après accord du client, extraire l'historique hors ligne et faire tourner les secrets trouvés.",
                    agent=self.name,
                )
            )

        env = board.with_prefix("exposure.dotenv", "exposure.database-config", "exposure.htpasswd")
        if env:
            out.append(
                Hypothesis(
                    id="exposure:config:credentials",
                    claim="La configuration applicative est publique : identifiants de base et clés d'API en clair.",
                    asset="Base de données",
                    stage="access",
                    confidence=_confidence(env[0], 0.05),
                    evidence=[item["id"] for item in env],
                    techniques=["T1552.001", "T1078"],
                    verification="Lire le fichier pour constater l'exposition, puis tester la connexion depuis un poste autorisé uniquement.",
                    agent=self.name,
                )
            )

        infra = board.with_prefix("exposure.terraform-state", "exposure.ssh-private-key", "exposure.gcp-service-account")
        if infra:
            out.append(
                Hypothesis(
                    id="exposure:infra:takeover",
                    claim="Un état Terraform ou une clé privée traîne en ligne : l'infrastructure devient pilotable.",
                    asset="Infrastructure cloud",
                    stage="escalation",
                    confidence=_confidence(infra[0], 0.05),
                    evidence=[item["id"] for item in infra],
                    techniques=["T1552.004", "T1078.004"],
                    verification=(
                        "Vérifier l'exposition et si le secret est encore actif (date de création côté "
                        "fournisseur). Aucune action sur l'infrastructure n'est lancée par l'outil."
                    ),
                    agent=self.name,
                )
            )

        listing = board.with_prefix("exposure.directory-listing")
        if listing:
            out.append(
                Hypothesis(
                    id="exposure:listing:enumeration",
                    claim="Un listing de répertoire ouvre l'énumération : sauvegardes, exports, fichiers oubliés.",
                    asset="Données personnelles",
                    stage="recon",
                    confidence=_confidence(listing[0]),
                    evidence=[item["id"] for item in listing],
                    techniques=["T1083"],
                    verification="Parcourir l'index et signaler les fichiers sensibles, sans télécharger de données personnelles.",
                    agent=self.name,
                )
            )
        return out


class CredentialAgent(Agent):
    """Tout ce qui mène à un compte : clés, jetons, cookies, sessions."""

    name = "credentials"
    role = "Spécialiste identités — clés, jetons, sessions"
    domain = "identité"

    def analyse(self, board: Blackboard) -> Iterable[Hypothesis]:
        out: list[Hypothesis] = []

        alg_none = board.with_prefix("secrets.jwt-alg-none")
        if alg_none:
            out.append(
                Hypothesis(
                    id="credentials:jwt:forge",
                    claim="Le JWT n'est pas signé (alg: none) : n'importe qui forge un jeton valide.",
                    asset="Comptes utilisateurs",
                    stage="access",
                    confidence=0.9,
                    evidence=[item["id"] for item in alg_none],
                    techniques=["T1550.001", "T1078"],
                    verification=(
                        "Décoder le jeton public, puis vérifier côté serveur qu'une signature absente est "
                        "refusée (test avec un jeton volontairement invalide, jamais avec un jeton usurpé)."
                    ),
                    agent=self.name,
                    rationale="Sans vérification de signature, l'identité déclarée devient l'identité réelle.",
                )
            )

        privileged = board.with_prefix("secrets.jwt-privileged")
        if privileged:
            out.append(
                Hypothesis(
                    id="credentials:jwt:claims",
                    claim="Le jeton porte des revendications de rôle lisibles : l'élévation se tente en modifiant le payload.",
                    asset="Console d'administration",
                    stage="escalation",
                    confidence=0.75,
                    evidence=[item["id"] for item in privileged],
                    techniques=["T1550.001", "T1068"],
                    verification="Vérifier que le rôle est relu en base à chaque requête et non depuis le jeton.",
                    agent=self.name,
                )
            )

        tokens = board.with_prefix(
            "secrets.", "exposure.git-credentials", "secrets.basic-auth-url"
        )
        if tokens:
            relevant = [item for item in tokens if item["severity"] in {"critical", "high"}]
            if relevant:
                out.append(
                    Hypothesis(
                        id="credentials:keys:abuse",
                        claim="Des clés d'API sont publiées dans le contenu livré au navigateur : elles fonctionnent encore.",
                        asset="Intégrations SaaS",
                        stage="access",
                        confidence=_confidence(relevant[0], 0.1),
                        evidence=[item["id"] for item in relevant[:4]],
                        techniques=["T1552.001", "T1078.004"],
                        verification=(
                            "Identifier le fournisseur et vérifier la portée de la clé depuis la console du "
                            "fournisseur — sans l'utiliser depuis l'extérieur."
                        ),
                        agent=self.name,
                    )
                )

        cookies = board.with_prefix("cookies.")
        if cookies:
            out.append(
                Hypothesis(
                    id="credentials:session:theft",
                    claim="Les cookies de session sont mal protégés (Secure/HttpOnly/Préfixe) : un vol devient exploitable.",
                    asset="Sessions authentifiées",
                    stage="escalation",
                    confidence=_confidence(cookies[0]),
                    evidence=[item["id"] for item in cookies],
                    techniques=["T1539", "T1185"],
                    verification="Lire les attributs des cookies dans une réponse HTTP et vérifier qu'ils sont absents de document.cookie.",
                    agent=self.name,
                )
            )
        return out

    def review(self, board: Blackboard) -> list[Hypothesis]:
        # Sans XSS exploitable, le vol de cookie reste théorique.
        xss = board.get("clientside:xss:reflected") or board.get("clientside:xss:stored")
        theft = board.get("credentials:session:theft")
        if theft and not xss:
            board.adjust(theft.id, -0.1, "aucun vecteur XSS confirmé dans les preuves", self.name)
        return []


class AccessAgent(Agent):
    """Contrôle d'accès : lire ou faire ce qu'on ne devrait pas."""

    name = "access"
    role = "Spécialiste autorisation — IDOR et privilèges"
    domain = "contrôle d'accès"

    def analyse(self, board: Blackboard) -> Iterable[Hypothesis]:
        out: list[Hypothesis] = []

        idor = board.with_prefix("access.idor", "access.hidden-object-id")
        if idor:
            out.append(
                Hypothesis(
                    id="access:idor:horizontal",
                    claim="Un compte ordinaire suffit à lire les données d'un autre client (IDOR/BOLA).",
                    asset="Données personnelles",
                    stage="exfiltration",
                    confidence=_confidence(idor[0]),
                    evidence=[item["id"] for item in idor],
                    techniques=["T1190", "T1078"],
                    verification=(
                        "Avec deux comptes de test créés pour la mission : demander l'objet du compte A "
                        "depuis le compte B. Jamais sur des données d'un vrai client."
                    ),
                    agent=self.name,
                    rationale="La sérialisation des identifiants ne prouve rien : seule la vérification croisée tranche.",
                )
            )

        control = board.with_prefix("access.parameter-control")
        if control:
            out.append(
                Hypothesis(
                    id="access:param:escalation",
                    claim="Un paramètre de rôle pilote les droits : l'élévation de privilèges se tente en changeant une valeur.",
                    asset="Console d'administration",
                    stage="escalation",
                    confidence=_confidence(control[0]),
                    evidence=[item["id"] for item in control],
                    techniques=["T1068", "T1548"],
                    verification="Comparer la réponse de l'API avec et sans le paramètre, sur un compte de test non privilégié.",
                    agent=self.name,
                )
            )

        admin = board.with_prefix("access.sensitive-endpoint")
        if admin:
            out.append(
                Hypothesis(
                    id="access:admin:surface",
                    claim="Les routes d'administration sont connues : reste à vérifier si le serveur les protège.",
                    asset="Console d'administration",
                    stage="recon",
                    confidence=_confidence(admin[0], 0.1),
                    evidence=[item["id"] for item in admin],
                    techniques=["T1595.002", "T1078"],
                    verification="Appeler une route d'admin sans session : un 401/403 est attendu, un 200 est une faille.",
                    agent=self.name,
                )
            )

        traversal = board.with_prefix("access.path-parameter")
        if traversal:
            out.append(
                Hypothesis(
                    id="access:path:traversal",
                    claim="Un paramètre désigne un fichier côté serveur : tentative de traversée de répertoire.",
                    asset="Serveurs et accès système",
                    stage="exfiltration",
                    confidence=_confidence(traversal[0]),
                    evidence=[item["id"] for item in traversal],
                    techniques=["T1005", "T1083"],
                    verification="Tester un chemin relatif inoffensif (../ vers un fichier de test) et vérifier le refus côté serveur.",
                    agent=self.name,
                )
            )
        return out


class ClientSideAgent(Agent):
    """Tout ce qui s'exécute dans le navigateur du visiteur."""

    name = "clientside"
    role = "Spécialiste navigateur — XSS, CSP, bibliothèques"
    domain = "client"

    def analyse(self, board: Blackboard) -> Iterable[Hypothesis]:
        out: list[Hypothesis] = []

        reflection = board.with_prefix("access.reflected-parameter", "content.inline-handlers")
        if reflection:
            out.append(
                Hypothesis(
                    id="clientside:xss:reflected",
                    claim="Un paramètre est reflété sans échappement : un lien piégé exécute du script chez la victime.",
                    asset="Navigateur des visiteurs",
                    stage="access",
                    confidence=_confidence(reflection[0]),
                    evidence=[item["id"] for item in reflection],
                    techniques=["T1059.007", "T1185"],
                    verification="Injecter un caractère inoffensif (<b>) dans le paramètre et observer s'il est échappé.",
                    agent=self.name,
                )
            )

        libs = board.with_prefix("libs.")
        if libs:
            finding = sorted(libs, key=lambda f: f.get("severity", "info"))[0]
            out.append(
                Hypothesis(
                    id="clientside:lib:dependency",
                    claim="Une bibliothèque front-end obsolète expose un exploit public dans le navigateur des visiteurs.",
                    asset="Navigateur des visiteurs",
                    stage="access",
                    confidence=_confidence(finding),
                    evidence=[item["id"] for item in libs],
                    techniques=["T1190", "T1059.007"],
                    verification="Identifier la CVE applicable, puis vérifier la version servie ; la mise à jour suffit à fermer la voie.",
                    agent=self.name,
                )
            )

        csp = board.with_prefix("headers.csp", "content.mixed-content")
        if csp:
            out.append(
                Hypothesis(
                    id="clientside:csp:mitigation",
                    claim="La CSP est absente ou permissive : rien ne freine l'exécution d'un script injecté.",
                    asset="Sessions authentifiées",
                    stage="escalation",
                    confidence=_confidence(csp[0]),
                    evidence=[item["id"] for item in csp[:3]],
                    techniques=["T1185"],
                    verification="Lire la CSP et vérifier l'absence d'unsafe-inline, de joker et de sources http:.",
                    agent=self.name,
                )
            )
        return out

    def review(self, board: Blackboard) -> list[Hypothesis]:
        # Une CSP stricte ne supprime pas la faille, mais complique l'exploitation.
        csp_findings = board.with_prefix("headers.csp-unsafe", "headers.csp-wildcard", "headers.csp-incomplete")
        xss = board.get("clientside:xss:reflected")
        if xss and not csp_findings:
            board.adjust(xss.id, -0.05, "CSP présente et non permissive", self.name)
        return []


class TransportAgent(Agent):
    """Ce qui circule : TLS, redirections, CORS."""

    name = "transport"
    role = "Spécialiste transport — TLS, HSTS, CORS"
    domain = "transport"

    def analyse(self, board: Blackboard) -> Iterable[Hypothesis]:
        out: list[Hypothesis] = []

        plain = board.with_prefix("transport.no-https", "transport.no-redirect", "content.insecure-password-form")
        if plain:
            out.append(
                Hypothesis(
                    id="transport:mitm:credentials",
                    claim="Le trafic peut être lu en clair : identifiants et cookies interceptables sur un Wi-Fi hostile.",
                    asset="Comptes utilisateurs",
                    stage="access",
                    confidence=_confidence(plain[0], 0.05),
                    evidence=[item["id"] for item in plain],
                    techniques=["T1557", "T1040"],
                    verification="Vérifier que tout http:// redirige en 301 vers https, y compris les sous-domaines.",
                    agent=self.name,
                )
            )

        tls = board.with_prefix("tls.")
        if tls:
            out.append(
                Hypothesis(
                    id="transport:tls:interception",
                    claim="Un défaut de certificat ou de protocole permet une interception discrète.",
                    asset="Sessions authentifiées",
                    stage="access",
                    confidence=_confidence(tls[0]),
                    evidence=[item["id"] for item in tls],
                    techniques=["T1557", "T1587.003"],
                    verification="Contrôler la chaîne, les dates et les protocoles acceptés avec un client TLS de référence.",
                    agent=self.name,
                )
            )

        cors = board.with_prefix("cors.")
        if cors:
            creds = board.with_prefix("cors.wildcard-credentials", "cors.reflected-credentials")
            out.append(
                Hypothesis(
                    id="transport:cors:exfiltration",
                    claim="Une politique CORS permissive laisse un site tiers lire les réponses authentifiées.",
                    asset="Données personnelles",
                    stage="exfiltration",
                    confidence=_confidence((creds or cors)[0], 0.05),
                    evidence=[item["id"] for item in cors],
                    techniques=["T1185", "T1539"],
                    verification="Envoyer une requête avec un Origin tiers et vérifier qu'Access-Control-Allow-Origin ne le reflète pas.",
                    agent=self.name,
                )
            )
        return out


class SupplyChainAgent(Agent):
    """Les tiers et les sous-domaines : entrer par la porte du voisin."""

    name = "supplychain"
    role = "Spécialiste chaîne d'approvisionnement"
    domain = "tiers"

    def analyse(self, board: Blackboard) -> Iterable[Hypothesis]:
        out: list[Hypothesis] = []

        takeover = board.with_prefix("recon.subdomain-takeover")
        if takeover:
            out.append(
                Hypothesis(
                    id="supplychain:subdomain:takeover",
                    claim="Un sous-domaine pointe vers un service libéré : il peut être repris pour héberger une page légitime aux yeux des victimes.",
                    asset="Contenu et réputation du site",
                    stage="access",
                    confidence=_confidence(takeover[0], 0.1),
                    evidence=[item["id"] for item in takeover],
                    techniques=["T1584.001", "T1583.001"],
                    verification="Vérifier l'enregistrement CNAME et l'absence de ressource côté fournisseur, sans enregistrer quoi que ce soit.",
                    agent=self.name,
                )
            )

        third = board.with_prefix("surface.third-parties")
        if third or board.third_parties:
            hosts = [item.get("host", "") for item in board.third_parties][:6]
            out.append(
                Hypothesis(
                    id="supplychain:thirdparty:compromise",
                    claim="Un script tiers s'exécute avec les pleins droits de la page : sa compromission devient la vôtre.",
                    asset="Navigateur des visiteurs",
                    stage="access",
                    confidence=0.5,
                    evidence=[item["id"] for item in third] or ["surface.third-parties"],
                    techniques=["T1195.002", "T1059.007"],
                    verification=(
                        "Pour chaque domaine tiers : vérifier l'intégrité (SRI), la CSP et la politique de "
                        "divulgation du fournisseur."
                    ),
                    agent=self.name,
                    rationale=("Hôtes concernés : " + ", ".join(hosts)) if hosts else "",
                )
            )

        integrity = board.with_prefix("content.script-integrity")
        if integrity:
            out.append(
                Hypothesis(
                    id="supplychain:sri:injection",
                    claim="Aucune empreinte d'intégrité : un script tiers modifié s'exécute sans que rien ne le détecte.",
                    asset="Navigateur des visiteurs",
                    stage="escalation",
                    confidence=_confidence(integrity[0]),
                    evidence=[item["id"] for item in integrity],
                    techniques=["T1195.002"],
                    verification="Lister les scripts externes sans attribut integrity et exiger un SRI ou un hébergement local.",
                    agent=self.name,
                )
            )
        return out


SPECIALISTS: tuple[type[Agent], ...] = (
    ReconAgent,
    ExposureAgent,
    CredentialAgent,
    AccessAgent,
    ClientSideAgent,
    TransportAgent,
    SupplyChainAgent,
)
