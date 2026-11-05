"""Rapport de situation : pour chaque faille, le chemin d'accès, ce qu'elle révèle et sa dangerosité.

Rien d'exploitable ici : on décrit le scénario tel qu'un attaquant le comprendrait (qui peut
atteindre quoi, sans authentification ni outil particulier), pour que la correction soit arbitrée
sur des faits et non sur une étiquette de sévérité.
"""

from __future__ import annotations

from typing import Any

SEVERITY_BASE = {"critical": 9, "high": 7, "medium": 5, "low": 3, "info": 1}

DANGER_LABELS: tuple[tuple[int, str], ...] = (
    (9, "Critique — exploitable immédiatement, impact majeur"),
    (7, "Grave — exploitable à distance avec un effort limité"),
    (5, "Sérieux — exploitable dans un scénario réaliste"),
    (3, "Limité — utile en combinaison avec une autre faille"),
    (1, "Faible — signal de durcissement"),
)


def danger_label(score: int) -> str:
    for threshold, label in DANGER_LABELS:
        if score >= threshold:
            return label
    return DANGER_LABELS[-1][1]


def clamp(score: int) -> int:
    return max(1, min(10, score))


def _steps(*items: str) -> list[str]:
    return list(items)


# Chaque famille décrit : le chemin d'accès (étapes), ce que la faille révèle, l'écart de
# dangerosité par rapport à la sévérité de base et le niveau de compétence nécessaire.
FAMILIES: tuple[tuple[str, dict[str, Any]], ...] = (
    (
        "libs.",
        {
            "steps": _steps(
                "Lire le nom des fichiers JavaScript servis par le site : la version y figure "
                "souvent en clair (`jquery-1.12.4.min.js`).",
                "Comparer cette version aux avis publics : la faille est déjà documentée, avec "
                "son numéro CVE et souvent une preuve de concept publiée.",
                "Injecter un contenu piégé dans une zone que cette bibliothèque traite (commentaire, "
                "nom de profil, paramètre d'URL) pour exécuter du script chez les visiteurs.",
            ),
            "reveals": "Une bibliothèque obsolète, donc une vulnérabilité publique applicable "
            "sans recherche : XSS stocké, pollution de prototype ou exécution de code selon la "
            "bibliothèque. Le navigateur des visiteurs authentifiés devient le point d'entrée.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "secrets.jwt-alg-none",
        {
            "steps": _steps(
                "Récupérer le jeton trouvé dans un fichier public (la preuve le masque).",
                "Décoder son en-tête : il annonce `alg: none`, donc aucune signature.",
                "Réécrire les revendications (`sub`, `role`, `exp`) et présenter le jeton au "
                "serveur : s'il accepte cet algorithme, la session est ouverte sans mot de passe.",
            ),
            "reveals": "Un contournement complet de l'authentification : n'importe quel rôle "
            "peut être endossé, y compris administrateur.",
            "modifier": 1,
            "skill": "aucune",
        },
    ),
    (
        "secrets.jwt-privileged",
        {
            "steps": _steps(
                "Extraire le jeton depuis les fichiers publics du site.",
                "Lire ses revendications : le rôle annoncé est administratif.",
                "Le rejouer tant qu'il est valide, ou s'en inspirer pour forger un jeton si la "
                "signature est mal vérifiée.",
            ),
            "reveals": "Un accès privilégié direct, ou le format exact des revendications à "
            "reproduire pour élever ses droits.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "headers.debug-token",
        {
            "steps": _steps(
                "Lire l'en-tête de réponse `X-Debug-Token` : il identifie une requête dans le "
                "profiler du framework.",
                "Ouvrir `/_profiler/<jeton>` : requêtes SQL, variables d'environnement, sessions "
                "et e-mails envoyés sont affichés sans authentification.",
                "Réutiliser les secrets trouvés (identifiants de base, jetons) pour aller plus loin.",
            ),
            "reveals": "L'intérieur de l'application : requêtes SQL, configuration, sessions "
            "d'utilisateurs et parfois secrets d'API.",
            "modifier": 1,
            "skill": "aucune",
        },
    ),
    (
        "exposure.terraform-state",
        {
            "steps": _steps(
                "Télécharger `{target}/terraform.tfstate` : le fichier est servi statiquement.",
                "Y lire l'inventaire d'infrastructure et les valeurs sensibles (mots de passe, "
                "clés d'accès) que Terraform y stocke en clair.",
                "Utiliser ces identifiants contre les services cloud ou les bases concernés.",
            ),
            "reveals": "La carte complète de l'infrastructure et ses secrets : c'est la prise "
            "de contrôle du cloud, pas seulement du site.",
            "modifier": 1,
            "skill": "aucune",
        },
    ),
    (
        "exposure.actuator-heapdump",
        {
            "steps": _steps(
                "Demander `{target}/actuator/heapdump` : un dump mémoire complet est renvoyé.",
                "L'analyser avec un outil Java pour extraire chaînes, mots de passe, clés et "
                "jetons de session encore en mémoire.",
                "Rejouer les sessions ou les identifiants extraits.",
            ),
            "reveals": "La mémoire vive du serveur applicatif : secrets de configuration, "
            "sessions actives et données personnelles.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "exposure.symfony-profiler",
        {
            "steps": _steps(
                "Ouvrir `{target}/_profiler` : l'interface de débogage s'affiche sans authentification.",
                "Parcourir les dernières requêtes : SQL, variables d'environnement, sessions.",
                "Réutiliser les secrets et les sessions trouvés.",
            ),
            "reveals": "Une console de débogage complète en production : structure interne, "
            "requêtes SQL et données de session.",
            "modifier": 1,
            "skill": "aucune",
        },
    ),
    (
        "exposure.ssh-private-key",
        {
            "steps": _steps(
                "Télécharger la clé privée exposée (`{target}/.ssh/id_rsa`).",
                "La présenter aux serveurs qui font confiance à la clé publique correspondante.",
                "Se connecter en SSH avec les droits du compte associé.",
            ),
            "reveals": "Un accès serveur direct, hors application, avec les droits du compte "
            "propriétaire de la clé.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "exposure.gcp-service-account",
        {
            "steps": _steps(
                "Télécharger le fichier d'identifiants de compte de service.",
                "S'authentifier auprès des API Google Cloud avec ce fichier.",
                "Lister et lire les ressources accessibles (stockage, base, facturation).",
            ),
            "reveals": "Les droits du compte de service sur l'infrastructure cloud : lecture et "
            "souvent écriture des données.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "exposure.database-config",
        {
            "steps": _steps(
                "Télécharger le fichier de configuration (`{target}/config/database.yml`).",
                "Y lire l'hôte, l'utilisateur et le mot de passe de la base.",
                "Se connecter directement à la base si elle est joignable depuis l'extérieur.",
            ),
            "reveals": "Un accès direct aux données, sans passer par l'application ni ses "
            "contrôles d'accès.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "exposure.htpasswd",
        {
            "steps": _steps(
                "Télécharger le fichier `.htpasswd` servi par erreur.",
                "Extraire les empreintes de mots de passe des comptes listés.",
                "Les casser hors ligne (ces empreintes sont souvent faibles) et se connecter.",
            ),
            "reveals": "Les identifiants des comptes protégés par l'authentification HTTP.",
            "modifier": 0,
            "skill": "faible",
        },
    ),
    (
        "exposure.git",
        {
            "steps": _steps(
                "Depuis un navigateur, ouvrir {target}/.git/HEAD : aucune authentification n'est demandée.",
                "Le serveur renvoie la référence de branche courante, preuve que le dossier est servi.",
                "En suivant les objets Git publics, un attaquant reconstruit l'arborescence et l'historique du code.",
                "Il y cherche ensuite les secrets jamais purgés : clés d'API, mots de passe de base, jetons CI.",
            ),
            "reveals": "Le code source complet, l'historique des commits et les secrets qui y ont été "
            "poussés par erreur — c'est l'une des fuites les plus rentables pour un attaquant.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "exposure.dotenv",
        {
            "steps": _steps(
                "Ouvrir {target}/.env : le fichier est servi comme une page statique.",
                "Lire les variables : chaînes de connexion, clés de chiffrement, jetons d'API.",
                "Réutiliser ces identifiants contre les services qu'ils protègent (base, cloud, e-mail).",
            ),
            "reveals": "Les secrets de configuration de l'application : accès direct à la base de données "
            "et aux services tiers, souvent sans autre barrière.",
            "modifier": 1,
            "skill": "aucune",
        },
    ),
    (
        "exposure.",
        {
            "steps": _steps(
                "Demander l'URL exposée (visible dans la preuve du constat) sans authentification.",
                "Le serveur répond 200 avec le contenu du fichier ou la page d'administration.",
                "Exploiter ce contenu : versions, sauvegardes, consoles d'administration ou traces internes.",
            ),
            "reveals": "Un fichier ou une interface qui n'aurait jamais dû être public : sauvegarde, "
            "configuration, console d'admin ou documentation interne.",
            "modifier": 1,
            "skill": "aucune",
        },
    ),
    (
        "secrets.",
        {
            "steps": _steps(
                "Charger les fichiers JavaScript publics du site, comme n'importe quel visiteur.",
                "Y repérer la valeur exposée (elle est dans la preuve, volontairement masquée).",
                "Utiliser cette valeur contre l'API du fournisseur concerné, hors de votre périmètre.",
            ),
            "reveals": "Un identifiant d'API vivant : accès aux ressources du compte (cloud, paiement, "
            "e-mailing, envoi de SMS), avec facturation au nom de l'organisation.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "transport.no-https",
        {
            "steps": _steps(
                "Se placer sur le même réseau que la victime (Wi-Fi public, opérateur, proxy d'entreprise).",
                "Observer le trafic HTTP en clair : le contenu des pages et les cookies passent tels quels.",
                "Réutiliser un cookie de session intercepté pour agir à la place de l'utilisateur.",
            ),
            "reveals": "Tout ce qui circule : identifiants, cookies de session, données de formulaire, "
            "et la possibilité de modifier les pages en transit.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "transport.",
        {
            "steps": _steps(
                "Demander d'abord l'URL en HTTP plutôt qu'en HTTPS.",
                "Observer la redirection (absente, partielle ou en chaîne) et le premier saut non chiffré.",
                "Intercepter ce premier échange pour capter cookies ou identifiants avant le passage en TLS.",
            ),
            "reveals": "Une fenêtre non chiffrée avant l'établissement de la session sécurisée.",
            "modifier": 0,
            "skill": "faible",
        },
    ),
    (
        "tls.",
        {
            "steps": _steps(
                "Se connecter au service en TLS et examiner le certificat présenté.",
                "Comparer le nom, la chaîne de confiance et les protocoles acceptés.",
                "Se placer en position d'interception pour exploiter une validation défaillante ou un protocole obsolète.",
            ),
            "reveals": "Le niveau de garantie sur l'identité du serveur et la confidentialité de la connexion.",
            "modifier": 0,
            "skill": "intermédiaire",
        },
    ),
    (
        "cookies.",
        {
            "steps": _steps(
                "Se connecter au site et lire les cookies émis (outils développeur du navigateur).",
                "Constater l'absence de Secure, HttpOnly ou SameSite.",
                "Exploiter la faiblesse via une page HTTP interceptée ou une injection de script pour rejouer la session.",
            ),
            "reveals": "La session utilisateur : un cookie mal protégé suffit à usurper l'identité.",
            "modifier": 0,
            "skill": "intermédiaire",
        },
    ),
    (
        "headers.clickjacking",
        {
            "steps": _steps(
                "Intégrer le site dans une iframe sur une page attaquante (le site ne l'interdit pas).",
                "Superposer des boutons invisibles au-dessus des actions réelles.",
                "L'utilisateur connecté clique sans le savoir et exécute une action à son insu.",
            ),
            "reveals": "La capacité de faire agir un utilisateur authentifié (paiement, changement d'e-mail, suppression).",
            "modifier": -1,
            "skill": "faible",
        },
    ),
    (
        "headers.csp",
        {
            "steps": _steps(
                "Chercher un point d'injection HTML sur le site (paramètre réfléchi, commentaire, champ mal échappé).",
                "Constaté que la CSP n'arrête pas le script injecté (joker, unsafe-inline, schéma http, base-uri absent).",
                "Le script s'exécute alors avec les droits de la page : vol de session, exfiltration de formulaire.",
            ),
            "reveals": "L'absence de filet de sécurité contre l'injection de script : la politique affichée ne protège pas.",
            "modifier": 0,
            "skill": "intermédiaire",
        },
    ),
    (
        "headers.hsts",
        {
            "steps": _steps(
                "Forcer une première requête en HTTP vers le domaine.",
                "Constaté qu'aucun HSTS ne contraint le navigateur à rester en HTTPS.",
                "Intercepter ce premier saut pour rediriger vers une copie du site.",
            ),
            "reveals": "La possibilité de rétrograder la première visite vers un canal non chiffré.",
            "modifier": -1,
            "skill": "faible",
        },
    ),
    (
        "headers.",
        {
            "steps": _steps(
                "Envoyer une requête standard et lire les en-têtes de réponse.",
                "Constaté l'absence d'une protection attendue (nosniff, Referrer-Policy, Permissions-Policy).",
                "Combiner cette absence avec un autre défaut (téléversement, fuite d'URL) pour amplifier l'attaque.",
            ),
            "reveals": "Une couche de défense en profondeur manquante, qui rend les autres failles plus faciles à exploiter.",
            "modifier": -1,
            "skill": "faible",
        },
    ),
    (
        "content.insecure-password-form",
        {
            "steps": _steps(
                "Repérer le formulaire d'authentification et vérifier la destination.",
                "Constaté que l'envoi part en HTTP ou depuis une page non chiffrée.",
                "Se positionner sur le réseau pour lire les identifiants en clair.",
            ),
            "reveals": "Les identifiants de vos utilisateurs, en clair sur le réseau au moment de la connexion.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "content.csrf",
        {
            "steps": _steps(
                "Identifier un formulaire sensible sans jeton anti-CSRF.",
                "Faire visiter à un utilisateur connecté une page qui déclenche l'action automatiquement.",
                "L'action est exécutée avec la session de la victime.",
            ),
            "reveals": "La capacité de faire modifier des données (profil, commande, mot de passe) sans consentement.",
            "modifier": -1,
            "skill": "intermédiaire",
        },
    ),
    (
        "content.",
        {
            "steps": _steps(
                "Charger la page comme un visiteur normal et inspecter le HTML livré.",
                "Constaté la faiblesse de contenu (script tiers sans intégrité, iframe non isolée, commentaire, cache).",
                "Exploiter la confiance accordée à un composant externe ou à un cache partagé.",
            ),
            "reveals": "Une dépendance ou une configuration qui expose la page aux contenus qu'elle charge.",
            "modifier": 0,
            "skill": "faible",
        },
    ),
    (
        "cors.",
        {
            "steps": _steps(
                "Envoyer une requête à l'API depuis un domaine contrôlé par l'attaquant.",
                "Constater que le serveur accepte cette origine (ou reflète l'origine reçue) avec les cookies.",
                "Lire la réponse authentifiée de la victime depuis la page attaquante.",
            ),
            "reveals": "Les données auxquelles l'utilisateur connecté a accès : profil, commandes, messages.",
            "modifier": 1,
            "skill": "intermédiaire",
        },
    ),
    (
        "methods.",
        {
            "steps": _steps(
                "Envoyer une requête avec la méthode concernée (TRACE, PUT, DELETE…).",
                "Constater que le serveur l'accepte ou l'annonce sans contrôle.",
                "Vérifier si la méthode atteint une ressource modifiable ou reflète des en-têtes (TRACE).",
            ),
            "reveals": "La surface de méthodes réellement exposée, souvent plus large que l'application ne l'imagine.",
            "modifier": -1,
            "skill": "intermédiaire",
        },
    ),
    (
        "web.open-redirect",
        {
            "steps": _steps(
                "Utiliser le paramètre de redirection du site avec une destination externe.",
                "Le domaine légitime redirige alors vers le site de l'attaquant.",
                "Servir une page de connexion clonée à un utilisateur qui faisait confiance au lien initial.",
            ),
            "reveals": "La crédibilité du domaine : un lien officiel devient un vecteur de phishing.",
            "modifier": 0,
            "skill": "faible",
        },
    ),
    (
        "secrets.source-map",
        {
            "steps": _steps(
                "Ouvrir la source map publiée à côté du bundle (visible dans la preuve).",
                "Reconstituer le code d'origine : noms de fonctions, endpoints internes, commentaires.",
                "Utiliser cette carte pour cibler les points d'entrée non documentés.",
            ),
            "reveals": "Le code source lisible et la logique interne de l'application.",
            "modifier": 0,
            "skill": "faible",
        },
    ),
    (
        "recon.subdomain-takeover",
        {
            "steps": _steps(
                "Le sous-domaine pointe encore vers un service tiers dont l'instance a été supprimée.",
                "Un tiers peut recréer cette instance chez le même fournisseur et la revendiquer.",
                "Le sous-domaine de l'organisation sert alors du contenu contrôlé par l'attaquant.",
            ),
            "reveals": "Un sous-domaine officiel détournable : cookies de domaine parent, e-mails de "
            "réinitialisation, confiance des utilisateurs.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "recon.ct-subdomains",
        {
            "steps": _steps(
                "Consulter les journaux publics de certificats pour le domaine.",
                "Lister les noms d'hôtes historiques, y compris les environnements oubliés.",
                "Tester lesquels répondent encore et lesquels exposent une interface moins protégée.",
            ),
            "reveals": "La carte des services exposés, dont ceux que l'équipe avait oubliés.",
            "modifier": 0,
            "skill": "aucune",
        },
    ),
    (
        "recon.",
        {
            "steps": _steps(
                "Énumérer les sous-domaines et environnements accessibles publiquement.",
                "Repérer ceux qui ne bénéficient pas des protections du site principal.",
                "Utiliser cet accès latéral comme point d'entrée.",
            ),
            "reveals": "Une surface d'attaque plus large que le site principal, souvent moins surveillée.",
            "modifier": 0,
            "skill": "faible",
        },
    ),
    (
        "dns.zone-transfer",
        {
            "steps": _steps(
                "Demander un transfert de zone (AXFR) au serveur DNS autoritaire.",
                "Le serveur répond avec l'intégralité de la zone au lieu de refuser.",
                "L'attaquant obtient la liste complète des hôtes internes et externes.",
            ),
            "reveals": "La cartographie complète du domaine, y compris les hôtes non publics.",
            "modifier": 1,
            "skill": "faible",
        },
    ),
    (
        "dns.",
        {
            "steps": _steps(
                "Interroger les enregistrements publics du domaine (SPF, DMARC, CAA).",
                "Constater la faiblesse de la politique d'authentification e-mail.",
                "Envoyer un message en usurpant le domaine depuis une infrastructure quelconque.",
            ),
            "reveals": "La crédibilité de vos e-mails : sans politique stricte, l'usurpation passe les filtres.",
            "modifier": 0,
            "skill": "faible",
        },
    ),
    (
        "email.",
        {
            "steps": _steps(
                "Lire les enregistrements publics (DMARC, DKIM, MTA-STS, TLS-RPT).",
                "Constater qu'une partie de la chaîne d'authentification ou de chiffrement manque.",
                "Usurper le domaine auprès des destinataires, ou intercepter les échanges SMTP.",
            ),
            "reveals": "La solidité réelle de l'authentification e-mail, donc la facilité à se faire passer pour vous.",
            "modifier": 0,
            "skill": "intermédiaire",
        },
    ),
    (
        "errors.stack-trace",
        {
            "steps": _steps(
                "Provoquer une erreur en demandant une URL inexistante.",
                "Lire la trace technique renvoyée : chemins, framework, requêtes, parfois variables.",
                "Utiliser ces détails pour cibler précisément l'infrastructure.",
            ),
            "reveals": "L'architecture interne et les chemins de fichiers du serveur.",
            "modifier": -1,
            "skill": "aucune",
        },
    ),
    (
        "robots.disclosure",
        {
            "steps": _steps(
                "Ouvrir /robots.txt, public par définition.",
                "Lire les chemins que l'administrateur voulait cacher.",
                "Demander directement ces chemins : ils sont rarement protégés autrement.",
            ),
            "reveals": "Une liste de raccourcis vers les zones sensibles (admin, sauvegardes, environnements de test).",
            "modifier": -1,
            "skill": "aucune",
        },
    ),
    (
        "surface.foreign-form-action",
        {
            "steps": _steps(
                "Remplir un formulaire du site et observer la destination de l'envoi.",
                "Constater que les données partent vers un domaine qui n'appartient pas au site.",
                "Vérifier qui contrôle ce domaine et ce qu'il fait des données reçues.",
            ),
            "reveals": "Le trajet réel des données de vos utilisateurs, potentiellement hors de votre maîtrise.",
            "modifier": 0,
            "skill": "aucune",
        },
    ),
    (
        "surface.third-parties",
        {
            "steps": _steps(
                "Charger le site et observer les domaines contactés par le navigateur.",
                "Identifier ceux qui exécutent du code (scripts) plutôt que d'afficher une image.",
                "Une compromission de l'un de ces fournisseurs s'exécute avec les droits de votre page.",
            ),
            "reveals": "Votre chaîne de dépendances front : autant de chemins d'attaque qui ne vous appartiennent pas.",
            "modifier": 0,
            "skill": "intermédiaire",
        },
    ),
    (
        "content.generator-version",
        {
            "steps": _steps(
                "Lire le code source de la page : la version du CMS est affichée.",
                "Rechercher les vulnérabilités publiques connues de cette version exacte.",
                "Cibler l'exploit correspondant si le CMS n'est pas à jour.",
            ),
            "reveals": "La version exacte du logiciel, qui désigne les vulnérabilités connues applicables.",
            "modifier": -1,
            "skill": "faible",
        },
    ),
    (
        "headers.version-disclosure",
        {
            "steps": _steps(
                "Lire les en-têtes de réponse : le serveur annonce sa version.",
                "Rechercher les failles connues de cette version.",
                "Adapter l'attaque au serveur précisément identifié.",
            ),
            "reveals": "La technologie et la version du serveur, donc la liste des failles connues applicables.",
            "modifier": -1,
            "skill": "faible",
        },
    ),
)

DEFAULT_FAMILY: dict[str, Any] = {
    "steps": _steps(
        "La faiblesse est atteignable depuis l'extérieur, sans authentification préalable.",
        "Un attaquant la combine avec une autre faille ou une erreur humaine pour progresser.",
        "L'impact dépend de ce que protège la zone concernée.",
    ),
    "reveals": "Un défaut de configuration ou de conception qui affaiblit la posture globale.",
    "modifier": 0,
    "skill": "faible",
}


def family_for(finding_id: str) -> dict[str, Any]:
    for prefix, family in FAMILIES:
        if finding_id.startswith(prefix):
            return family
    return DEFAULT_FAMILY


def scenario(finding: dict[str, Any], target: str) -> dict[str, Any]:
    """Chemin d'accès, révélation et dangerosité 1-10 pour un constat donné."""
    finding_id = str(finding.get("id", ""))
    severity = str(finding.get("severity", "info"))
    family = family_for(finding_id)

    base = SEVERITY_BASE.get(severity, 1)
    modifier = int(family.get("modifier", 0))
    confidence = finding.get("confidence", "certain")
    if confidence == "probable":
        modifier -= 1
    elif confidence == "a-confirmer":
        modifier -= 1
    danger = clamp(base + modifier)

    site = (target or finding.get("target") or "").rstrip("/")
    steps = [step.replace("{target}", site or "le site").replace("{host}", site or "le site")
             for step in family.get("steps", DEFAULT_FAMILY["steps"])]

    return {
        "danger": danger,
        "danger_label": danger_label(danger),
        "access": steps,
        "reveals": family.get("reveals", DEFAULT_FAMILY["reveals"]),
        "skill": family.get("skill", "faible"),
    }


def annotate(findings: list[dict[str, Any]], target: str) -> list[dict[str, Any]]:
    """Ajoute les champs de situation à chaque constat (mutation en place)."""
    for finding in findings:
        finding.update(scenario(finding, target))
    return findings


def max_danger(findings: list[dict[str, Any]]) -> int:
    return max((int(finding.get("danger") or 0) for finding in findings), default=0)


def situation_table(findings: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """Vue synthétique triée par dangerosité décroissante, pour le rapport de situation."""
    ordered = sorted(
        findings,
        key=lambda item: (-int(item.get("danger") or 0), item.get("severity", ""), item.get("id", "")),
    )
    return [
        {
            "id": item.get("id", ""),
            "title": item.get("title", ""),
            "severity": item.get("severity", "info"),
            "severity_label": item.get("severity_label", ""),
            "category": item.get("category", ""),
            "danger": int(item.get("danger") or 0),
            "danger_label": item.get("danger_label", ""),
            "access": item.get("access", []),
            "reveals": item.get("reveals", ""),
            "skill": item.get("skill", ""),
            "remediation": item.get("remediation", ""),
        }
        for item in ordered[:limit]
    ]
