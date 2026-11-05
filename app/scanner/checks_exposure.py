"""Détection de fichiers exposés, listages de répertoires et fuites d'information."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from urllib.parse import urljoin, urlparse

from ..models import Finding, Severity
from .fetcher import Fetcher, HttpResponse

CATEGORY = "Exposition de fichiers"


def _text(resp: HttpResponse, limit: int = 4000) -> str:
    return resp.body[:limit].decode("utf-8", errors="replace")


def _is_html(resp: HttpResponse) -> bool:
    ctype = resp.header("content-type").lower()
    return "text/html" in ctype or _text(resp, 400).lstrip().lower().startswith("<!doctype html")


def _body_startswith(*prefixes: bytes) -> Callable[[HttpResponse], str | None]:
    def validator(resp: HttpResponse) -> str | None:
        head = resp.body[:64]
        return f"Contenu commence par {head[:32]!r}" if head.startswith(prefixes) else None

    return validator


def _regex(pattern: str, label: str, flags: int = 0) -> Callable[[HttpResponse], str | None]:
    compiled = re.compile(pattern, flags)

    def validator(resp: HttpResponse) -> str | None:
        match = compiled.search(_text(resp))
        return f"{label} : {match.group(0)[:120]!r}" if match else None

    return validator


def _contains(*needles: str, ignore_html: bool = False) -> Callable[[HttpResponse], str | None]:
    def validator(resp: HttpResponse) -> str | None:
        if resp.status != 200:
            return None
        if ignore_html and _is_html(resp):
            return None
        body = _text(resp, 20000)
        for needle in needles:
            if needle.lower() in body.lower():
                return f"Marqueur détecté : {needle!r}"
        return None

    return validator


@dataclass
class Probe:
    path: str
    title: str
    severity: Severity
    description: str
    remediation: str
    reference: str
    validate: Callable[[HttpResponse], str | None]
    id: str


PROBES: list[Probe] = [
    Probe(
        "/.git/HEAD",
        "Dépôt Git exposé",
        Severity.CRITICAL,
        "Le dossier `.git` est accessible publiquement : tout le code source, l'historique et "
        "parfois des secrets (mots de passe, clés API) peuvent être reconstitués.",
        "Bloquez l'accès à `.git/` au niveau du serveur ou du reverse-proxy, puis révoquez tous "
        "les secrets présents dans l'historique.",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
        _body_startswith(b"ref:", b"DIRC"),
        "exposure.git",
    ),
    Probe(
        "/.git/config",
        "Configuration Git exposée",
        Severity.CRITICAL,
        "Le fichier de configuration Git révèle les remotes (souvent internes) et la structure du "
        "projet.",
        "Interdisez l'accès à `.git/` et révoquez les identifiants présents dans les URLs de remote.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _regex(r"\[core\]|\[remote", "Section de configuration"),
        "exposure.git-config",
    ),
    Probe(
        "/.env",
        "Fichier .env exposé",
        Severity.CRITICAL,
        "Le fichier d'environnement contient les secrets de l'application (base de données, clés "
        "d'API, jetons).",
        "Supprimez le fichier de la racine web, bloquez-le et faites tourner tous les secrets exposés.",
        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
        _regex(r"(?m)^\s*[A-Z0-9_]{3,}\s*=", "Variable d'environnement"),
        "exposure.dotenv",
    ),
    Probe(
        "/.env.local",
        "Fichier .env.local exposé",
        Severity.CRITICAL,
        "Variante du fichier d'environnement, généralement chargée en production localement.",
        "Bloquez tous les fichiers `.env*` et révoquez les secrets.",
        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
        _regex(r"(?m)^\s*[A-Z0-9_]{3,}\s*=", "Variable d'environnement"),
        "exposure.dotenv-local",
    ),
    Probe(
        "/.htaccess",
        "Fichier .htaccess lisible",
        Severity.MEDIUM,
        "Les règles de réécriture et de protection du serveur sont visibles, ce qui facilite la "
        "recherche de contournements.",
        "Désactivez la lecture directe des fichiers de configuration Apache.",
        "https://httpd.apache.org/docs/2.4/howto/htaccess.html",
        _contains("RewriteEngine", "Order ", "AuthType", ignore_html=True),
        "exposure.htaccess",
    ),
    Probe(
        "/web.config",
        "web.config exposé",
        Severity.HIGH,
        "Le fichier de configuration IIS/.NET peut contenir des chaînes de connexion et des clés.",
        "Bloquez l'accès aux fichiers de configuration et déplacez les secrets hors du répertoire web.",
        "https://learn.microsoft.com/fr-fr/aspnet/core/host-and-deploy/iis/",
        _contains("<configuration", "<connectionStrings", ignore_html=True),
        "exposure.web-config",
    ),
    Probe(
        "/Dockerfile",
        "Dockerfile exposé",
        Severity.MEDIUM,
        "Le Dockerfile révèle la stack, les dépendances et parfois des identifiants de build.",
        "Excluez les fichiers de build du déploiement public.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _regex(r"(?m)^\s*FROM\s+\S+", "Instruction Dockerfile"),
        "exposure.dockerfile",
    ),
    Probe(
        "/docker-compose.yml",
        "docker-compose.yml exposé",
        Severity.HIGH,
        "Le fichier peut contenir des mots de passe de bases, des ports internes et la topologie "
        "de l'infrastructure.",
        "Retirez ce fichier du répertoire servi et faites tourner les secrets.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _regex(r"^\s*services\s*:|^\s*image\s*:\s*\S+", "Clé compose", re.M),
        "exposure.compose",
    ),
    Probe(
        "/phpinfo.php",
        "Page phpinfo() exposée",
        Severity.HIGH,
        "phpinfo divulgue la configuration PHP, les chemins serveur, les modules et les variables "
        "d'environnement.",
        "Supprimez le fichier et désactivez phpinfo en production.",
        "https://www.php.net/manual/fr/function.phpinfo.php",
        _regex(r"PHP Version\s*[0-9.]+|phpinfo\(\)", "Version PHP"),
        "exposure.phpinfo",
    ),
    Probe(
        "/server-status",
        "Statut Apache exposé",
        Severity.HIGH,
        "Le module mod_status divulgue les URL en cours de traitement (parfois avec des jetons) et "
        "les adresses IP clientes.",
        "Restreignez `/server-status` aux adresses d'administration.",
        "https://httpd.apache.org/docs/2.4/mod/mod_status.html",
        _contains("Apache Server Status", "Server Status"),
        "exposure.server-status",
    ),
    Probe(
        "/actuator/env",
        "Actuator Spring Boot exposé",
        Severity.CRITICAL,
        "L'endpoint `env` expose les propriétés de l'application, souvent avec des secrets et des "
        "identifiants de base de données.",
        "Restreignez les endpoints Actuator (`management.endpoints.web.exposure.include`) et "
        "protégez-les par authentification.",
        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
        _regex(r'"propertySources"|"activeProfiles"', "Charge utile Actuator", re.I),
        "exposure.actuator",
    ),
    Probe(
        "/actuator/health",
        "Endpoint de santé Spring Boot exposé",
        Severity.LOW,
        "L'endpoint de santé confirme la stack et peut divulguer l'état des dépendances.",
        "Limitez l'exposition des endpoints Actuator.",
        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
        _regex(r'"status"\s*:\s*"(UP|DOWN)"', "Statut applicatif", re.I),
        "exposure.actuator-health",
    ),
    Probe(
        "/.DS_Store",
        "Fichier .DS_Store exposé",
        Severity.LOW,
        "Ce fichier macOS liste l'arborescence du répertoire et aide à découvrir des fichiers "
        "non référencés.",
        "Supprimez les fichiers `.DS_Store` du déploiement et ajoutez-les à `.gitignore`.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _body_startswith(b"\x00\x00\x00\x01Bud1"),
        "exposure.ds-store",
    ),
    Probe(
        "/.git/logs/HEAD",
        "Historique Git exposé",
        Severity.CRITICAL,
        "Le reflog contient les adresses e-mail des développeurs, les branches et les messages "
        "de commit : une mine d'or pour l'ingénierie sociale et la reconstitution du code.",
        "Bloquez l'accès à `.git/` en totalité et purgez l'historique des secrets.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _regex(r"[0-9a-f]{40} .+ <[^>]+@[^>]+>", "Entrée de reflog"),
        "exposure.git-logs",
    ),
    Probe(
        "/.svn/entries",
        "Dépôt Subversion exposé",
        Severity.MEDIUM,
        "Un dossier `.svn` accessible permet de récupérer les sources et l'historique du projet.",
        "Interdisez l'accès aux dossiers de métadonnées de version (`.svn`, `.hg`, `.git`).",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _regex(r"^\d+\s*\n(dir|file)\s*$", "Entrées SVN", re.M),
        "exposure.svn",
    ),
    Probe(
        "/.hg/requires",
        "Dépôt Mercurial exposé",
        Severity.MEDIUM,
        "Le fichier `requires` de Mercurial confirme qu'un dépôt est téléchargeable.",
        "Interdisez l'accès au dossier `.hg/`.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _contains("revlogv1", "store", ignore_html=True),
        "exposure.hg",
    ),
    Probe(
        "/.env.production",
        "Fichier .env.production exposé",
        Severity.CRITICAL,
        "L'environnement de production expose les identifiants réels des bases et services.",
        "Bloquez tous les fichiers `.env*` et faites tourner les secrets.",
        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
        _regex(r"(?m)^\s*[A-Z0-9_]{3,}\s*=", "Variable d'environnement"),
        "exposure.dotenv-production",
    ),
    Probe(
        "/.aws/credentials",
        "Clés AWS exposées",
        Severity.CRITICAL,
        "Un fichier d'identifiants AWS accessible donne potentiellement le contrôle total du "
        "compte cloud.",
        "Supprimez immédiatement le fichier, révoquez les clés dans IAM et auditez CloudTrail.",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        _contains("aws_access_key_id", "[default]", ignore_html=True),
        "exposure.aws-credentials",
    ),
    Probe(
        "/storage/logs/laravel.log",
        "Journaux Laravel exposés",
        Severity.HIGH,
        "Les logs applicatifs contiennent des traces, des requêtes SQL et parfois des jetons de "
        "session ou des mots de passe.",
        "Interdisez l'accès au dossier `storage/` et purgez les logs exposés.",
        "https://laravel.com/docs/logging",
        _contains("production.ERROR", "stacktrace", "local.ERROR", ignore_html=True),
        "exposure.laravel-log",
    ),
    Probe(
        "/appsettings.json",
        "Configuration .NET exposée",
        Severity.HIGH,
        "Le fichier peut contenir des chaînes de connexion et des clés de service.",
        "Retirez les fichiers de configuration du répertoire public et utilisez un coffre de secrets.",
        "https://learn.microsoft.com/fr-fr/aspnet/core/fundamentals/configuration/",
        _regex(r'"ConnectionStrings"|"Logging"\s*:', "Configuration .NET"),
        "exposure.appsettings",
    ),
    Probe(
        "/trace.axd",
        "Trace ASP.NET exposée",
        Severity.HIGH,
        "`trace.axd` révèle les requêtes, les en-têtes de session et les chemins internes de "
        "l'application.",
        "Désactivez le tracing (`<trace enabled=\"false\" />`) en production.",
        "https://learn.microsoft.com/fr-fr/aspnet/web-forms/overview/older-versions-getting-started/deployment-to-a-hosting-provider/",
        _contains("Application Trace", "Request Details", "Trace Information"),
        "exposure.trace-axd",
    ),
    Probe(
        "/server-info",
        "Informations serveur Apache exposées",
        Severity.HIGH,
        "Le module mod_info divulgue la configuration complète : modules, chemins, versions.",
        "Désactivez `mod_info` ou restreignez son accès aux administrateurs.",
        "https://httpd.apache.org/docs/2.4/mod/mod_info.html",
        _contains("Server Settings", "Server Version", "Module Name"),
        "exposure.server-info",
    ),
    Probe(
        "/crossdomain.xml",
        "Politique crossdomain.xml permissive",
        Severity.MEDIUM,
        "Une politique autorisant `*` permet à n'importe quel site Flash/AIR de lire les réponses "
        "authentifiées.",
        "Restreignez `allow-access-from` aux domaines de confiance, ou supprimez le fichier.",
        "https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/rossdomain.html",
        _regex(r'allow-access-from\s+domain\s*=\s*["\']?\*', "Domaine générique autorisé", re.I),
        "exposure.crossdomain",
    ),
    Probe(
        "/phpmyadmin/",
        "Interface phpMyAdmin accessible",
        Severity.MEDIUM,
        "L'interface d'administration de la base de données est exposée publiquement : cible "
        "privilégiée pour la force brute.",
        "Restreignez l'accès par IP ou VPN et activez l'authentification à deux facteurs.",
        "https://www.phpmyadmin.net/",
        _contains("phpMyAdmin", "pma_username"),
        "exposure.phpmyadmin",
    ),
    Probe(
        "/wp-json/wp/v2/users",
        "Énumération des utilisateurs WordPress",
        Severity.MEDIUM,
        "L'API REST expose les comptes existants (`slug`, nom affiché), ce qui alimente "
        "directement une attaque par force brute ciblée.",
        "Désactivez l'endpoint ou filtrez les champs publics ; utilisez un plugin de sécurité "
        "et des mots de passe forts avec 2FA.",
        "https://developer.wordpress.org/rest-api/reference/users/",
        _regex(r'"slug"\s*:', "Liste d'utilisateurs"),
        "exposure.wp-users",
    ),
    Probe(
        "/xmlrpc.php",
        "XML-RPC WordPress actif",
        Severity.MEDIUM,
        "`xmlrpc.php` autorise des milliers de tentatives d'authentification en une requête "
        "(amplification de force brute).",
        "Désactivez XML-RPC si vous ne l'utilisez pas (filtre serveur ou plugin).",
        "https://developer.wordpress.org/reference/classes/wp_xmlrpc_server/",
        _contains("XML-RPC server accepts POST requests only"),
        "exposure.xmlrpc",
    ),
    Probe(
        "/readme.html",
        "Fichier readme.html exposé",
        Severity.LOW,
        "Le readme par défaut de WordPress confirme la présence du CMS et parfois sa version.",
        "Supprimez `readme.html` et masquez la version du CMS.",
        "https://wordpress.org/support/article/hardening-wordpress/",
        _regex(r"Semantic Personal Publishing|WordPress\s*(&rsaquo;|›)?\s*\d+\.\d+", "Marqueur WordPress"),
        "exposure.readme",
    ),
    Probe(
        "/config.php.bak",
        "Sauvegarde de configuration PHP exposée",
        Severity.HIGH,
        "Une copie `.bak` du fichier de configuration contient les identifiants de base de "
        "données et les clés de salage.",
        "Supprimez les fichiers de sauvegarde et bloquez les extensions `.bak`, `.old`, `.orig`.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _contains("<?php", "DB_PASSWORD", "DB_NAME", ignore_html=False),
        "exposure.php-bak",
    ),
    Probe(
        "/.idea/workspace.xml",
        "Projet JetBrains exposé",
        Severity.LOW,
        "Le fichier de workspace révèle l'arborescence du projet et parfois des chemins de "
        "déploiement.",
        "Excluez les dossiers d'IDE du déploiement.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _contains("<project version", "ProjectRootManager"),
        "exposure.jetbrains",
    ),
    Probe(
        "/backup.zip",
        "Archive de sauvegarde téléchargeable",
        Severity.HIGH,
        "Une archive de sauvegarde accessible permet de récupérer le code source ou la base de "
        "données complète.",
        "Supprimez les archives du répertoire public et stockez les sauvegardes hors du serveur web.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        lambda r: f"HTTP {r.status}, {r.header('content-type') or 'type inconnu'}"
        if r.status == 200 and "html" not in r.header("content-type").lower()
        else None,
        "exposure.backup-zip",
    ),
    Probe(
        "/backup.tar.gz",
        "Archive de sauvegarde téléchargeable",
        Severity.HIGH,
        "Une archive accessible permet de récupérer le code source ou les données complètes.",
        "Supprimez les archives du répertoire public et stockez les sauvegardes hors du serveur.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        lambda r: f"HTTP {r.status}, {r.header('content-type') or 'type inconnu'}"
        if r.status == 200 and "html" not in r.header("content-type").lower()
        else None,
        "exposure.backup-tar",
    ),
    Probe(
        "/site.zip",
        "Archive du site téléchargeable",
        Severity.HIGH,
        "L'archive complète du site (sources, médias, configuration) est téléchargeable.",
        "Retirez les archives du répertoire servi et protégez les exports.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        lambda r: f"HTTP {r.status}, {r.header('content-type') or 'type inconnu'}"
        if r.status == 200 and "html" not in r.header("content-type").lower()
        else None,
        "exposure.site-zip",
    ),
    Probe(
        "/backup.sql",
        "Dump SQL téléchargeable",
        Severity.CRITICAL,
        "Un export de base de données accessible expose l'intégralité des données utilisateurs.",
        "Supprimez le fichier, bloquez les extensions `.sql`, et faites une analyse d'impact RGPD.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _regex(r"CREATE TABLE|INSERT INTO|-- MySQL dump", "Instruction SQL", re.I),
        "exposure.sql-dump",
    ),
    Probe(
        "/composer.json",
        "Manifeste Composer exposé",
        Severity.LOW,
        "Les dépendances PHP et leurs contraintes de version sont visibles, ce qui oriente la "
        "recherche de CVE.",
        "Empêchez l'accès aux fichiers de dépendances en production.",
        "https://getcomposer.org/doc/",
        _regex(r'"require"\s*:', "Section require"),
        "exposure.composer",
    ),
    Probe(
        "/package.json",
        "Manifeste npm exposé",
        Severity.LOW,
        "Les dépendances JavaScript et versions sont visibles.",
        "Empêchez l'accès à `package.json` en production.",
        "https://docs.npmjs.com/cli/configuring-npm/package-json",
        _regex(r'"dependencies"\s*:', "Section dependencies"),
        "exposure.package-json",
    ),
    Probe(
        "/swagger-ui.html",
        "Interface Swagger/OpenAPI exposée",
        Severity.MEDIUM,
        "La documentation interactive de l'API révèle tous les endpoints, y compris ceux qui ne "
        "devraient pas être publics.",
        "Protégez la documentation par authentification ou désactivez-la en production.",
        "https://swagger.io/tools/swagger-ui/",
        _contains("swagger-ui", "Swagger UI", ignore_html=False),
        "exposure.swagger",
    ),
    Probe(
        "/graphql",
        "Endpoint GraphQL détecté",
        Severity.INFO,
        "Un endpoint GraphQL est exposé. Vérifiez que l'introspection est désactivée et que les "
        "requêtes sont limitées en profondeur.",
        "Désactivez l'introspection en production, ajoutez une limitation de profondeur et de débit.",
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        _regex(r'"errors"\s*:|"data"\s*:\s*\{|GraphQL', "Réponse GraphQL", re.I),
        "exposure.graphql",
    ),
    Probe(
        "/terraform.tfstate",
        "État Terraform exposé",
        Severity.CRITICAL,
        "Le fichier d'état Terraform contient l'inventaire complet de l'infrastructure et, "
        "souvent, des valeurs sensibles en clair : mots de passe de bases, clés d'accès, "
        "identifiants de passerelle.",
        "Retirez le fichier du dossier public, stockez l'état dans un backend distant chiffré "
        "(S3 + verrou) et faites tourner tous les secrets qu'il contenait.",
        "https://developer.hashicorp.com/terraform/language/state/sensitive-data",
        _regex(r'"terraform_version"\s*:\s*"\d', "Version Terraform"),
        "exposure.terraform-state",
    ),
    Probe(
        "/.ssh/id_rsa",
        "Clé privée SSH exposée",
        Severity.CRITICAL,
        "Une clé privée SSH téléchargeable permet de s'authentifier sur les serveurs qui "
        "acceptent la clé publique correspondante, sans mot de passe.",
        "Supprimez le fichier du dossier web, retirez la clé des `authorized_keys` concernés "
        "et générez une nouvelle paire avec une phrase de passe.",
        "https://www.ssh.com/academy/ssh/public-key-authentication",
        _regex(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", "Bloc de clé privée"),
        "exposure.ssh-private-key",
    ),
    Probe(
        "/.git-credentials",
        "Identifiants Git en clair",
        Severity.CRITICAL,
        "Le fichier `.git-credentials` stocke des identifiants (utilisateur + jeton) pour les "
        "dépôts distants : il donne un accès en écriture au code source.",
        "Supprimez le fichier, révoquez les jetons concernés et utilisez un gestionnaire "
        "d'identifiants ou des déploiements par clé SSH.",
        "https://git-scm.com/docs/gitcredentials",
        _regex(r"(?m)^https?://[^\s:/]+:[^\s@]+@", "Ligne identifiant@hôte"),
        "exposure.git-credentials",
    ),
    Probe(
        "/service-account.json",
        "Clé de compte de service Google Cloud exposée",
        Severity.CRITICAL,
        "Un fichier de compte de service GCP permet de se connecter aux API Google Cloud avec "
        "les droits du compte (stockage, base, facturation).",
        "Supprimez la clé, révoquez-la dans IAM, et utilisez des identités de charge de travail "
        "ou des identités managées au lieu d'un fichier de clé.",
        "https://cloud.google.com/iam/docs/best-practices-service-accounts",
        _regex(r'"type"\s*:\s*"service_account"', "Compte de service"),
        "exposure.gcp-service-account",
    ),
    Probe(
        "/credentials.json",
        "Fichier d'identifiants cloud exposé",
        Severity.CRITICAL,
        "Un fichier d'identifiants de compte de service est servi publiquement : les API cloud "
        "sont accessibles avec ses droits.",
        "Retirez le fichier du dossier public et révoquez la clé.",
        "https://cloud.google.com/iam/docs/best-practices-service-accounts",
        _regex(r'"type"\s*:\s*"service_account"', "Compte de service"),
        "exposure.gcp-service-account",
    ),
    Probe(
        "/actuator/heapdump",
        "Dump mémoire Spring Actuator exposé",
        Severity.CRITICAL,
        "Le heap dump contient la mémoire du processus Java : mots de passe de base, clés de "
        "chiffrement, jetons de session et données personnelles des utilisateurs.",
        "Fermez `/actuator/**` (au minimum `heapdump`, `env`, `threaddump`) et n'exposez "
        "Actuator que sur un port ou une interface d'administration.",
        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
        _body_startswith(b"JAVA PROFILE"),
        "exposure.actuator-heapdump",
    ),
    Probe(
        "/config/database.yml",
        "Configuration de base de données exposée",
        Severity.CRITICAL,
        "Le fichier de configuration décrit la base (hôte, utilisateur, mot de passe) : la base "
        "est joignable directement avec ces identifiants.",
        "Retirez le fichier du dossier public, changez le mot de passe et restreignez l'accès "
        "réseau à la base.",
        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
        _regex(
            r"(?s)adapter:\s*\w+.{0,600}?password:\s*\S+",
            "Bloc adapter + password",
        ),
        "exposure.database-config",
    ),
    Probe(
        "/.htpasswd",
        "Fichier de mots de passe (htpasswd) exposé",
        Severity.HIGH,
        "Les empreintes de mots de passe des comptes protégés par authentification HTTP sont "
        "téléchargeables : elles peuvent être cassées hors ligne.",
        "Déplacez le fichier hors du dossier web et utilisez des empreintes fortes (bcrypt).",
        "https://httpd.apache.org/docs/2.4/programs/htpasswd.html",
        _regex(r"(?m)^[^:\s]+:\$(?:apr1|2[aby]|5|6)\$", "Empreinte de mot de passe"),
        "exposure.htpasswd",
    ),
    Probe(
        "/openapi.json",
        "Schéma OpenAPI 3 exposé",
        Severity.MEDIUM,
        "Le schéma OpenAPI décrit tous les endpoints, paramètres et schémas de données : il "
        "fournit une carte complète de l'API, y compris les routes non documentées publiquement.",
        "Protégez la documentation par authentification ou ne l'exposez pas en production.",
        "https://swagger.io/specification/",
        _regex(r'"openapi"\s*:\s*"3\.', "Document OpenAPI 3"),
        "exposure.openapi",
    ),
    Probe(
        "/swagger/v1/swagger.json",
        "Schéma Swagger 2.0 exposé",
        Severity.MEDIUM,
        "Le schéma Swagger décrit l'API complète (routes, paramètres, modèles) et facilite "
        "l'énumération méthodique des points d'entrée.",
        "Restreignez l'accès au schéma en production.",
        "https://swagger.io/specification/v2/",
        _regex(r'"swagger"\s*:\s*"2\.', "Document Swagger 2.0"),
        "exposure.swagger-schema",
    ),
    Probe(
        "/graphiql",
        "Console GraphiQL exposée",
        Severity.MEDIUM,
        "La console GraphiQL permet d'exécuter des requêtes GraphQL depuis le navigateur, "
        "notamment l'introspection, qui révèle tout le schéma de l'API.",
        "Désactivez l'IDE en production et l'introspection pour les clients non authentifiés.",
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        _contains("GraphiQL", "graphql-playground", "Apollo Sandbox", ignore_html=False),
        "exposure.graphiql",
    ),
    Probe(
        "/_profiler",
        "Profiler Symfony exposé",
        Severity.HIGH,
        "Le profiler de développement expose les requêtes SQL, variables d'environnement, "
        "jetons de session et parfois les e-mails envoyés : c'est une fuite interne complète.",
        "Désactivez le profiler en production (`APP_ENV=prod`, `debug=false`) et bloquez "
        "`/_profiler` au niveau du serveur.",
        "https://symfony.com/doc/current/profiler.html",
        _regex(r"symfony profiler|sf-profiler|debug-toolbar|sf-toolbar", "Interface du profiler", re.I),
        "exposure.symfony-profiler",
    ),
    Probe(
        "/.well-known/security.txt",
        "security.txt absent",
        Severity.INFO,
        "Aucun canal de signalement de vulnérabilités n'est publié : les chercheurs ne savent pas "
        "à qui s'adresser.",
        "Publiez `/.well-known/security.txt` avec un contact et une politique de divulgation.",
        "https://www.rfc-editor.org/rfc/rfc9116",
        lambda r: None,
        "exposure.security-txt",
    ),
]


async def check_exposed_files(fetcher: Fetcher, base_url: str) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    meta: dict[str, str] = {}

    async def probe_one(probe: Probe):
        url = urljoin(base_url, probe.path.lstrip("/"))
        resp = await fetcher.get(url, max_bytes=48_000, timeout=min(8.0, 20))
        return probe, resp

    results = await fetcher.parallel([probe_one(p) for p in PROBES])

    for probe, resp in results:
        if resp.error:
            continue
        if probe.id == "exposure.security-txt":
            if resp.status == 200 and "contact:" in resp.text.lower():
                meta["security.txt"] = "présent"
                expiry = re.search(r"(?im)^expires:\s*(.+)$", resp.text)
                if expiry:
                    meta["security.txt_expire"] = expiry.group(1).strip()[:40]
                    try:
                        from datetime import datetime

                        stamp = datetime.fromisoformat(
                            expiry.group(1).strip().replace("Z", "+00:00")
                        )
                        if stamp < datetime.now(UTC):
                            findings.append(
                                Finding(
                                    id="exposure.security-txt-expired",
                                    title="security.txt expiré",
                                    severity=Severity.LOW,
                                    category=CATEGORY,
                                    description="Le champ `Expires` est dépassé : le fichier est "
                                    "considéré comme obsolète par les chercheurs.",
                                    evidence=f"Expires: {expiry.group(1).strip()}",
                                    remediation="Mettez à jour `Expires` (moins d'un an) et vérifiez "
                                    "que le contact est toujours valide.",
                                    reference="https://www.rfc-editor.org/rfc/rfc9116",
                                )
                            )
                    except ValueError:
                        pass
            else:
                findings.append(
                    Finding(
                        id=probe.id,
                        title=probe.title,
                        severity=probe.severity,
                        category=CATEGORY,
                        description=probe.description,
                        evidence="GET /.well-known/security.txt → 404 / contenu sans contact",
                        remediation=probe.remediation,
                        reference=probe.reference,
                    )
                )
            continue

        # Une signature n'a de valeur que sur une réponse réellement servie (200) :
        # sinon n'importe quelle page d'erreur personnalisée créerait un faux positif.
        if resp.status != 200:
            continue

        evidence = probe.validate(resp)
        if evidence:
            findings.append(
                Finding(
                    id=probe.id,
                    title=probe.title,
                    severity=probe.severity,
                    category=CATEGORY,
                    description=probe.description,
                    evidence=f"GET {probe.path} → HTTP {resp.status}\n{evidence}",
                    remediation=probe.remediation,
                    reference=probe.reference,
                )
            )
    return findings, meta


async def check_robots(fetcher: Fetcher, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    resp = await fetcher.get(urljoin(base_url, "robots.txt"), max_bytes=64_000)
    if resp.error or resp.status != 200:
        return findings

    text = resp.text
    disallow = [
        line.split(":", 1)[1].strip()
        for line in text.splitlines()
        if line.lower().lstrip().startswith("disallow:")
    ]
    disallow = [d for d in disallow if d and d != "/"]
    sensitive = [
        d
        for d in disallow
        if re.search(r"admin|backup|private|config|db|secret|staging|dev|test|api|internal|\.env", d, re.I)
    ]
    if sensitive:
        findings.append(
            Finding(
                id="robots.disclosure",
                title="robots.txt révèle des chemins sensibles",
                severity=Severity.LOW,
                category="Reconnaissance",
                description="Les entrées `Disallow` indiquent précisément les zones que "
                "l'administrateur souhaite cacher. Elles sont publiques et servent de feuille de "
                "route aux attaquants.",
                evidence="\n".join(sensitive[:10]),
                remediation="N'utilisez pas robots.txt comme contrôle d'accès. Protégez réellement "
                "ces chemins (authentification, restriction IP).",
                reference="https://www.rfc-editor.org/rfc/rfc9309",
            )
        )
    if "sitemap" not in text.lower():
        pass
    return findings


async def check_error_pages(fetcher: Fetcher, base_url: str) -> list[Finding]:
    """Provoque une 404 et cherche des traces techniques dans la réponse."""
    findings: list[Finding] = []
    marker = "vulnlens-404-probe-8f3a1c"
    resp = await fetcher.get(urljoin(base_url, marker), max_bytes=64_000)
    if resp.error or resp.status not in (404, 500):
        return findings

    body = resp.text[:20000]
    patterns = {
        "Traceback (most recent call last)": "traceback Python",
        "at System.": "stack trace .NET",
        "SQLSTATE": "erreur SQL",
        "Warning: mysql": "erreur MySQL",
        "You have an error in your SQL syntax": "erreur SQL",
        "org.springframework": "stack trace Spring",
        "Notice: Undefined": "notice PHP",
        "Fatal error:": "erreur fatale PHP",
        "Whitelabel Error Page": "page d'erreur Spring par défaut",
        "Stack trace:": "stack trace",
    }
    hits = [label for needle, label in patterns.items() if needle.lower() in body.lower()]
    if hits:
        findings.append(
            Finding(
                id="errors.stack-trace",
                title="Traces techniques dans les pages d'erreur",
                severity=Severity.MEDIUM,
                category="Fuite d'information",
                description="Les erreurs détaillées révèlent les chemins, frameworks et requêtes "
                "internes : une aide précieuse pour préparer une attaque.",
                evidence=f"HTTP {resp.status} sur /{marker} → {', '.join(sorted(set(hits)))}",
                remediation="Désactivez l'affichage des erreurs en production et renvoyez une page "
                "d'erreur générique.",
                reference="https://owasp.org/www-community/Improper_Error_Handling",
            )
        )
    return findings


async def check_directory_listing(fetcher: Fetcher, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in ("", "uploads/", "images/", "static/"):
        url = base_url if not path else urljoin(base_url, path)
        resp = await fetcher.get(url, max_bytes=32_000)
        if resp.error or resp.status != 200:
            continue
        body = resp.text[:8000].lower()
        if "<title>index of /" in body or "directory listing for" in body:
            findings.append(
                Finding(
                    id="exposure.directory-listing",
                    title="Listage de répertoire activé",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Le serveur liste le contenu des répertoires, ce qui expose les "
                    "fichiers non référencés (sauvegardes, documents internes).",
                    evidence=f"GET {url} → listage automatique",
                    remediation="Désactivez `Options -Indexes` (Apache) ou `autoindex off` (Nginx).",
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                )
            )
            break
    return findings


def detect_fingerprint(headers: dict[str, str], html: str) -> dict[str, str]:
    """Empreinte technique : utile pour le rapport, pas une vulnérabilité en soi."""
    blob = html[:200_000].lower()
    fingerprint: dict[str, str] = {}

    server = headers.get("server", "")
    if server:
        fingerprint["serveur"] = server
    powered = headers.get("x-powered-by", "")
    if powered:
        fingerprint["technologie"] = powered

    signatures = {
        "wordpress": "WordPress",
        "wp-content": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "shopify": "Shopify",
        "next.js": "Next.js",
        "__next_data__": "Next.js",
        "react": "React",
        "vue.js": "Vue.js",
        "angular": "Angular",
        "laravel": "Laravel",
        "django": "Django",
        "spring": "Spring",
        "cloudflare": "Cloudflare",
    }
    detected = sorted({name for needle, name in signatures.items() if needle in blob})
    if detected:
        fingerprint["frameworks"] = ", ".join(detected)

    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if generator:
        fingerprint["generateur"] = generator.group(1)

    host = urlparse(headers.get("__url__", "")).hostname or ""
    if host:
        fingerprint["hote"] = host
    return fingerprint
