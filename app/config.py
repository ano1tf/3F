"""Configuration centralisée (surchargeable par variables d'environnement)."""

from __future__ import annotations

import os

APP_NAME = "VulnLens"
APP_VERSION = "4.0.0"
APP_TAGLINE = "Scanner de vulnérabilités web — en un clic"

# Identité envoyée aux cibles scannées (transparence : on ne se cache pas).
USER_AGENT = os.getenv(
    "VULNLENS_USER_AGENT",
    f"{APP_NAME}/{APP_VERSION} (+scan securite autorise; contact: {os.getenv('VULNLENS_CONTACT', 'security@example.org')})",
)
TOOL_CONTACT = os.getenv("VULNLENS_CONTACT", "security@example.org")

# Réseau
HTTP_TIMEOUT = float(os.getenv("VULNLENS_TIMEOUT", "12"))
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 1_200_000
PATH_PROBE_CONCURRENCY = 5
MAX_CONCURRENT_SCANS = int(os.getenv("VULNLENS_MAX_SCANS", "1"))

# Autoriser les cibles privées (localhost, 10.x, 192.168.x…) — réservé au développement local.
ALLOW_PRIVATE_TARGETS = os.getenv("VULNLENS_ALLOW_PRIVATE", "0") in {"1", "true", "yes"}

# Une analyse ne doit jamais durer plus longtemps que ça.
SCAN_DEADLINE_SECONDS = float(os.getenv("VULNLENS_SCAN_DEADLINE", "120"))

# --- Alertes sortantes (webhook) -------------------------------------------
WEBHOOK_URL = os.getenv("VULNLENS_WEBHOOK_URL", "").strip()
_env_threshold = os.getenv("VULNLENS_ALERT_THRESHOLD", "").strip()
ALERT_THRESHOLD = int(_env_threshold) if _env_threshold.isdigit() else None
ALERT_MIN_DROP = int(os.getenv("VULNLENS_ALERT_MIN_DROP", "10"))
ALERT_ON_CRITICAL = os.getenv("VULNLENS_ALERT_ON_CRITICAL", "1") in {"1", "true", "yes"}

# --- Protection de l'instance (vide = pas d'authentification) ---------------
AUTH_TOKEN = os.getenv("VULNLENS_TOKEN", "").strip()
