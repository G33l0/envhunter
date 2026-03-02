#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ███████╗███╗   ██╗██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗  ║
║   ██╔════╝████╗  ██║██║   ██║██║  ██║██║   ██║████╗  ██║  ║
║   █████╗  ██╔██╗ ██║██║   ██║███████║██║   ██║██╔██╗ ██║  ║
║   ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██╔══██║██║   ██║██║╚██╗██║  ║
║   ███████╗██║ ╚████║ ╚████╔╝ ██║  ██║╚██████╔╝██║ ╚████║  ║
║   ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  ║
║                                                           ║
║       .env Exposure & Secrets Recon Framework  v4.0       ║
║               Author : g33l0  |  Telegram : @x0x0h33l0    ║
╚═══════════════════════════════════════════════════════════╝
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import os
import sys
import re
import json
import time
import random
import hashlib
import sqlite3
import argparse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, List

# ── signal: SIGINT is the only cross-platform-safe signal ────────────────────
import signal

# ── third-party: caught with helpful messages if missing ─────────────────────
def _require(pkg, install_name=None):
    import importlib
    try:
        return importlib.import_module(pkg)
    except ImportError:
        name = install_name or pkg
        print(f"\n[ERROR] Missing package '{name}'. Install it with:\n"
              f"        pip install {name}\n"
              f"  or install all requirements:\n"
              f"        pip install -r requirements.txt\n")
        sys.exit(1)

requests  = _require("requests")
colorama  = _require("colorama")
rich_mod  = _require("rich")
schedule  = _require("schedule")

import urllib3
from colorama import init
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich import box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)
console = Console()

# ─── META ─────────────────────────────────────────────────────────────────────
VERSION   = "4.0"
AUTHOR    = "g33l0"
TG_HANDLE = "@x0x0h33l0"
DB_PATH   = "envhunter_state.db"

BANNER = """[bold cyan]
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ███████╗███╗   ██╗██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗  ║
║   ██╔════╝████╗  ██║██║   ██║██║  ██║██║   ██║████╗  ██║  ║
║   █████╗  ██╔██╗ ██║██║   ██║███████║██║   ██║██╔██╗ ██║  ║
║   ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██╔══██║██║   ██║██║╚██╗██║  ║
║   ███████╗██║ ╚████║ ╚████╔╝ ██║  ██║╚██████╔╝██║ ╚████║  ║
║   ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  ║
║                                                           ║
║      [bold white]  .env Exposure & Secrets Recon Framework  v4.0[/bold white][bold cyan]      ║
║         [bold red]  Author : g33l0[/bold red][bold cyan]  |  [bold green]Telegram : @x0x0h33l0[/bold green][bold cyan]        ║
╚═══════════════════════════════════════════════════════════╝[/bold cyan]"""

# ─── SCAN MODULES ─────────────────────────────────────────────────────────────
# Each module is a named group of paths. The engine checks ALL enabled modules.
# Add new modules here without touching the scan engine.

SCAN_MODULES: dict = {

    # ── Already existed in v3.x ──────────────────────────────────────────────
    "env_files": {
        "enabled": True,
        "label":   ".env Files",
        "paths": [
            "/.env", "/.env.local", "/.env.dev", "/.env.development",
            "/.env.prod", "/.env.production", "/.env.staging", "/.env.backup",
            "/.env.bak", "/.env.old", "/.env.example", "/.env.sample",
            "/.env.test", "/.env.php", "/.env.save", "/.env.copy",
            "/.env.dist", "/.env.secret",
            "/api/.env", "/backend/.env", "/app/.env", "/config/.env",
            "/src/.env", "/public/.env", "/web/.env", "/www/.env",
            "/laravel/.env", "/wp-content/.env", "/application/.env",
            "/server/.env", "/deploy/.env", "/docker/.env",
            "/storage/.env", "/core/.env", "/portal/.env",
        ],
    },

    # ── NEW: phpMyAdmin & DB Admin Tools ─────────────────────────────────────
    "phpmyadmin": {
        "enabled": True,
        "label":   "phpMyAdmin / DB Admin",
        "paths": [
            "/phpmyadmin/", "/phpmyadmin/index.php",
            "/phpMyAdmin/", "/phpMyAdmin/index.php",
            "/pma/", "/pma/index.php",
            "/admin/phpmyadmin/", "/db/", "/dbadmin/",
            "/mysql/", "/mysqladmin/", "/phpmyadmin2/",
            "/phpmyadmin3/", "/phpmyadmin4/",
            "/myadmin/", "/sqlmanager/", "/mysqlmanager/",
            "/php-myadmin/", "/phpmy-admin/",
            "/adminer.php", "/adminer/",
            "/adminer-4.php", "/adminer-4.7.9.php",
        ],
    },

    # ── NEW: Admin Panels ─────────────────────────────────────────────────────
    "admin_panels": {
        "enabled": True,
        "label":   "Admin Panels",
        "paths": [
            "/admin/", "/admin/login", "/admin/login.php", "/admin/index.php",
            "/administrator/", "/administrator/index.php",
            "/adminpanel/", "/admin-panel/", "/wp-admin/",
            "/wp-login.php", "/user/login", "/auth/login",
            "/backend/", "/backend/login", "/control/",
            "/controlpanel/", "/cp/", "/cpanel/",
            "/manage/", "/management/", "/manager/",
            "/moderator/", "/superadmin/", "/siteadmin/",
            "/webadmin/", "/adminarea/", "/bb-admin/",
            "/adminLogin/", "/admin_area/", "/panel-administracion/",
            "/instadmin/", "/memberadmin/", "/administratorlogin/",
        ],
    },

    # ── NEW: PHP Info & Debug Pages ───────────────────────────────────────────
    "php_info": {
        "enabled": True,
        "label":   "PHP Info / Debug",
        "paths": [
            "/phpinfo.php", "/info.php", "/php_info.php", "/phpinfo/",
            "/test.php", "/info/", "/?phpinfo=1",
            "/debug/", "/debug/default/view", "/debug/vars",
            "/_profiler/", "/_profiler/phpinfo",
            "/telescope", "/telescope/requests",
            "/horizon", "/clockwork/app", "/__clockwork/",
            "/debugbar/",
        ],
    },

    # ── NEW: Server Status & Version Disclosure ───────────────────────────────
    "server_status": {
        "enabled": True,
        "label":   "Server Status / Info",
        "paths": [
            "/server-status", "/server-info",
            "/nginx_status", "/status",
            "/actuator", "/actuator/health",
            "/actuator/env", "/actuator/info",
            "/actuator/mappings", "/actuator/beans",
            "/actuator/logfile", "/actuator/httptrace",
            "/metrics", "/health", "/healthz",
            "/ready", "/readyz", "/live", "/livez",
            "/_cat/indices", "/_cat/nodes",
            "/_cluster/health",
            "/solr/", "/solr/admin/",
            "/jmx", "/jolokia/",
        ],
    },

    # ── NEW: Exposed Config Files ─────────────────────────────────────────────
    "config_files": {
        "enabled": True,
        "label":   "Config Files",
        "paths": [
            "/config.php", "/config/config.php", "/configuration.php",
            "/config/database.php", "/config/app.php",
            "/wp-config.php", "/wp-config.php.bak",
            "/config.inc.php", "/settings.php", "/settings.inc.php",
            "/database.php", "/db.php", "/db_config.php",
            "/conf/config.php", "/includes/config.php",
            "/application/config/database.php",
            "/app/config/database.php",
            "/sites/default/settings.php",
            "/config/settings.inc.php",
            "/config.xml", "/config.json",
            "/config.yml", "/config.yaml", "/.config",
            "/config/config.yml", "/config/config.yaml",
            "/app/config/parameters.yml",
            "/app/config/parameters.yaml",
        ],
    },

    # ── NEW: Backup & Database Dumps ─────────────────────────────────────────
    "backup_files": {
        "enabled": True,
        "label":   "Backup / Dump Files",
        "paths": [
            "/backup.sql", "/backup.sql.gz", "/dump.sql",
            "/database.sql", "/db.sql", "/db_backup.sql",
            "/backup/", "/backups/", "/backup.zip",
            "/backup.tar.gz", "/backup.tar",
            "/site.tar.gz", "/website.zip", "/www.zip",
            "/public_html.zip", "/html.zip",
            "/db_dump.sql", "/mysqldump.sql",
            "/latest.sql", "/prod.sql", "/production.sql",
        ],
    },

    # ── NEW: Git / VCS Exposure ───────────────────────────────────────────────
    "git_exposure": {
        "enabled": True,
        "label":   "Git / VCS Exposure",
        "paths": [
            "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
            "/.git/index", "/.git/packed-refs",
            "/.gitignore", "/.gitmodules", "/.gitattributes",
            "/.svn/entries", "/.svn/wc.db",
            "/.hg/hgrc", "/.bzr/README",
            "/CVS/Root", "/CVS/Entries",
        ],
    },

    # ── NEW: Log Files ────────────────────────────────────────────────────────
    "log_files": {
        "enabled": True,
        "label":   "Log Files",
        "paths": [
            "/logs/", "/log/", "/error.log", "/error_log",
            "/access.log", "/access_log",
            "/app/storage/logs/laravel.log",
            "/storage/logs/laravel.log",
            "/storage/logs/",
            "/logs/error.log", "/logs/app.log",
            "/logs/debug.log", "/site/logs/",
            "/.npm-debug.log", "/npm-debug.log",
            "/yarn-error.log", "/debug.log",
        ],
    },

    # ── NEW: SSH Keys & Certificates ─────────────────────────────────────────
    "ssh_keys": {
        "enabled": True,
        "label":   "SSH Keys / Certs",
        "paths": [
            "/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/id_ecdsa",
            "/.ssh/id_ed25519", "/.ssh/authorized_keys",
            "/.ssh/known_hosts", "/.ssh/config",
            "/id_rsa", "/id_rsa.pub",
            "/server.key", "/private.key",
            "/ssl.key", "/ssl.crt", "/server.crt",
        ],
    },

    # ── NEW: Composer / Package Manifests ────────────────────────────────────
    "package_files": {
        "enabled": True,
        "label":   "Package / Dependency Files",
        "paths": [
            "/composer.json", "/composer.lock",
            "/package.json", "/package-lock.json",
            "/yarn.lock", "/Gemfile", "/Gemfile.lock",
            "/requirements.txt", "/Pipfile", "/Pipfile.lock",
            "/go.mod", "/go.sum",
        ],
    },

    # ── NEW: Docker / DevOps / CI ─────────────────────────────────────────────
    "devops_files": {
        "enabled": True,
        "label":   "Docker / DevOps / CI",
        "paths": [
            "/docker-compose.yml", "/docker-compose.yaml",
            "/docker-compose.override.yml",
            "/docker-compose.prod.yml",
            "/Dockerfile", "/.dockerignore",
            "/kubernetes.yml", "/k8s.yml",
            "/.travis.yml", "/.circleci/config.yml",
            "/Jenkinsfile",
            "/ansible.cfg", "/playbook.yml",
            "/terraform.tfvars", "/Vagrantfile",
        ],
    },

    # ── NEW: API Docs & GraphQL ───────────────────────────────────────────────
    "api_exposure": {
        "enabled": True,
        "label":   "API Docs / GraphQL",
        "paths": [
            "/swagger.json", "/swagger.yaml",
            "/swagger-ui/", "/swagger-ui.html",
            "/api-docs/", "/api-docs.json",
            "/openapi.json", "/openapi.yaml",
            "/v1/api-docs", "/v2/api-docs",
            "/graphql", "/graphiql", "/playground",
            "/api/swagger", "/docs/api",
        ],
    },

    # ── NEW: WordPress Specific ───────────────────────────────────────────────
    "wordpress": {
        "enabled": True,
        "label":   "WordPress",
        "paths": [
            "/wp-json/wp/v2/users",
            "/wp-json/",
            "/wp-content/debug.log",
            "/wp-content/uploads/",
            "/xmlrpc.php",
            "/?author=1",
            "/?author=2",
            "/wp-includes/",
            "/wp-config-sample.php",
        ],
    },
}

# Convenience flat list for backwards-compat (extra_paths etc.)
ENV_PATHS: List[str] = []
for _mod in SCAN_MODULES.values():
    if _mod["enabled"]:
        ENV_PATHS.extend(_mod["paths"])
ENV_PATHS = list(dict.fromkeys(ENV_PATHS))  # deduplicate preserving order

# ─── DETECTION PATTERNS ───────────────────────────────────────────────────────
# Applied to file CONTENT for .env / config / log files.
# Applied to RESPONSE METADATA (headers, URL, body keywords) for page-type checks.

SENSITIVE_PATTERNS = {
    # ── Existing patterns (v3.x) ─────────────────────────────────────────────
    "SMTP / Mail":          r'(?i)(smtp|mail_host|mail_port|mail_user|mail_pass|mailer|sendgrid|mailgun|ses_key)',
    "Database Credentials": r'(?i)(db_pass|db_user|database_url|mysql_pw|postgres_pass|mongo_uri|db_host|db_name)',
    "API Keys":             r'(?i)(api_key|api_secret|api_token|access_key|secret_key|client_secret|consumer_key)',
    "Cloud Credentials":    r'(?i)(aws_access|aws_secret|gcp_key|azure_client|digitalocean_token|cloudflare_api)',
    "Auth / JWT Secrets":   r'(?i)(jwt_secret|app_secret|auth_secret|secret_key|encryption_key|token_secret)',
    "OAuth / SSO":          r'(?i)(oauth_|client_id|client_secret|github_token|google_client|facebook_app)',
    "Passwords":            r'(?i)(password|passwd|pass=|pwd=|passphrase)',
    "Usernames":            r'(?i)(username|user_name|login_user|admin_user)',
    "Stripe / Payment":     r'(?i)(stripe_key|stripe_secret|paypal_secret|braintree|square_token)',
    "Twilio / SMS":         r'(?i)(twilio_sid|twilio_token|twilio_auth|vonage_api|nexmo_key)',
    "Private Keys/Certs":   r'(?i)(private_key|ssl_key|rsa_key|certificate|pem_file)',
    "Redis / Cache":        r'(?i)(redis_url|redis_pass|redis_host|memcached_pass)',
    "Webhook Secrets":      r'(?i)(webhook_secret|slack_token|discord_token|telegram_bot)',
    "General Secrets":      r'(?i)(secret|token|key|credential|passwd)[\s]*[=:]+[\s]*[^\s]{6,}',
    # ── New patterns (v4.0) ───────────────────────────────────────────────────
    "Docker / DevOps":      r'(?i)(docker_pass|registry_pass|ci_token|deploy_key|ansible_pass|vault_token|terraform)',
    "SSH / Private Keys":   r'(?i)(-----BEGIN|RSA PRIVATE|OPENSSH PRIVATE|DSA PRIVATE|EC PRIVATE|ssh-rsa|ssh-ed25519)',
    "Spring Boot Actuator": r'(?i)(spring\.datasource|spring\.security|management\.endpoints)',
    "WordPress Secrets":    r'(?i)(DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|table_prefix)',
    "Laravel App Config":   r'(?i)(APP_KEY=base64|APP_DEBUG=true|APP_ENV=local|cipher=AES)',
    "Database DSN":         r'(?i)(mysql://|postgres://|postgresql://|mongodb://|redis://|sqlite://)',
    "Internal IPs":         r'(?i)(db_host|redis_host|memcached_host|mq_host)[\s]*[=:][\s]*(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)',
    "Version Disclosure":   r'(?i)(x-powered-by|server:\s*(apache|nginx|iis|php|laravel|express))',
}

# ── Per-module content signatures ─────────────────────────────────────────────
# Used by the exposure scanner to validate that a page response is genuinely
# the resource we expect (not a 200 OK catch-all / soft 404).

MODULE_SIGNATURES: dict = {
    "phpmyadmin":    [r'(?i)(phpmyadmin|pma_|pmahomme|phpMyAdmin)', r'(?i)(mysql|mariadb|database)'],
    "admin_panels":  [r'(?i)(login|username|password|admin|administrator|sign.?in)'],
    "php_info":      [r'(?i)(phpinfo|PHP Version|php\.ini|Configuration|extension)'],
    "server_status": [r'(?i)(server.status|requests.currently|uptime|connections|worker)'],
    "config_files":  [r'(?i)(password|database|secret|key|host|username|token)'],
    "backup_files":  [r'(?i)(INSERT INTO|CREATE TABLE|mysqldump|Database:|Host:)'],
    "git_exposure":  [r'(?i)(repositoryformatversion|filemode|bare|ref:|HEAD|branch)'],
    "log_files":     [r'(?i)(ERROR|WARNING|NOTICE|Stack trace|exception|Traceback|\[error\])'],
    "ssh_keys":      [r'(?i)(-----BEGIN|RSA PRIVATE|OPENSSH|ssh-rsa|ssh-ed25519)'],
    "package_files": [r'(?i)("name"|"version"|"dependencies"|"require"|packages)'],
    "devops_files":  [r'(?i)(version:|services:|image:|FROM |RUN |ENV |COPY |ARG )'],
    "api_exposure":  [r'(?i)(swagger|openapi|paths:|definitions:|"info":|"paths":)'],
    "wordpress":     [r'(?i)(wp-|wordpress|wp_|woocommerce|wp-content)'],
    "env_files":     [],  # uses existing _looks_like_env() logic
}

FP_MARKERS = [
    r'(?i)^#', r'(?i)=\s*$', r'(?i)=\s*null', r'(?i)=\s*false',
    r'(?i)=\s*your_', r'(?i)=\s*<', r'(?i)=\s*\{', r'(?i)=\s*\[',
    r'(?i)_example', r'(?i)_placeholder', r'(?i)change.?me', r'(?i)xxx+',
]

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/121.0",
    "curl/7.88.1",
]


# ─── SAFE ARGS HELPER ─────────────────────────────────────────────────────────
def aget(args, attr: str, default=None):
    """Safe attribute access on any args object (argparse namespace or plain class)."""
    return getattr(args, attr, default)


# ─── SAFE PROMPT HELPERS ──────────────────────────────────────────────────────
def prompt_int(question: str, default: int, min_val: int = 1, max_val: int = 99999) -> int:
    """
    Ask for an integer with validation loop.
    Accepts:  '10', '10.0', '10.5' (truncated), '  10  '
    Rejects:  'abc', '', negative (if min_val > 0)
    """
    while True:
        raw = Prompt.ask(question, default=str(default)).strip()
        try:
            # Accept floats like '0.5' and truncate — user intent is clear
            val = int(float(raw))
            if min_val <= val <= max_val:
                return val
            console.print(f"  [red]  ✗ Enter a number between {min_val} and {max_val}[/red]")
        except (ValueError, OverflowError):
            console.print(f"  [red]  ✗ '{raw}' is not a valid number — try again[/red]")


def prompt_float(question: str, default: float, min_val: float = 0.0, max_val: float = 3600.0) -> float:
    """
    Ask for a float with validation loop.
    Accepts:  '0', '0.5', '1', '1.5', '2.0', '.5'
    Rejects:  'abc', 'half', negative values
    """
    while True:
        raw = Prompt.ask(question, default=str(default)).strip()
        # Allow common shorthand: '.5' → '0.5'
        if raw.startswith('.'):
            raw = '0' + raw
        try:
            val = float(raw)
            if min_val <= val <= max_val:
                return val
            console.print(f"  [red]  ✗ Enter a number between {min_val} and {max_val}[/red]")
        except (ValueError, OverflowError):
            console.print(f"  [red]  ✗ '{raw}' is not a valid number — try again (e.g. 0.5, 1, 2)[/red]")


# ─── DATA MODELS ──────────────────────────────────────────────────────────────
class ExposedEnv:
    def __init__(self, url: str, status_code: int, content_length: int, content_type: str):
        self.url            = url
        self.status_code    = status_code
        self.content_length = content_length
        self.content_type   = content_type
        self.raw_content    = ""
        self.findings: dict = {}
        self.risk_level     = "LOW"


class ExposedPage:
    """
    Represents any publicly accessible resource that should NOT be public.
    Covers phpMyAdmin, admin panels, debug pages, git repos, backups, etc.
    """
    def __init__(self, url: str, status_code: int, content_length: int,
                 module: str, label: str, evidence: List[str]):
        self.url            = url
        self.status_code    = status_code
        self.content_length = content_length
        self.module         = module   # key from SCAN_MODULES
        self.label          = label    # human label e.g. "phpMyAdmin / DB Admin"
        self.evidence       = evidence # matched signature lines / keywords
        self.risk_level     = "MEDIUM" # default; engine upgrades based on module
        self.raw_snippet    = ""       # first 500 chars of response


class ScanResult:
    def __init__(self, target: str):
        self.target          = target
        self.timestamp       = datetime.utcnow().isoformat()
        self.exposed_envs:  List[ExposedEnv]  = []
        self.exposed_pages: List[ExposedPage] = []   # NEW
        self.scan_status     = "pending"
        self.source          = "manual"  # manual | shodan | censys | crtsh | hackertarget | otx


# ─── DEFAULT ARGS ─────────────────────────────────────────────────────────────
class DefaultArgs:
    """
    Single place that defines every attribute with a safe default.
    Both the wizard and argparse CLI populate an instance of this,
    so the engine/reporter never encounter AttributeError.
    """
    def __init__(self):
        # Targets
        self.url: Optional[str]       = None
        self.file: Optional[str]      = None
        # Discovery
        self.discover: List[str]      = []
        self.shodan_key: Optional[str]= None
        self.shodan_query: List[str]  = []
        self.shodan_pages: int        = 1
        self.censys_id: Optional[str] = None
        self.censys_secret: Optional[str] = None
        self.censys_query: List[str]  = []
        self.use_crtsh: bool          = True
        self.use_hackertarget: bool   = True
        self.use_otx: bool            = True
        # Internal discovery query lists (wizard uses these)
        self._shodan_queries: List[str]  = []
        self._censys_queries: List[str]  = []
        # Scan
        self.threads: int             = 10
        self.timeout: int             = 10
        self.delay: float             = 0.0
        self.proxy: Optional[str]     = None
        self.aggressive: bool         = False
        self.extra_paths: List[str]   = []
        self.headers: List[str]       = []
        # Telegram
        self.tg_token: Optional[str]  = None
        self.tg_chat: Optional[str]   = None
        # Scheduler
        self.schedule: Optional[float]= None
        # Output
        self.output: str              = "./reports"
        self.json: bool               = False
        self.txt: bool                = False
        self.html: bool               = False
        self.all_reports: bool        = False
        self.redact: bool             = False
        self.show_content: bool       = False
        self.history: bool            = False
        self.verbose: bool            = False
        self.quiet: bool              = False


def merge_argparse(parsed) -> DefaultArgs:
    """Overlay an argparse Namespace onto DefaultArgs so every attr is guaranteed."""
    cfg = DefaultArgs()
    for key, val in vars(parsed).items():
        # argparse stores None for unset optional args — keep DefaultArgs default in that case
        if val is not None:
            setattr(cfg, key, val)
        # For boolean flags argparse returns False, not None — always honour those
        if isinstance(val, bool):
            setattr(cfg, key, val)
    # Derived flags from --no-X args
    cfg.use_crtsh        = not getattr(parsed, "no_crtsh",        False)
    cfg.use_hackertarget = not getattr(parsed, "no_hackertarget", False)
    cfg.use_otx          = not getattr(parsed, "no_otx",          False)
    # Derive CLI discovery query lists into the internal names the engine uses
    cfg._shodan_queries  = list(getattr(parsed, "shodan_query", None) or [])
    cfg._censys_queries  = list(getattr(parsed, "censys_query", None) or [])
    if cfg.all_reports:
        cfg.json = cfg.txt = cfg.html = True
    return cfg


# ─── STATE DATABASE ───────────────────────────────────────────────────────────
class StateDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.lock    = threading.Lock()
        self.conn    = sqlite3.connect(db_path, check_same_thread=False)
        self._init()

    def _init(self):
        with self.lock:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS seen_findings (
                    fingerprint TEXT PRIMARY KEY,
                    url         TEXT NOT NULL,
                    risk_level  TEXT NOT NULL,
                    categories  TEXT NOT NULL,
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL
                )
            """)
            self.conn.commit()

    def _fp(self, env: ExposedEnv) -> str:
        raw = env.url + "|" + "|".join(sorted(env.findings.keys()))
        return hashlib.sha256(raw.encode()).hexdigest()

    def is_new(self, env: ExposedEnv) -> bool:
        fp = self._fp(env)
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM seen_findings WHERE fingerprint=?", (fp,)
            ).fetchone()
        return row is None

    def mark_seen(self, env: ExposedEnv):
        fp   = self._fp(env)
        now  = datetime.utcnow().isoformat()
        cats = ",".join(env.findings.keys()) or "exposed"
        with self.lock:
            self.conn.execute("""
                INSERT INTO seen_findings (fingerprint,url,risk_level,categories,first_seen,last_seen)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(fingerprint) DO UPDATE SET last_seen=excluded.last_seen
            """, (fp, env.url, env.risk_level, cats, now, now))
            self.conn.commit()

    def get_history(self) -> list:
        with self.lock:
            return self.conn.execute(
                "SELECT url,risk_level,categories,first_seen,last_seen "
                "FROM seen_findings ORDER BY first_seen DESC"
            ).fetchall()

    def _fp_page(self, page) -> str:
        raw = page.url + "|page|" + page.module
        return hashlib.sha256(raw.encode()).hexdigest()

    def is_new_page(self, page) -> bool:
        fp = self._fp_page(page)
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM seen_findings WHERE fingerprint=?", (fp,)
            ).fetchone()
        return row is None

    def mark_seen_page(self, page):
        fp  = self._fp_page(page)
        now = datetime.utcnow().isoformat()
        with self.lock:
            self.conn.execute("""
                INSERT INTO seen_findings (fingerprint,url,risk_level,categories,first_seen,last_seen)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(fingerprint) DO UPDATE SET last_seen=excluded.last_seen
            """, (fp, page.url, page.risk_level, page.label, now, now))
            self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# ─── ASSET DISCOVERY ──────────────────────────────────────────────────────────
class AssetDiscovery:
    def __init__(self, args: DefaultArgs):
        self.args = args

    def _hdr(self) -> dict:
        return {"User-Agent": random.choice(USER_AGENTS)}

    def _norm_host(self, host: str, port: int = 443) -> str:
        scheme = "https" if port in (443, 8443) else "http"
        if port in (80, 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    # ── Shodan ────────────────────────────────────────────────────────────────
    def shodan_search(self, query: str) -> List[str]:
        if not self.args.shodan_key:
            console.print("[yellow]  [!] Shodan key not set — skipping.[/yellow]")
            return []
        targets: List[str] = []
        try:
            console.print(f"  [cyan]→ Shodan:[/cyan] {query}")
            for page in range(1, self.args.shodan_pages + 1):
                resp = requests.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": self.args.shodan_key, "query": query,
                            "page": page, "minify": True},
                    headers=self._hdr(), timeout=20
                )
                if resp.status_code == 401:
                    console.print("[red]  [!] Shodan: Invalid API key.[/red]")
                    break
                if resp.status_code != 200:
                    console.print(f"[red]  [!] Shodan HTTP {resp.status_code}[/red]")
                    break
                matches = resp.json().get("matches", [])
                if not matches:
                    break
                for m in matches:
                    port = m.get("port", 80)
                    for h in m.get("hostnames", []):
                        targets.append(self._norm_host(h, port))
                    ip = m.get("ip_str", "")
                    if ip and not m.get("hostnames"):
                        targets.append(self._norm_host(ip, port))
                console.print(f"    [dim]Page {page}: {len(matches)} results[/dim]")
                time.sleep(1)
        except Exception as e:
            console.print(f"[red]  [!] Shodan: {e}[/red]")
        unique = list(set(targets))
        console.print(f"  [green]✔ Shodan: {len(unique)} targets[/green]")
        return unique

    # ── Censys ────────────────────────────────────────────────────────────────
    def censys_search(self, query: str) -> List[str]:
        if not (self.args.censys_id and self.args.censys_secret):
            console.print("[yellow]  [!] Censys credentials not set — skipping.[/yellow]")
            return []
        targets: List[str] = []
        try:
            console.print(f"  [cyan]→ Censys:[/cyan] {query}")
            resp = requests.get(
                "https://search.censys.io/api/v2/hosts/search",
                params={"q": query, "per_page": 100},
                headers={"Accept": "application/json", **self._hdr()},
                auth=(self.args.censys_id, self.args.censys_secret),
                timeout=20
            )
            if resp.status_code == 401:
                console.print("[red]  [!] Censys: Invalid credentials.[/red]")
                return []
            if resp.status_code != 200:
                console.print(f"[red]  [!] Censys HTTP {resp.status_code}[/red]")
                return []
            for hit in resp.json().get("result", {}).get("hits", []):
                name = hit.get("name", "") or hit.get("ip", "")
                if name:
                    targets.append(f"https://{name}")
        except Exception as e:
            console.print(f"[red]  [!] Censys: {e}[/red]")
        unique = list(set(targets))
        console.print(f"  [green]✔ Censys: {len(unique)} targets[/green]")
        return unique

    # ── crt.sh ────────────────────────────────────────────────────────────────
    def crtsh_search(self, domain: str) -> List[str]:
        targets: List[str] = []
        try:
            console.print(f"  [cyan]→ crt.sh:[/cyan] *.{domain}")
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers=self._hdr(), timeout=30
            )
            if resp.status_code != 200:
                console.print(f"[yellow]  [!] crt.sh HTTP {resp.status_code}[/yellow]")
                return []
            seen: set = set()
            for entry in resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and "." in name and name not in seen:
                        seen.add(name)
                        targets.append(f"https://{name}")
        except Exception as e:
            console.print(f"[red]  [!] crt.sh: {e}[/red]")
        unique = list(set(targets))
        console.print(f"  [green]✔ crt.sh: {len(unique)} subdomains[/green]")
        return unique

    # ── HackerTarget ──────────────────────────────────────────────────────────
    def hackertarget_search(self, domain: str) -> List[str]:
        targets: List[str] = []
        try:
            console.print(f"  [cyan]→ HackerTarget:[/cyan] {domain}")
            resp = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                headers=self._hdr(), timeout=20
            )
            if resp.status_code != 200:
                console.print(f"[yellow]  [!] HackerTarget HTTP {resp.status_code}[/yellow]")
                return []
            text = resp.text.strip()
            if "error" in text.lower() or not text:
                console.print(f"[yellow]  [!] HackerTarget: {text[:80]}[/yellow]")
                return []
            for line in text.splitlines():
                if "," in line:
                    name = line.split(",", 1)[0].strip()
                    if name:
                        targets.append(f"https://{name}")
        except Exception as e:
            console.print(f"[red]  [!] HackerTarget: {e}[/red]")
        unique = list(set(targets))
        console.print(f"  [green]✔ HackerTarget: {len(unique)} subdomains[/green]")
        return unique

    # ── AlienVault OTX ────────────────────────────────────────────────────────
    def otx_search(self, domain: str) -> List[str]:
        targets: List[str] = []
        try:
            console.print(f"  [cyan]→ AlienVault OTX:[/cyan] {domain}")
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers=self._hdr(), timeout=20
            )
            if resp.status_code != 200:
                return []
            for rec in resp.json().get("passive_dns", []):
                h = rec.get("hostname", "").strip()
                if h:
                    targets.append(f"https://{h}")
        except Exception as e:
            console.print(f"[red]  [!] OTX: {e}[/red]")
        unique = list(set(targets))
        console.print(f"  [green]✔ OTX: {len(unique)} passive DNS records[/green]")
        return unique

    def discover_all(self, domains: List[str] = None,
                     shodan_queries: List[str] = None,
                     censys_queries: List[str] = None) -> List[str]:
        all_targets: List[str] = []
        console.print()
        console.print(Panel("[bold cyan]◉ Asset Discovery Phase[/bold cyan]", border_style="cyan"))

        for q in (shodan_queries or []):
            all_targets += self.shodan_search(q)

        for q in (censys_queries or []):
            all_targets += self.censys_search(q)

        for domain in (domains or []):
            domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
            if not domain:
                continue
            if self.args.use_crtsh:
                all_targets += self.crtsh_search(domain)
            if self.args.use_hackertarget:
                all_targets += self.hackertarget_search(domain)
            if self.args.use_otx:
                all_targets += self.otx_search(domain)

        deduped = list(set(all_targets))
        console.print(f"\n  [bold green]◉ Discovery complete — {len(deduped)} unique assets[/bold green]\n")
        return deduped


# ─── TELEGRAM NOTIFIER ────────────────────────────────────────────────────────
class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id   = chat_id
        self._base     = f"https://api.telegram.org/bot{bot_token}"

    def _send(self, text: str) -> bool:
        try:
            resp = requests.post(
                f"{self._base}/sendMessage",
                json={"chat_id": self.chat_id, "text": text, "parse_mode": "HTML"},
                timeout=15
            )
            if resp.status_code != 200:
                console.print(f"[red]  [!] Telegram HTTP {resp.status_code}: {resp.text[:100]}[/red]")
                return False
            return True
        except requests.exceptions.ConnectionError:
            console.print("[red]  [!] Telegram: Network unreachable.[/red]")
        except requests.exceptions.Timeout:
            console.print("[red]  [!] Telegram: Request timed out.[/red]")
        except Exception as e:
            console.print(f"[red]  [!] Telegram: {e}[/red]")
        return False

    def send_finding(self, env: ExposedEnv, target: str, is_new: bool = True) -> bool:
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(env.risk_level, "⚪")
        badge = "🆕 <b>NEW FINDING</b>\n" if is_new else ""
        if env.findings:
            cats = "\n".join(f"  • <code>{c}</code>" for c in env.findings.keys())
        else:
            cats = "  • <i>No sensitive keywords matched</i>"
        msg = (
            f"{badge}"
            f"{emoji} <b>EnvHunter Alert — {env.risk_level}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"🔗 <b>URL:</b> <code>{env.url}</code>\n"
            f"📊 <b>HTTP:</b> {env.status_code}  |  📏 <b>Size:</b> {env.content_length}B\n"
            f"🕐 <b>Time:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"\n🔑 <b>Secrets Detected:</b>\n{cats}\n"
            f"\n<i>EnvHunter v{VERSION} | {AUTHOR} | {TG_HANDLE}</i>"
        )
        return self._send(msg)

    def send_summary(self, stats: dict) -> bool:
        msg = (
            f"📋 <b>EnvHunter — Scan Complete</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 Targets Scanned : <b>{stats.get('scanned',0)}</b>\n"
            f"🚨 .env Exposed    : <b>{stats.get('exposed',0)}</b>\n"
            f"🌐 Pages Exposed   : <b>{stats.get('pages_found',0)}</b>\n"
            f"🔴 Critical        : <b>{stats.get('critical',0)}</b>\n"
            f"🆕 New Findings    : <b>{stats.get('new_findings',0)}</b>\n"
            f"🕐 Completed       : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"\n<i>EnvHunter v{VERSION} | {AUTHOR} | {TG_HANDLE}</i>"
        )
        return self._send(msg)

    def send_page_finding(self, page, target: str) -> bool:
        emoji  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(page.risk_level, "⚪")
        ev     = "\n".join(f"  • <code>{e}</code>" for e in page.evidence[:5]) or "  • <i>Confirmed accessible</i>"
        msg = (
            f"🆕 <b>NEW FINDING</b>\n"
            f"{emoji} <b>EnvHunter Alert — {page.risk_level}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"🔗 <b>URL:</b> <code>{page.url}</code>\n"
            f"📂 <b>Type:</b> {page.label}\n"
            f"📊 <b>HTTP:</b> {page.status_code}  |  📏 <b>Size:</b> {page.content_length}B\n"
            f"🕐 <b>Time:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"\n🔍 <b>Evidence:</b>\n{ev}\n"
            f"\n<i>EnvHunter v{{VERSION}} | {AUTHOR} | {TG_HANDLE}</i>"
        ).replace("{VERSION}", VERSION)
        return self._send(msg)

    def test_connection(self) -> bool:
        return self._send(
            f"✅ <b>EnvHunter v{VERSION}</b> — Telegram integration active.\n"
            f"Authored by {AUTHOR} | {TG_HANDLE}"
        )


# ─── SCAN ENGINE ──────────────────────────────────────────────────────────────
class EnvHunter:
    def __init__(self, args: DefaultArgs):
        self.args     = args
        self.session  = self._build_session()
        self.results: List[ScanResult] = []
        self.lock     = threading.Lock()
        self.stats    = {
            "total": 0, "exposed": 0, "critical": 0,
            "scanned": 0, "errors": 0, "new_findings": 0,
            "pages_found": 0,   # NEW: non-.env exposures
        }
        self.state_db = StateDB(DB_PATH)
        self.notifier: Optional[TelegramNotifier] = None
        if self.args.tg_token and self.args.tg_chat:
            self.notifier = TelegramNotifier(self.args.tg_token, self.args.tg_chat)

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        if self.args.proxy:
            s.proxies = {"http": self.args.proxy, "https": self.args.proxy}
        s.verify = False
        return s

    def _headers(self) -> dict:
        h = {
            "User-Agent":      random.choice(USER_AGENTS),
            "Accept":          "text/html,application/xhtml+xml,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection":      "keep-alive",
        }
        for raw in (self.args.headers or []):
            if ":" in raw:
                k, v = raw.split(":", 1)
                h[k.strip()] = v.strip()
        return h

    def _normalize(self, target: str) -> str:
        t = target.strip()
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        return t.rstrip("/")

    def _looks_like_env(self, text: str) -> bool:
        if re.search(r'<html|<body|<!doctype', text[:500], re.IGNORECASE):
            return False
        return len(re.findall(r'^[A-Z_][A-Z0-9_]*\s*=', text, re.MULTILINE)) >= 1

    def _is_fp(self, line: str) -> bool:
        return any(re.search(p, line) for p in FP_MARKERS)

    def _extract_findings(self, content: str) -> dict:
        findings: dict = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or self._is_fp(line):
                continue
            for cat, pat in SENSITIVE_PATTERNS.items():
                if re.search(pat, line):
                    display = line
                    if self.args.redact:
                        display = re.sub(r'(=\s*)(.{3}).+', r'\1\2****[REDACTED]', line)
                    findings.setdefault(cat, [])
                    if display not in findings[cat]:
                        findings[cat].append(display)
        return findings

    def _risk_level(self, findings: dict) -> str:
        crit = {"Database Credentials", "API Keys", "Cloud Credentials",
                "Auth / JWT Secrets", "Passwords", "Private Keys/Certs"}
        high = {"SMTP / Mail", "OAuth / SSO", "Stripe / Payment", "Twilio / SMS"}
        if any(c in findings for c in crit):
            return "CRITICAL"
        if any(c in findings for c in high):
            return "HIGH"
        if findings:
            return "MEDIUM"
        return "LOW"

    def _fetch_url(self, url: str) -> Optional[ExposedEnv]:
        """Fetch one URL and return an ExposedEnv if it looks like a real .env file."""
        try:
            resp = self.session.get(
                url, headers=self._headers(),
                allow_redirects=False,
                timeout=self.args.timeout
            )
            if resp.status_code not in (200, 206):
                return None

            ct = resp.headers.get("Content-Type", "")
            if not self.args.aggressive:
                bad = ("text/html", "application/json", "image/", "video/", "audio/")
                if any(b in ct for b in bad):
                    return None

            try:
                content = resp.text
            except Exception:
                content = resp.content.decode("utf-8", errors="replace")

            if not self._looks_like_env(content):
                return None

            env = ExposedEnv(url, resp.status_code, len(content), ct)
            env.raw_content = content
            env.findings    = self._extract_findings(content)
            env.risk_level  = self._risk_level(env.findings)
            return env

        except requests.exceptions.SSLError:
            # Retry over plain HTTP
            if url.startswith("https://"):
                return self._fetch_url(url.replace("https://", "http://"))
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects):
            pass
        except Exception as e:
            if self.args.verbose:
                console.print(f"[dim red]  [!] {url}: {e}[/dim red]")
        return None

    def _page_risk(self, module: str) -> str:
        """Assign risk level based on which module detected the exposure."""
        critical = {"phpmyadmin", "backup_files", "ssh_keys", "git_exposure"}
        high     = {"admin_panels", "config_files", "devops_files", "php_info"}
        medium   = {"server_status", "log_files", "wordpress", "api_exposure",
                    "package_files"}
        low      = {"env_files"}  # handled separately by _fetch_url
        if module in critical: return "CRITICAL"
        if module in high:     return "HIGH"
        if module in medium:   return "MEDIUM"
        return "LOW"

    def _fetch_page(self, url: str, module: str) -> Optional[ExposedPage]:
        """
        Fetch a non-.env URL and check if it's genuinely exposed.
        Uses MODULE_SIGNATURES to confirm the page is real (not a soft 404).
        Returns ExposedPage if confirmed exposed, None otherwise.
        """
        try:
            resp = self.session.get(
                url, headers=self._headers(),
                allow_redirects=True,   # follow redirects for admin panels
                timeout=self.args.timeout
            )
            if resp.status_code not in (200, 206):
                return None

            try:
                content = resp.text
            except Exception:
                content = resp.content.decode("utf-8", errors="replace")

            if not content or len(content) < 20:
                return None

            # Check against module signatures to reject soft 404s
            sigs = MODULE_SIGNATURES.get(module, [])
            evidence: List[str] = []

            if sigs:
                for sig in sigs:
                    matches = re.findall(sig, content[:5000])
                    if matches:
                        # Deduplicate and clean evidence
                        for m in matches[:3]:
                            m_str = m if isinstance(m, str) else m[0]
                            if m_str and m_str not in evidence:
                                evidence.append(m_str[:80])
                if not evidence:
                    return None  # No signature match — likely soft 404
            else:
                # No signatures defined — trust HTTP 200 + content length
                if len(content) < 100:
                    return None

            label      = SCAN_MODULES.get(module, {}).get("label", module)
            page       = ExposedPage(url, resp.status_code, len(content),
                                     module, label, evidence)
            page.risk_level  = self._page_risk(module)
            page.raw_snippet = content[:500]
            return page

        except requests.exceptions.SSLError:
            if url.startswith("https://"):
                return self._fetch_page(url.replace("https://", "http://"), module)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects):
            pass
        except Exception as e:
            if self.args.verbose:
                console.print(f"[dim red]  [!] {url}: {e}[/dim red]")
        return None

    def scan_target(self, target: str) -> ScanResult:
        target = self._normalize(target)
        result = ScanResult(target)
        result.scan_status = "running"

        # ── Phase 1: .env file scanning (existing logic) ───────────────────
        env_paths = list(SCAN_MODULES["env_files"]["paths"])
        for p in (self.args.extra_paths or []):
            if p not in env_paths:
                env_paths.append(p)

        for path in env_paths:
            url = target + path
            env = self._fetch_url(url)
            if env:
                result.exposed_envs.append(env)
                is_new = self.state_db.is_new(env)
                self.state_db.mark_seen(env)

                if self.args.verbose:
                    rc    = {"CRITICAL": "red", "HIGH": "yellow",
                             "MEDIUM": "cyan", "LOW": "green"}.get(env.risk_level, "white")
                    badge = "[bold green][NEW][/bold green]   " if is_new else "[dim][KNOWN][/dim] "
                    console.print(f"  {badge}[bold {rc}]✓ .env [{env.risk_level}] {url}[/bold {rc}]")

                if self.notifier and is_new:
                    self.notifier.send_finding(env, target, is_new=True)
                    with self.lock:
                        self.stats["new_findings"] += 1

            if self.args.delay:
                time.sleep(random.uniform(self.args.delay * 0.5, self.args.delay))

        # ── Phase 2: Web exposure scanning (new in v4.0) ───────────────────
        for mod_key, mod_cfg in SCAN_MODULES.items():
            if mod_key == "env_files":
                continue  # already handled above
            if not mod_cfg.get("enabled", True):
                continue

            for path in mod_cfg["paths"]:
                url  = target + path
                page = self._fetch_page(url, mod_key)
                if page:
                    result.exposed_pages.append(page)
                    is_new = self.state_db.is_new_page(page)
                    self.state_db.mark_seen_page(page)

                    if self.args.verbose:
                        rc    = {"CRITICAL": "red", "HIGH": "yellow",
                                 "MEDIUM": "cyan", "LOW": "green"}.get(page.risk_level, "white")
                        badge = "[bold green][NEW][/bold green]   " if is_new else "[dim][KNOWN][/dim] "
                        console.print(
                            f"  {badge}[bold {rc}]✓ {page.label} [{page.risk_level}] {url}[/bold {rc}]"
                        )

                    if self.notifier and is_new:
                        self.notifier.send_page_finding(page, target)
                        with self.lock:
                            self.stats["new_findings"] += 1

                if self.args.delay:
                    time.sleep(random.uniform(self.args.delay * 0.5, self.args.delay))

        result.scan_status = "done"
        return result

    def run(self, targets: List[str]) -> List[ScanResult]:
        self.stats["total"] = len(targets)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[bold white]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[bold cyan]Scanning targets...", total=len(targets))
            with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                futures = {executor.submit(self.scan_target, t): t for t in targets}
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        with self.lock:
                            self.results.append(result)
                            self.stats["scanned"] += 1
                            if result.exposed_envs:
                                self.stats["exposed"] += 1
                                for env in result.exposed_envs:
                                    if env.risk_level == "CRITICAL":
                                        self.stats["critical"] += 1
                        if result.exposed_pages:
                            self.stats["pages_found"] += len(result.exposed_pages)
                            for page in result.exposed_pages:
                                if page.risk_level == "CRITICAL":
                                    self.stats["critical"] += 1
                    except Exception as e:
                        with self.lock:
                            self.stats["errors"] += 1
                        if self.args.verbose:
                            console.print(f"[red]  [!] Scan error: {e}[/red]")
                    finally:
                        progress.advance(task)

        if self.notifier:
            self.notifier.send_summary(self.stats)

        return self.results

    def close(self):
        self.state_db.close()
        try:
            self.session.close()
        except Exception:
            pass


# ─── REPORTER ─────────────────────────────────────────────────────────────────
RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "yellow",
    "MEDIUM":   "cyan",
    "LOW":      "green",
}

class Reporter:
    def __init__(self, results: List[ScanResult], stats: dict, args: DefaultArgs):
        self.results = results
        self.stats   = stats
        self.args    = args

    def _rc(self, level: str) -> str:
        return RISK_COLORS.get(level, "white")

    def print_summary_table(self):
        console.print()
        t = Table(
            title="[bold cyan]Scan Summary[/bold cyan]",
            box=box.DOUBLE_EDGE, border_style="cyan", show_lines=True
        )
        t.add_column("Target",        style="bold white", no_wrap=True)
        t.add_column("Source",        justify="center")
        t.add_column(".env Status",   justify="center")
        t.add_column(".env Paths",    justify="center")
        t.add_column("Pages Found",   justify="center")
        t.add_column("Findings",      justify="center")
        t.add_column("Risk",          justify="center")
        for r in self.results:
            src_label = f"[dim]{r.source}[/dim]"
            # Determine highest risk across both env and page findings
            all_risks  = ([e.risk_level for e in r.exposed_envs] +
                          [p.risk_level for p in r.exposed_pages])
            risk_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            highest    = max(all_risks, key=lambda x: risk_order.index(x)) if all_risks else None
            tf         = sum(len(v) for e in r.exposed_envs for v in e.findings.values())
            pages_n    = len(r.exposed_pages)

            if r.exposed_envs or r.exposed_pages:
                env_status = "[bold green]✓ .env EXPOSED[/bold green]" if r.exposed_envs else "[dim]✗ .env Clean[/dim]"
                t.add_row(
                    r.target, src_label, env_status,
                    str(len(r.exposed_envs)),
                    str(pages_n) if pages_n else "[dim]0[/dim]",
                    str(tf),
                    f"[{self._rc(highest)}]{highest}[/{self._rc(highest)}]"
                )
            else:
                t.add_row(r.target, src_label, "[dim]✗ Clean[/dim]",
                          "0", "0", "0", "[dim]—[/dim]")
        console.print(t)

    def print_findings(self):
        for r in self.results:
            if not r.exposed_envs:
                continue
            console.print()
            console.print(Panel(
                f"[bold white]Target:[/bold white] {r.target}  [dim]({r.source})[/dim]\n"
                f"[bold white]Time:[/bold white]   {r.timestamp}",
                title="[bold cyan]◉ Exposed Target[/bold cyan]", border_style="cyan"
            ))
            for env in r.exposed_envs:
                rc = self._rc(env.risk_level)
                console.print(
                    f"\n  [bold white]URL:[/bold white] {env.url}\n"
                    f"  [bold white]HTTP:[/bold white] {env.status_code}  "
                    f"[bold white]Size:[/bold white] {env.content_length}B  "
                    f"[bold white]Risk:[/bold white] [{rc}]{env.risk_level}[/{rc}]"
                )
                if env.findings:
                    ft = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
                    ft.add_column("Category",      style="bold yellow")
                    ft.add_column("Matched Lines", style="white")
                    for cat, lines in env.findings.items():
                        for i, ln in enumerate(lines):
                            ft.add_row(cat if i == 0 else "", ln[:120])
                    console.print(ft)
                else:
                    console.print("  [dim]  .env found but no sensitive keywords matched.[/dim]")
                if self.args.show_content:
                    console.print(Panel(
                        env.raw_content[:3000],
                        title="[dim]Raw .env Content (first 3000 chars)[/dim]",
                        border_style="dim"
                    ))

    def print_stats(self):
        console.print()
        console.print(Panel(
            f"[bold white]Total Targets  :[/bold white]  {self.stats.get('total', 0)}\n"
            f"[bold white]Scanned        :[/bold white]  {self.stats.get('scanned', 0)}\n"
            f"[bold green].env Exposed   :[/bold green]  {self.stats.get('exposed', 0)}\n"
            f"[bold green]Pages Exposed  :[/bold green]  {self.stats.get('pages_found', 0)}\n"
            f"[bold red]Critical       :[/bold red]  {self.stats.get('critical', 0)}\n"
            f"[bold cyan]New Findings   :[/bold cyan]  {self.stats.get('new_findings', 0)}\n"
            f"[bold yellow]Errors         :[/bold yellow]  {self.stats.get('errors', 0)}",
            title="[bold cyan]◉ Final Statistics[/bold cyan]", border_style="cyan"
        ))

    def print_page_findings(self):
        """Print all non-.env web exposure findings."""
        page_results = [r for r in self.results if r.exposed_pages]
        if not page_results:
            return
        console.print()
        console.print(Panel(
            "[bold white]Non-.env resources publicly accessible[/bold white]",
            title="[bold cyan]◉ Web Exposure Findings[/bold cyan]", border_style="cyan"
        ))
        for r in page_results:
            for page in r.exposed_pages:
                rc = self._rc(page.risk_level)
                console.print(
                    f"\n  [{rc}]■[/{rc}] [bold white]{page.label}[/bold white]  "
                    f"[{rc}][{page.risk_level}][/{rc}]"
                )
                console.print(f"    [bold white]URL   :[/bold white] {page.url}")
                console.print(f"    [bold white]HTTP  :[/bold white] {page.status_code}  "
                              f"[bold white]Size:[/bold white] {page.content_length}B")
                if page.evidence:
                    console.print("    [bold white]Evidence:[/bold white]")
                    for ev in page.evidence[:5]:
                        console.print(f"      [dim yellow]→[/dim yellow] {ev}")
                if self.args.show_content and page.raw_snippet:
                    console.print(Panel(
                        page.raw_snippet[:500],
                        title="[dim]Response Snippet[/dim]", border_style="dim"
                    ))

    def save_json(self, path: str):
        data = []
        for r in self.results:
            if not r.exposed_envs:
                continue
            entry = {
                "target": r.target, "source": r.source,
                "timestamp": r.timestamp,
                "exposed_env_files": [],
                "exposed_pages": [],
            }
            for env in r.exposed_envs:
                entry["exposed_env_files"].append({
                    "url":            env.url,
                    "status_code":    env.status_code,
                    "content_length": env.content_length,
                    "content_type":   env.content_type,
                    "risk_level":     env.risk_level,
                    "findings":       env.findings,
                    "raw_content":    env.raw_content if not self.args.redact else "[REDACTED]",
                })
            for page in r.exposed_pages:
                entry["exposed_pages"].append({
                    "url":            page.url,
                    "status_code":    page.status_code,
                    "content_length": page.content_length,
                    "module":         page.module,
                    "label":          page.label,
                    "risk_level":     page.risk_level,
                    "evidence":       page.evidence,
                    "raw_snippet":    page.raw_snippet if not self.args.redact else "[REDACTED]",
                })
            data.append(entry)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            console.print(f"[bold green]✔[/bold green] JSON → [cyan]{path}[/cyan]")
        except OSError as e:
            console.print(f"[red]  [!] Could not write JSON: {e}[/red]")

    def save_txt(self, path: str):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"EnvHunter v{VERSION} | {AUTHOR} | {TG_HANDLE}\n")
                f.write(f"Date: {datetime.utcnow().isoformat()} UTC\n")
                f.write("=" * 70 + "\n\n")
                exposed_count = 0
                for r in self.results:
                    if not r.exposed_envs:
                        continue
                    exposed_count += 1
                    f.write(f"TARGET: {r.target}  [source: {r.source}]\n")
                    for env in r.exposed_envs:
                        f.write(f"  URL:        {env.url}\n")
                        f.write(f"  HTTP:       {env.status_code}\n")
                        f.write(f"  Size:       {env.content_length}B\n")
                        f.write(f"  Risk Level: {env.risk_level}\n")
                        for cat, lines in env.findings.items():
                            f.write(f"  [{cat}]\n")
                            for ln in lines:
                                f.write(f"    {ln}\n")
                        f.write("\n")
                for page in r.exposed_pages:
                    f.write(f"  [WEB EXPOSURE] {page.label}\n")
                    f.write(f"  URL:        {page.url}\n")
                    f.write(f"  HTTP:       {page.status_code}\n")
                    f.write(f"  Size:       {page.content_length}B\n")
                    f.write(f"  Risk Level: {page.risk_level}\n")
                    for ev in page.evidence:
                        f.write(f"    → {ev}\n")
                    f.write("\n")
                if exposed_count == 0:
                    f.write("No exposed .env files found.\n")
            console.print(f"[bold green]✔[/bold green] TXT  → [cyan]{path}[/cyan]")
        except OSError as e:
            console.print(f"[red]  [!] Could not write TXT: {e}[/red]")

    def save_html(self, path: str):
        rows = ""
        for r in self.results:
            if not r.exposed_envs:
                continue
            for env in r.exposed_envs:
                rc = {"CRITICAL": "critical", "HIGH": "high",
                      "MEDIUM": "medium", "LOW": "low"}.get(env.risk_level, "low")
                fh = ""
                for c, ls in env.findings.items():
                    fh += f"<b>{c}:</b><br>"
                    for ln in ls:
                        # HTML-escape angle brackets
                        safe_ln = ln.replace("<", "&lt;").replace(">", "&gt;")
                        fh += f"&nbsp;&nbsp;<code>{safe_ln[:120]}</code><br>"
                if not fh:
                    fh = "<em>No sensitive keywords matched</em>"
                safe_url    = env.url.replace('"', "&quot;")
                safe_target = r.target.replace("<", "&lt;").replace(">", "&gt;")
                rows += (
                    f"<tr>"
                    f"<td>{safe_target}<br><small class='src'>[{r.source}]</small></td>"
                    f"<td><a href=\"{safe_url}\" target=\"_blank\">{env.url}</a></td>"
                    f"<td>{env.status_code}</td>"
                    f"<td>{env.content_length}</td>"
                    f"<td><span class='badge {rc}'>{env.risk_level}</span></td>"
                    f"<td class='findings'>{fh}</td>"
                    f"</tr>"
                )
        # ── Page findings rows ──────────────────────────────────────────
        page_rows = ""
        for r in self.results:
            for page in r.exposed_pages:
                rc2   = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low"}.get(page.risk_level,"low")
                evh   = "".join(f"<code>{ev.replace('<','&lt;').replace('>','&gt;')}</code><br>" for ev in page.evidence[:5]) or "<em>Accessible</em>"
                safe_t = r.target.replace("<","&lt;").replace(">","&gt;")
                safe_u = page.url.replace('"', "&quot;")
                page_rows += (
                    f"<tr>"
                    f"<td>{safe_t}<br><small class='src'>[{r.source}]</small></td>"
                    f"<td><a href=\"{safe_u}\" target=\"_blank\">{page.url}</a></td>"
                    f"<td>{page.status_code}</td>"
                    f"<td>{page.content_length}</td>"
                    f"<td><span class='badge {rc2}'>{page.risk_level}</span></td>"
                    f"<td class='findings'><b>{page.label}</b><br>{evh}</td>"
                    f"</tr>"
                )

        if not rows:
            rows = "<tr><td colspan='6' style='text-align:center;color:#6e7681'>.env scan: No exposures found.</td></tr>"
        if not page_rows:
            page_rows = "<tr><td colspan='6' style='text-align:center;color:#6e7681'>Web exposure scan: No exposures found.</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EnvHunter Report</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Courier New',monospace;background:#0d0d0d;color:#c9d1d9;padding:24px}}
    h1{{color:#58a6ff;text-align:center;margin-bottom:6px;font-size:1.6rem}}
    .meta{{color:#8b949e;text-align:center;margin-bottom:28px;font-size:.85rem}}
    table{{width:100%;border-collapse:collapse;font-size:.88rem}}
    th{{background:#161b22;color:#58a6ff;padding:10px 12px;border:1px solid #30363d;text-align:left}}
    td{{padding:9px 12px;border:1px solid #21262d;vertical-align:top;word-break:break-all}}
    tr:nth-child(even){{background:#0f0f0f}}
    tr:hover{{background:#1a1f27}}
    .badge{{display:inline-block;padding:3px 9px;border-radius:4px;font-weight:bold;font-size:.8rem}}
    .critical{{background:#7f1d1d;color:#fca5a5}}
    .high{{background:#78350f;color:#fcd34d}}
    .medium{{background:#1e3a5f;color:#93c5fd}}
    .low{{background:#14532d;color:#86efac}}
    .findings{{font-size:.82em;line-height:1.7}}
    .src{{color:#6e7681;font-size:.8em}}
    a{{color:#58a6ff;text-decoration:none}}
    a:hover{{text-decoration:underline}}
    code{{background:#161b22;padding:1px 4px;border-radius:3px;font-size:.85em}}
  </style>
</head>
<body>
  <h1>🔍 EnvHunter Report</h1>
  <p class="meta">
    By {AUTHOR} | {TG_HANDLE} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
  </p>
  <h2 style="color:#58a6ff;margin:20px 0 10px">.env File Exposures</h2>
  <table>
    <thead>
      <tr>
        <th>Target</th><th>Exposed URL</th><th>HTTP</th>
        <th>Size</th><th>Risk</th><th>Findings</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>

  <h2 style="color:#58a6ff;margin:30px 0 10px">Web Exposure Findings</h2>
  <p style="color:#8b949e;font-size:.85em;margin-bottom:12px">
    phpMyAdmin, Admin Panels, Debug Pages, Config Files, Git Repos, Backups, SSH Keys, and more
  </p>
  <table>
    <thead>
      <tr>
        <th>Target</th><th>Exposed URL</th><th>HTTP</th>
        <th>Size</th><th>Risk</th><th>Type / Evidence</th>
      </tr>
    </thead>
    <tbody>{page_rows}</tbody>
  </table>
</body>
</html>"""
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            console.print(f"[bold green]✔[/bold green] HTML → [cyan]{path}[/cyan]")
        except OSError as e:
            console.print(f"[red]  [!] Could not write HTML: {e}[/red]")


# ─── SCHEDULER ────────────────────────────────────────────────────────────────
class ScheduledRunner:
    """Runs EnvHunter on a repeating interval. SIGINT-safe on all platforms."""

    def __init__(self, args: DefaultArgs, target_factory):
        self.args           = args
        self.target_factory = target_factory
        self._stop          = threading.Event()

    def _run_once(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        console.print(Panel(
            f"[bold cyan]◉ Scheduled Run[/bold cyan] — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            border_style="cyan"
        ))
        targets = self.target_factory()
        if not targets:
            console.print("[yellow]  No targets for this run.[/yellow]")
            return

        hunter   = EnvHunter(self.args)
        results  = hunter.run(targets)
        reporter = Reporter(results, hunter.stats, self.args)
        reporter.print_summary_table()
        reporter.print_page_findings()
        reporter.print_stats()

        out_dir = self.args.output
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        base = os.path.join(out_dir, f"scheduled_{ts}")
        reporter.save_json(base + ".json")
        reporter.save_txt(base  + ".txt")
        reporter.save_html(base + ".html")
        hunter.close()

    def start(self, interval_hours: float):
        console.print(Panel(
            f"[bold white]Scheduler active[/bold white] — every [bold cyan]{interval_hours}h[/bold cyan]\n"
            f"Press [bold red]Ctrl+C[/bold red] to stop.",
            title="[bold cyan]◉ EnvHunter Scheduler[/bold cyan]", border_style="cyan"
        ))

        # SIGINT is the only signal handler reliably supported on Windows
        original_handler = signal.getsignal(signal.SIGINT)

        def _stop_handler(sig, frame):
            console.print("\n[yellow]  Scheduler stopped by user.[/yellow]")
            self._stop.set()
            # Restore original so second Ctrl+C force-kills
            signal.signal(signal.SIGINT, original_handler)

        signal.signal(signal.SIGINT, _stop_handler)

        # Run immediately, then schedule
        self._run_once()
        schedule.every(interval_hours).hours.do(self._run_once)

        while not self._stop.is_set():
            schedule.run_pending()
            # Sleep in small chunks so Ctrl+C is responsive
            for _ in range(6):
                if self._stop.is_set():
                    break
                time.sleep(5)


# ─── HELPERS ──────────────────────────────────────────────────────────────────
def _load_targets_file(path: str) -> List[str]:
    if not os.path.isfile(path):
        console.print(f"[red]  [!] File not found: {path}[/red]")
        sys.exit(1)
    with open(path, encoding="utf-8", errors="replace") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def _print_history():
    db   = StateDB(DB_PATH)
    rows = db.get_history()
    db.close()
    if not rows:
        console.print("\n[dim]  No findings in the state database yet.[/dim]\n")
        return
    t = Table(
        title="[bold cyan]Historical Findings[/bold cyan]",
        box=box.SIMPLE_HEAVY, border_style="cyan", show_lines=True
    )
    t.add_column("URL",        style="cyan",        no_wrap=False, max_width=60)
    t.add_column("Risk",       justify="center",    min_width=8)
    t.add_column("Categories", style="yellow",      no_wrap=False)
    t.add_column("First Seen", min_width=19)
    t.add_column("Last Seen",  min_width=19)
    for row in rows:
        rc = RISK_COLORS.get(row[1], "white")
        t.add_row(row[0], f"[{rc}]{row[1]}[/{rc}]", row[2], row[3][:19], row[4][:19])
    console.print(t)


# ─── INTERACTIVE WIZARD ───────────────────────────────────────────────────────
def interactive_wizard():
    console.print(BANNER)
    console.print(Panel(
        "[bold white]EnvHunter v4.0 — Web Exposure & Secrets Recon Framework[/bold white]\n"
        "[dim]Authorized use only. Scan only systems you own or have explicit permission to test.[/dim]",
        border_style="cyan"
    ))

    # ── Mode select ───────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ SELECT MODE ][/bold cyan]")
    console.print("  [bold white]scan[/bold white]           Scan manually provided targets")
    console.print("  [bold white]discover+scan[/bold white]  Auto-discover assets via APIs, then scan")
    console.print("  [bold white]scheduler[/bold white]      Repeat scans every N hours automatically")
    console.print("  [bold white]history[/bold white]        View all previously detected exposures")
    console.print()
    mode = Prompt.ask("  Mode", choices=["scan", "discover+scan", "scheduler", "history"], default="scan")

    if mode == "history":
        _print_history()
        return

    # ── Build args object with full defaults ──────────────────────────────────
    args = DefaultArgs()

    # ── Target input ──────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ TARGET INPUT ][/bold cyan]")
    inp = Prompt.ask("  Input method", choices=["single", "file"], default="single")
    manual_targets: List[str] = []
    if inp == "single":
        while True:
            t = Prompt.ask("  Enter target URL (e.g. https://example.com)")
            if t.strip():
                manual_targets.append(t.strip())
            if not Confirm.ask("  Add another target?", default=False):
                break
    else:
        fp = Prompt.ask("  Path to targets file")
        manual_targets = _load_targets_file(fp)
        console.print(f"  [green]✔ Loaded {len(manual_targets)} targets[/green]")

    # ── Discovery ─────────────────────────────────────────────────────────────
    discovery_domains: List[str] = []
    if mode in ("discover+scan", "scheduler"):
        console.print("\n[bold cyan][ ASSET DISCOVERY ][/bold cyan]")
        seed_raw = Prompt.ask(
            "  Seed domain(s) for discovery (comma-separated)\n"
            "  e.g. example.com, app.example.com"
        )
        discovery_domains = [d.strip() for d in seed_raw.split(",") if d.strip()]

        console.print("\n  [bold white]Free sources (no API key required):[/bold white]")
        args.use_crtsh        = Confirm.ask("    crt.sh  (SSL certificate transparency)", default=True)
        args.use_hackertarget = Confirm.ask("    HackerTarget subdomain search",          default=True)
        args.use_otx          = Confirm.ask("    AlienVault OTX passive DNS",             default=True)

        console.print("\n  [bold white]API-based sources:[/bold white]")
        if Confirm.ask("    Use Shodan? [requires paid API key]", default=False):
            args.shodan_key   = Prompt.ask("    Shodan API key")
            args.shodan_pages = prompt_int("    Pages to fetch (1 page ≈ 100 results) [1-10]", default=1, min_val=1, max_val=10)
            sq = Prompt.ask("    Shodan query  e.g. hostname:example.com http.status:200")
            args._shodan_queries = [sq]

        if Confirm.ask("    Use Censys? [requires API credentials]", default=False):
            args.censys_id     = Prompt.ask("    Censys API ID")
            args.censys_secret = Prompt.ask("    Censys API Secret", password=True)
            cq = Prompt.ask("    Censys query  e.g. services.http.response.headers.server: nginx")
            args._censys_queries = [cq]

    # ── Scan options ──────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ SCAN OPTIONS ][/bold cyan]")
    args.threads = prompt_int(
        "  Concurrent threads        [recommended: 10-20]",
        default=10, min_val=1, max_val=100
    )
    args.timeout = prompt_int(
        "  Request timeout seconds   [recommended: 10]",
        default=10, min_val=1, max_val=120
    )
    args.delay = prompt_float(
        "  Delay between requests    [0=none | 0.5=safe | 1=stealth]",
        default=0.0, min_val=0.0, max_val=60.0
    )
    args.redact       = Confirm.ask("  Redact secret values in all output?",        default=False)
    args.aggressive   = Confirm.ask("  Aggressive mode (check all content types)?", default=False)
    args.verbose      = Confirm.ask("  Verbose output (print each URL checked)?",   default=True)
    args.show_content = Confirm.ask("  Print raw .env content in terminal?",        default=False)

    proxy_raw = Prompt.ask("  Proxy URL (leave blank to skip)", default="")
    if proxy_raw.strip():
        args.proxy = proxy_raw.strip()

    # ── Telegram ──────────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ TELEGRAM ALERTS ][/bold cyan]")
    if Confirm.ask("  Enable Telegram alerts for new findings only?", default=False):
        args.tg_token = Prompt.ask("  Bot Token  (from @BotFather)")
        args.tg_chat  = Prompt.ask("  Chat ID    (your user ID or group ID)")
        notifier = TelegramNotifier(args.tg_token, args.tg_chat)
        if notifier.test_connection():
            console.print("  [bold green]✔ Telegram connection verified[/bold green]")
        else:
            console.print("  [red]  ✗ Telegram test failed — double-check your token and chat ID[/red]")

    # ── Output options ────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ OUTPUT ][/bold cyan]")
    args.output  = Prompt.ask("  Output directory", default="./reports")
    args.json    = Confirm.ask("  Save JSON report?", default=True)
    args.txt     = Confirm.ask("  Save TXT report?",  default=True)
    args.html    = Confirm.ask("  Save HTML report?", default=True)

    # ── Scheduler ─────────────────────────────────────────────────────────────
    if mode == "scheduler":
        console.print("\n[bold cyan][ SCHEDULER ][/bold cyan]")
        interval = prompt_float("  Scan interval in hours  [e.g. 6, 12, 24]", default=24.0, min_val=0.1, max_val=8760.0)

        def target_factory() -> List[str]:
            t = list(manual_targets)
            if discovery_domains:
                disc = AssetDiscovery(args)
                t += disc.discover_all(
                    domains=discovery_domains,
                    shodan_queries=args._shodan_queries,
                    censys_queries=args._censys_queries,
                )
            return list(set(t))

        runner = ScheduledRunner(args, target_factory)
        runner.start(interval)
        return

    # ── Build final target list ───────────────────────────────────────────────
    all_targets = list(manual_targets)
    if mode == "discover+scan" and discovery_domains:
        disc = AssetDiscovery(args)
        all_targets += disc.discover_all(
            domains=discovery_domains,
            shodan_queries=args._shodan_queries,
            censys_queries=args._censys_queries,
        )
        all_targets = list(set(all_targets))

    if not all_targets:
        console.print("[red]  No targets to scan. Exiting.[/red]")
        return

    # ── Launch summary ────────────────────────────────────────────────────────
    console.print()
    console.print(Panel(
        f"[bold white]Total Targets :[/bold white]  {len(all_targets)}\n"
        f"[bold white]Threads       :[/bold white]  {args.threads}\n"
        f"[bold white]Timeout       :[/bold white]  {args.timeout}s\n"
        f"[bold white]Delay         :[/bold white]  {args.delay}s\n"
        f"[bold white]Redact        :[/bold white]  {args.redact}\n"
        f"[bold white]Proxy         :[/bold white]  {args.proxy or 'None'}\n"
        f"[bold white]Telegram      :[/bold white]  {'✔ Enabled' if args.tg_token else '✗ Disabled'}\n"
        f"[bold white]Output dir    :[/bold white]  {args.output}",
        title="[bold cyan]◉ Scan Configuration[/bold cyan]", border_style="cyan"
    ))

    if not Confirm.ask("\n  [bold yellow]▶ Launch scan?[/bold yellow]", default=True):
        console.print("[dim]  Aborted.[/dim]")
        return

    hunter   = EnvHunter(args)
    results  = hunter.run(all_targets)
    reporter = Reporter(results, hunter.stats, args)

    reporter.print_summary_table()
    reporter.print_findings()
    reporter.print_page_findings()
    reporter.print_stats()

    Path(args.output).mkdir(parents=True, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(args.output, f"envhunter_{ts}")
    if args.json: reporter.save_json(base + ".json")
    if args.txt:  reporter.save_txt(base  + ".txt")
    if args.html: reporter.save_html(base + ".html")

    hunter.close()


# ─── CLI ARG PARSER ───────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="envhunter",
        description=f"EnvHunter v{VERSION} — Web Exposure & Secrets Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"  Author: {AUTHOR}  |  Telegram: {TG_HANDLE}"
    )

    inp = p.add_argument_group("Input")
    inp.add_argument("-u", "--url",  default=None, help="Single target URL")
    inp.add_argument("-f", "--file", default=None, help="File with target URLs (one per line)")

    disc = p.add_argument_group("Asset Discovery")
    disc.add_argument("--discover",         nargs="+", metavar="DOMAIN", default=None,
                      help="Seed domains for asset discovery")
    disc.add_argument("--shodan-key",       metavar="KEY",    default=None, help="Shodan API key")
    disc.add_argument("--shodan-query",     nargs="+",        default=None, help="Shodan search queries")
    disc.add_argument("--shodan-pages",     type=int,         default=1,    help="Shodan pages (default 1)")
    disc.add_argument("--censys-id",        metavar="ID",     default=None, help="Censys API ID")
    disc.add_argument("--censys-secret",    metavar="SECRET", default=None, help="Censys API Secret")
    disc.add_argument("--censys-query",     nargs="+",        default=None, help="Censys queries")
    disc.add_argument("--no-crtsh",         action="store_true", help="Disable crt.sh")
    disc.add_argument("--no-hackertarget",  action="store_true", help="Disable HackerTarget")
    disc.add_argument("--no-otx",           action="store_true", help="Disable AlienVault OTX")

    sc = p.add_argument_group("Scan Options")
    sc.add_argument("-t", "--threads",   type=int,   default=10)
    sc.add_argument("--timeout",         type=int,   default=10)
    sc.add_argument("--delay",           type=float, default=0.0)
    sc.add_argument("--proxy",           default=None, metavar="URL")
    sc.add_argument("--aggressive",      action="store_true")
    sc.add_argument("--extra-paths",     nargs="+",  default=None)
    sc.add_argument("-H", "--headers",   nargs="+",  default=None)

    tg = p.add_argument_group("Telegram")
    tg.add_argument("--tg-token",  metavar="TOKEN", default=None, help="Telegram bot token")
    tg.add_argument("--tg-chat",   metavar="ID",    default=None, help="Telegram chat/group ID")
    tg.add_argument("--tg-test",   action="store_true",           help="Send test message and exit")

    sched = p.add_argument_group("Scheduler")
    sched.add_argument("--schedule", type=float, default=None, metavar="HOURS",
                       help="Run repeatedly every N hours")

    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output",   default="./reports")
    out.add_argument("--json",           action="store_true")
    out.add_argument("--txt",            action="store_true")
    out.add_argument("--html",           action="store_true")
    out.add_argument("--all-reports",    action="store_true", help="Save JSON + TXT + HTML")
    out.add_argument("--redact",         action="store_true", help="Redact secret values in output")
    out.add_argument("--show-content",   action="store_true", help="Print raw .env content")
    out.add_argument("--history",        action="store_true", help="Show stored findings and exit")
    out.add_argument("-v", "--verbose",  action="store_true")
    out.add_argument("-q", "--quiet",    action="store_true")

    return p


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) == 1:
        interactive_wizard()
        return

    parser = build_parser()
    parsed = parser.parse_args()

    # Merge into DefaultArgs (guarantees every attribute exists)
    args = merge_argparse(parsed)

    if not args.quiet:
        console.print(BANNER)

    # ── History ────────────────────────────────────────────────────────────────
    if args.history:
        _print_history()
        return

    # ── Telegram test ──────────────────────────────────────────────────────────
    if getattr(parsed, "tg_test", False):
        if not (args.tg_token and args.tg_chat):
            console.print("[red]  --tg-token and --tg-chat are required for --tg-test[/red]")
            sys.exit(1)
        ok = TelegramNotifier(args.tg_token, args.tg_chat).test_connection()
        console.print("  " + ("[green]✔ Telegram: Success[/green]" if ok else "[red]✗ Telegram: Failed[/red]"))
        return

    # ── Collect manual targets ─────────────────────────────────────────────────
    manual_targets: List[str] = []
    if args.url:
        manual_targets.append(args.url)
    if args.file:
        manual_targets += _load_targets_file(args.file)

    # ── Target factory ─────────────────────────────────────────────────────────
    def build_targets() -> List[str]:
        t = list(manual_targets)
        disc_domains   = args.discover or []
        shodan_queries = args._shodan_queries
        censys_queries = args._censys_queries
        if disc_domains or shodan_queries or censys_queries:
            disc = AssetDiscovery(args)
            t += disc.discover_all(
                domains=disc_domains,
                shodan_queries=shodan_queries,
                censys_queries=censys_queries,
            )
        return list(set(t))

    # ── Scheduler ─────────────────────────────────────────────────────────────
    if args.schedule:
        runner = ScheduledRunner(args, build_targets)
        runner.start(args.schedule)
        return

    # ── Single run ─────────────────────────────────────────────────────────────
    all_targets = build_targets()
    if not all_targets:
        console.print("[red]  No targets provided. Use -u <url>, -f <file>, or --discover <domain>.[/red]")
        parser.print_help()
        sys.exit(1)

    console.print(Panel(
        f"[bold white]Targets  :[/bold white] {len(all_targets)}\n"
        f"[bold white]Threads  :[/bold white] {args.threads}\n"
        f"[bold white]Timeout  :[/bold white] {args.timeout}s\n"
        f"[bold white]Proxy    :[/bold white] {args.proxy or 'None'}\n"
        f"[bold white]Redact   :[/bold white] {args.redact}\n"
        f"[bold white]Telegram :[/bold white] {'✔' if args.tg_token else '✗'}\n"
        f"[bold white]Output   :[/bold white] {args.output}",
        title="[bold cyan]◉ Scan Configuration[/bold cyan]", border_style="cyan"
    ))

    hunter   = EnvHunter(args)
    results  = hunter.run(all_targets)
    reporter = Reporter(results, hunter.stats, args)

    if not args.quiet:
        reporter.print_summary_table()
        reporter.print_findings()
        reporter.print_page_findings()
    reporter.print_stats()

    Path(args.output).mkdir(parents=True, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(args.output, f"envhunter_{ts}")
    if args.json: reporter.save_json(base + ".json")
    if args.txt:  reporter.save_txt(base  + ".txt")
    if args.html: reporter.save_html(base + ".html")

    hunter.close()


if __name__ == "__main__":
    main()
