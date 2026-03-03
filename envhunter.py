#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ███████╗███╗   ██╗██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗           ║
║   ██╔════╝████╗  ██║██║   ██║██║  ██║██║   ██║████╗  ██║           ║
║   █████╗  ██╔██╗ ██║██║   ██║███████║██║   ██║██╔██╗ ██║           ║
║   ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██╔══██║██║   ██║██║╚██╗██║           ║
║   ███████╗██║ ╚████║ ╚████╔╝ ██║  ██║╚██████╔╝██║ ╚████║           ║
║   ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝           ║
║                                                                      ║
║       .env Exposure & Secrets Recon Framework  v4.2                  ║
║               Author : g33l0  |  Telegram : @x0x0h33l0              ║
╚══════════════════════════════════════════════════════════════════════╝
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
    import importlib, sys, os
    try:
        return importlib.import_module(pkg)
    except ImportError:
        name = install_name or pkg
        # On Windows, 'python' and 'python3' can point to different installs.
        # Show both pip and pip3 commands so the user uses the right one.
        win_note = (
            "\n  Windows tip: run the pip that matches the python you used to\n"
            "  launch this script. If 'python envhunter.py' use 'pip install'.\n"
            "  If 'python3 envhunter.py' use 'pip3 install'.\n"
            "  Or use: python -m pip install " + name
        ) if os.name == "nt" else ""
        print(f"\n[ERROR] Missing package '{name}'. Install it with:\n"
              f"        pip install {name}\n"
              f"  or install all requirements:\n"
              f"        pip install -r requirements.txt"
              + win_note + "\n")
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
VERSION   = "4.2"
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
║    [bold white]  .env Exposure & Secrets Recon Framework  v4.2[/bold white][bold cyan]        ║
║      [bold red]  Author : g33l0[/bold red][bold cyan]  |  [bold green]Telegram : @x0x0h33l0[/bold green][bold cyan]           ║
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
            "/user/login", "/auth/login",
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
    # Note: wp-login.php removed — it is a normal page, not an exposure.
    # We target paths that genuinely leak data when publicly accessible.
    "wordpress": {
        "enabled": True,
        "label":   "WordPress",
        "paths": [
            "/wp-json/wp/v2/users",     # user enumeration via REST API
            "/wp-content/debug.log",    # debug log — may contain DB errors, passwords
            "/wp-content/uploads/.htaccess",  # htaccess may be missing, exposing uploads
            "/xmlrpc.php",              # XML-RPC — brute force / info disclosure
            "/?author=1",               # legacy author enumeration
            "/wp-config-sample.php",    # config sample — may contain real credentials
            "/wp-admin/install.php",    # re-installation page — should be inaccessible post-install
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
    "General Secrets":      r'(?im)^[A-Z_]*(SECRET|TOKEN|KEY|CREDENTIAL|PASSWD)[A-Z0-9_]*\s*=\s*\S{8,}',
    # ── Extended patterns (v4.x) ─────────────────────────────────────────────
    "Docker / DevOps":      r'(?i)(docker_pass|registry_pass|ci_token|deploy_key|ansible_pass|vault_token|terraform)',
    "SSH / Private Keys":   r'(?i)(-----BEGIN|RSA PRIVATE|OPENSSH PRIVATE|DSA PRIVATE|EC PRIVATE|ssh-rsa|ssh-ed25519)',
    "Spring Boot Actuator": r'(?i)(spring\.datasource|spring\.security|management\.endpoints)',
    "WordPress Secrets":    r'(?i)(DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|table_prefix)',
    "Laravel App Config":   r'(?i)(APP_KEY=base64|APP_DEBUG=true|APP_ENV=local|cipher=AES)',
    "Database DSN":         r'(?i)(mysql://|postgres://|postgresql://|mongodb://|redis://|sqlite://)',
    "Internal IPs":         r'(?i)(db_host|redis_host|memcached_host|mq_host)[\s]*[=:][\s]*(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)',
}

# ── Per-module content signatures ─────────────────────────────────────────────
# Used by the exposure scanner to validate that a page response is genuinely
# the resource we expect (not a 200 OK catch-all / soft 404).

MODULE_SIGNATURES: dict = {
    # ═══ SIGNATURE DESIGN RULES ═══════════════════════════════════════════════
    # 1. OR logic: ANY single matching signature = confirmed exposure
    # 2. Each signature must be SPECIFIC to the genuine resource
    #    — it must NOT match normal web pages, login forms, or error pages
    # 3. Evidence extracted = the matched line from response (full context)
    # 4. When in doubt, be MORE strict: false negatives are better than
    #    false positives (we alert on what is real, not what might be real)
    # ══════════════════════════════════════════════════════════════════════════

    # ── phpMyAdmin: only fire on pages that ARE phpMyAdmin ───────────────────
    # Generic MySQL login pages (Adminer, custom DB tools) need their own paths
    "phpmyadmin": [
        r'(?i)(id="pma_|class="pma|pmahomme|PMA_VERSION|pma_navigation)',
        r'(?i)<title>\s*phpMyAdmin\s*</title>',
        r'(?i)(pma_token|pma_lang|pma_charset|pmaAbsoluteUri)',
    ],

    # ── Admin panels: specific hosting/framework control panels ONLY ─────────
    # Login forms are NOT an exposure — every site has a login page.
    # We only flag UNPROTECTED admin interfaces that expose data directly.
    # flask-admin/django-admin on a login page is NOT a finding — we need
    # the actual admin content (list views, model data) to be exposed.
    "admin_panels": [
        r'(?i)(cpanel|whm_login|plesk\s+login|directadmin)',
        r'(?i)<title>[^<]*(cpanel|webmin|plesk|directadmin|WHM)[^<]*</title>',
        r'(?i)(webmin\.cgi|webmin/index\.cgi)',
        r'(?i)(Joomla\s+Administration\s+Login)',
        # Django admin: only fire on the actual admin list/change pages, NOT login
        r'(?i)<title>[^<]*\|\s*Django\s+site\s+admin[^<]*</title>',
        # Flask-Admin: only fire on pages with the actual admin panel nav
        r'(?i)class="flask-admin\b',
    ],

    # ── PHP info: phpinfo() table structure — unique, cannot appear in HTML ──
    # Must match the specific two-column info table phpinfo() generates.
    # class="e" alone is far too broad (any HTML table can have class="e").
    "php_info": [
        r'(?i)PHP\s+Version\s*</td>',
        r'(?i)(Configure\s+Command\s*</td>|Build\s+Date\s*</td>)',
        r'(?i)Loaded\s+Configuration\s+File\s*</td>',
        r'(?i)<title>\s*phpinfo\s*\(\s*\)',
    ],

    # ── Server status: Apache/Nginx/Spring specific output format ────────────
    "server_status": [
        r'(?i)(Apache\s+Server\s+Status|Requests\s+currently\s+being\s+processed)',
        r'(?i)(Active\s+connections:\s*\d|server\s+accepts\s+handled\s+requests)',
        r'(?i)"status"\s*:\s*"(UP|DOWN)"\s*,\s*"(components|groups|details)"',
        r'(?i)("diskSpace"\s*:\s*\{|"db"\s*:\s*\{.*"status")',
    ],

    # ── Config files: require actual secret assignment syntax ────────────────
    # Words like 'key', 'host', 'token' on a webpage are NOT config findings
    "config_files": [
        r'(?im)^(DB_PASSWORD|DB_PASS|DATABASE_PASSWORD|MYSQL_PASSWORD)\s*=\s*\S',
        r'(?im)^(APP_KEY|SECRET_KEY|API_KEY|JWT_SECRET)\s*=\s*\S',
        r"(?i)define\s*\(\s*['\"]DB_PASSWORD['\"]",
        r'(?i)["\']password["\']\s*:\s*["\'][^"\']{4,}["\']',
    ],

    # ── Backup files: real SQL dump syntax ───────────────────────────────────
    "backup_files": [
        r'(?i)INSERT\s+INTO\s+`?\w+`?\s*VALUES\s*\(',
        r'(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?\w',
        r'(?i)(mysqldump\s+\d+\.\d+|-- Dump completed on)',
    ],

    # ── Git exposure: OR logic, each pattern matches ONE specific git file ────
    # Fixes the globant.com false positive where HTML <head> matched (?i)HEAD
    # These patterns CANNOT appear in normal HTML pages:
    #   - A 40-char hex string followed by "refs/" is exclusively packed-refs
    #   - "[core]" on its own line is exclusively .git/config
    #   - "ref: refs/heads/" is exclusively .git/HEAD content
    "git_exposure": [
        r'(?m)^[0-9a-f]{40}\s+refs/',          # packed-refs: SHA40 + ref path
        r'(?m)^\[core\]\s*$',                   # .git/config: [core] section header
        r'(?m)^ref:\s*refs/heads/\S',           # .git/HEAD: ref pointer format
        r'(?m)^repositoryformatversion\s*=\s*\d',  # .git/config version field
    ],

    # ── Log files: require actual log line format with timestamp/level ───────
    "log_files": [
        r'\[\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
        r'(?i)(Stack\s+trace:|Traceback\s+\(most\s+recent\s+call)',
        r'(?i)SQLSTATE\[',
        r'(?i)Illuminate\\(Database|Http|Auth)',
    ],

    # ── SSH keys: BEGIN header is unmistakable and cannot appear in HTML ──────
    "ssh_keys": [
        r'-----BEGIN\s+(RSA |DSA |EC |OPENSSH )?PRIVATE\s+KEY-----',
        r'-----BEGIN\s+CERTIFICATE-----',
    ],

    # ── Package files: require JSON manifest structure ────────────────────────
    # Split multi-line patterns — literal newlines in r-strings are valid but
    # must use (?s) or \n explicitly so they work across line boundaries.
    "package_files": [
        r'"name"\s*:\s*"[\w@/\-\.]+"\s*,',
        r'"version"\s*:\s*"\d+\.\d+',
        r'"dependencies"\s*:\s*\{',
        r'"require"\s*:\s*\{\s*"php"\s*:',
    ],

    # ── DevOps files: docker-compose/Dockerfile specific syntax ──────────────
    "devops_files": [
        r'(?m)^services:\s*$',
        r'(?m)^FROM\s+\S+',
        r'(?m)^(RUN|ENV|COPY|ARG|EXPOSE)\s+\S',
        r'(?im)(DOCKER_PASSWORD|REGISTRY_TOKEN|CI_TOKEN|VAULT_ADDR)',
    ],

    # ── API docs: Swagger/OpenAPI JSON document structure ────────────────────
    # "paths":{} alone matches ANY JSON API response — must require the swagger
    # or openapi version field that only appears in spec documents.
    "api_exposure": [
        r'"swagger"\s*:\s*"[23]\.',
        r'"openapi"\s*:\s*"[23]\.',
        r'"swaggerVersion"\s*:\s*"[12]\.',
        r'(?i)<title>[^<]*swagger\s*ui[^<]*</title>',
        r'(?i)Swagger\s+UI\s*[-–]',
    ],

    # ── WordPress: specific data-leaking WP responses ────────────────────────
    # NOT wp-login.php (that's normal). Only actually-leaking endpoints.
    "wordpress": [
        r'"id"\s*:\s*\d+\s*,\s*"name"\s*:\s*"[^"]+"\s*,\s*"url"\s*:',
        r'(?i)XML-RPC\s+server\s+accepts\s+POST\s+requests\s+only',
        r'(?i)<methodResponse>',
        r'(?i)"capabilities"\s*:\s*\{\s*"edit_posts"',
    ],

    # .env files use _looks_like_env() — no signatures needed here
    "env_files": [],
}
FP_MARKERS = [
    r'(?i)^#',                    # comment lines
    r'(?i)=\s*$',                 # empty value
    r'(?i)=\s*null\b',            # null value
    r'(?i)=\s*false\b',           # false value
    r'(?i)=\s*true\b',            # true value (standalone booleans are not secrets)
    r'(?i)=\s*your_',             # placeholder: your_key, your_secret etc.
    r'(?i)=\s*<',                 # placeholder: <value>, <TOKEN>
    r'(?i)=\s*\{',                # object placeholder
    r'(?i)=\s*\[',                # array placeholder
    r'(?i)_example\b',            # example suffix
    r'(?i)_placeholder\b',        # placeholder suffix
    r'(?i)change.?me\b',          # change-me placeholder
    r'(?i)xxx+',                  # xxx placeholder
    r'(?i)=\s*enter.{0,20}here',  # "enter value here" placeholder
    r'(?i)=\s*replace.{0,20}this',# "replace this" placeholder
    r'(?i)=\s*todo\b',            # TODO placeholder
    r'(?i)=\s*\*+\s*$',          # asterisks only (redacted display)
    r'(?i)^(login|username|password|user|email)\s*$',  # standalone words (not KEY=val)
]

# Pre-compiled for performance — avoids repeated re.compile() in hot paths
# FP_MARKERS: strip per-pattern (?i) flags, apply re.IGNORECASE globally.
# Joining patterns that each contain (?i) raises re.error on Python 3.6+:
#   "global flags not at the start of the expression"
# because only the FIRST sub-pattern in a joined OR may set global flags.
def _strip_inline_flags(pat: str) -> str:
    """Remove leading (?iflag) groups so patterns can be safely joined with |"""
    return re.sub(r"^\(\?[imsxaul]+\)", "", pat)

_FP_RE_COMPILED = re.compile(
    "|".join(_strip_inline_flags(p) for p in FP_MARKERS),
    re.IGNORECASE | re.MULTILINE
)
# SENSITIVE_PATTERNS: compiled individually so their own inline flags are safe
_SENS_RE_COMPILED = {cat: re.compile(pat) for cat, pat in SENSITIVE_PATTERNS.items()}

# (Pre-compiled regexes are defined below, after _strip_inline_flags is declared)

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/121.0",
    "curl/7.88.1",
]


# ─── TARGET DEDUPLICATION ─────────────────────────────────────────────────────
def _dedup_targets(targets: list) -> "List[str]":
    """
    Deduplicate targets intelligently:
    - Treats http://x.com and https://x.com as the SAME host (keeps https)
    - Strips trailing slashes before comparing
    - Preserves first-occurrence order
    Real-world: crt.sh returns https://, a user's targets file has http://
    Without this the same site is scanned twice, doubling noise and load.
    """
    from urllib.parse import urlparse as _up
    seen: dict = {}  # lowercased netloc → canonical URL
    for raw in targets:
        url = raw.strip().rstrip("/")
        if not url:
            continue
        try:
            p = _up(url if "://" in url else "https://" + url)
            key = p.netloc.lower()
            if not key:
                continue
            if key not in seen:
                seen[key] = url
            elif url.startswith("https://") and seen[key].startswith("http://"):
                seen[key] = url  # upgrade plain http to https
        except Exception:
            seen.setdefault(url, url)
    return list(seen.values())


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
                    kind        TEXT NOT NULL DEFAULT 'env',
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL
                )
            """)
            # Migrate existing DBs that don't have the kind column yet
            try:
                self.conn.execute("ALTER TABLE seen_findings ADD COLUMN kind TEXT NOT NULL DEFAULT 'env'")
            except Exception:
                pass  # Column already exists
            self.conn.commit()

    def _fp(self, env: ExposedEnv) -> str:
        raw = env.url + "|" + "|".join(sorted(env.findings.keys()))
        return hashlib.sha256(raw.encode()).hexdigest()

    def mark_seen_atomic(self, env: ExposedEnv) -> bool:
        """
        Atomically insert the finding and return True if it was NEW.
        Uses INSERT OR IGNORE so that the first thread to write wins.
        Checking rowcount inside the same lock eliminates the race condition
        where two threads both call is_new()→True then both fire Telegram alerts.
        """
        fp   = self._fp(env)
        now  = datetime.utcnow().isoformat()
        cats = ",".join(env.findings.keys()) or "exposed"
        with self.lock:
            cur = self.conn.execute("""
                INSERT OR IGNORE INTO seen_findings
                    (fingerprint, url, risk_level, categories, kind, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 'env', ?, ?)
            """, (fp, env.url, env.risk_level, cats, now, now))
            if cur.rowcount == 0:
                # Row already existed — update last_seen only
                self.conn.execute(
                    "UPDATE seen_findings SET last_seen=? WHERE fingerprint=?", (now, fp)
                )
            self.conn.commit()
            return cur.rowcount > 0  # True = new finding, False = already known

    # Backwards-compat aliases used by scan_target
    def is_new(self, env: ExposedEnv) -> bool:
        fp = self._fp(env)
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM seen_findings WHERE fingerprint=?", (fp,)
            ).fetchone()
        return row is None

    def mark_seen(self, env: ExposedEnv):
        self.mark_seen_atomic(env)  # delegates; return value discarded

    def get_history(self) -> list:
        with self.lock:
            return self.conn.execute(
                "SELECT url,risk_level,categories,kind,first_seen,last_seen "
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

    def mark_seen_page_atomic(self, page) -> bool:
        """Atomically record a page finding. Returns True if it was new."""
        fp  = self._fp_page(page)
        now = datetime.utcnow().isoformat()
        with self.lock:
            cur = self.conn.execute("""
                INSERT OR IGNORE INTO seen_findings
                    (fingerprint, url, risk_level, categories, kind, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 'page', ?, ?)
            """, (fp, page.url, page.risk_level, page.label, now, now))
            if cur.rowcount == 0:
                self.conn.execute(
                    "UPDATE seen_findings SET last_seen=? WHERE fingerprint=?", (now, fp)
                )
            self.conn.commit()
            return cur.rowcount > 0

    def mark_seen_page(self, page):
        self.mark_seen_page_atomic(page)

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
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        s = requests.Session()
        if self.args.proxy:
            s.proxies = {"http": self.args.proxy, "https": self.args.proxy}
        s.verify = False
        # Connection pooling: large pool for many concurrent threads
        # Retry once on connection reset / transient errors (not on 4xx/5xx)
        retry = Retry(total=1, connect=1, read=0, status=0, raise_on_status=False)
        adapter = HTTPAdapter(
            pool_connections=20,
            pool_maxsize=max(self.args.threads, 20),
            max_retries=retry,
        )
        s.mount("http://",  adapter)
        s.mount("https://", adapter)
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
        """
        Normalise a target URL to a bare origin: scheme://host[:port]
        Strip any path components the user accidentally included.
        Example: https://example.com/app/v2 → https://example.com
        This ensures every path in SCAN_MODULES is appended to the root.
        """
        t = target.strip()
        # Ensure scheme is present so urllib can parse it
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        # Strip path, query, fragment — we only want origin
        from urllib.parse import urlparse as _up
        p = _up(t)
        origin = f"{p.scheme}://{p.netloc}"
        # Preserve non-standard ports (already in netloc)
        return origin.rstrip("/")

    def _looks_like_env(self, text: str) -> bool:
        # Strip BOM (Byte Order Mark) — Windows editors add \ufeff to files.
        # Without stripping it, the HTML check and KEY=VALUE scan both fail
        # on the first character of an otherwise valid .env file.
        text = text.lstrip('\ufeff\ufffe\xef\xbb\xbf')
        # Reject HTML pages immediately
        if re.search(r'<html|<body|<!doctype', text[:500], re.IGNORECASE):
            return False
        # Reject pure JSON responses — but ONLY if the entire body is JSON.
        # Do NOT reject .env files that happen to have a JSON-like first line
        # (e.g. corrupted files, merged configs). Check if the whole body
        # parses as JSON, not just if the first char is '{' or '['.
        stripped = text.strip()
        if stripped.startswith(('{', '[')):
            try:
                import json as _json
                _json.loads(stripped)
                # Successfully parsed as pure JSON — not an .env file
                return False
            except Exception:
                # Failed to parse — may be a .env with a JSON-looking first line
                # Don't reject it; let the KEY=VALUE scan below decide.
                pass
        # Require at least 2 KEY=VALUE lines where VALUE is non-empty and non-trivial.
        # KEY must be at least 1 char (changed from {2,} which required 3+, causing
        # keys like 'DB=', 'PW=' to be completely invisible to the scanner).
        real_kv = re.findall(
            r'^[A-Z_][A-Z0-9_]*\s*=\s*[^\s#\n][^\n]{0,}',
            text, re.MULTILINE
        )
        # Filter out lines that are placeholder values, not real secrets
        actual = [
            ln for ln in real_kv
            if not re.search(
                r'(?i)(=\s*null\b|=\s*false\b|=\s*true\b|=\s*<|=\s*\{|'
                r'change.?me|your_|_example|_placeholder|xxx+|=\s*$)',
                ln
            )
        ]
        return len(actual) >= 2

    def _is_fp(self, line: str) -> bool:
        return bool(_FP_RE_COMPILED.search(line))

    def _extract_findings(self, content: str) -> dict:
        findings: dict = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or self._is_fp(line):
                continue
            for cat, _cre in _SENS_RE_COMPILED.items():
                if _cre.search(line):
                    display = line
                    if self.args.redact:
                        # Redact: keep key name, hide entire value — never expose any chars
                        display = re.sub(r'(=\s*)(.+)', r'\1****[REDACTED]', line)
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
                timeout=(5, self.args.timeout),  # (connect_timeout, read_timeout)
            )
            if resp.status_code not in (200, 206):
                return None

            ct = resp.headers.get("Content-Type", "")
            if not self.args.aggressive:
                # Only hard-block binary content types — never a .env file
                binary = ("image/", "video/", "audio/", "application/pdf",
                          "application/zip", "application/octet-stream",
                          "font/")
                if any(b in ct for b in binary):
                    return None
                # text/html CAN be a .env file on misconfigured servers —
                # let _looks_like_env() decide, don't block here

            try:
                content = resp.text
            except Exception:
                content = resp.content.decode("utf-8", errors="replace")

            if not self._looks_like_env(content):
                return None

            # Use byte length for accurate size reporting (matches HTTP Content-Length)
            byte_len = len(resp.content)
            env = ExposedEnv(url, resp.status_code, byte_len, ct)
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

        KEY DESIGN DECISIONS:
        - Redirects are DISABLED by default. A genuine exposed resource
          responds 200 directly. If /admin/ redirects to /login.php that
          means the admin panel is PROTECTED — it requires authentication.
          Following the redirect would land on a login form which contains
          "password" and "username" words, causing false positives.
        - Signatures require ALL patterns in the list to match (AND logic).
          This prevents single broad words from triggering a finding.
        - Evidence shown in the report is the matched line from the
          response, not just the tiny regex token.
        """
        # Modules where following redirects is valid
        # (e.g. server status pages sometimes redirect to their canonical path)
        redirect_ok = {"server_status", "api_exposure", "php_info"}

        try:
            resp = self.session.get(
                url,
                headers=self._headers(),
                allow_redirects=(module in redirect_ok),
                timeout=(5, self.args.timeout),  # (connect_timeout, read_timeout)
            )

            # Only accept direct 200/206 — redirects mean the resource is
            # protected or moved; 403/401 means it exists but is locked.
            if resp.status_code not in (200, 206):
                return None

            try:
                content = resp.text
            except Exception:
                content = resp.content.decode("utf-8", errors="replace")

            if not content or len(content) < 50:
                return None

            # ── Module-specific content-type guard ────────────────────────────
            # Raw file modules (git, ssh, backup, package, devops, config)
            # should NEVER return HTML — if they do it's a soft 404 or CMS page.
            raw_file_modules = {
                "git_exposure", "ssh_keys", "backup_files",
                "package_files", "devops_files", "config_files", "log_files"
            }
            if module in raw_file_modules:
                if re.search(r'<html|<!doctype|<head\b|<body\b', content[:500], re.IGNORECASE):
                    return None

            # ── Soft 404 detection ─────────────────────────────────────────────
            # Many sites return HTTP 200 for every non-existent URL
            # with a custom "Page Not Found" page. Reject these BEFORE
            # running signature checks to avoid false positives.
            SOFT_404_PATTERNS = [
                r'(?i)<title>[^<]*(404|not.?found|page.?not.?found|error)[^<]*</title>',
                r'(?i)(the page you (are looking for|requested) (could not be found|does not exist))',
                r'(?i)(404\s*[-–—]\s*(not found|page not found|file not found))',
                r'(?i)(this page (doesn.t|does not) exist)',
                r'(?i)(oops[.!]?\s+(something went wrong|page not found|we can.t find))',
                r'(?i)(no\s+such\s+file\s+or\s+directory)',
            ]
            head = content[:3000]
            for _s404 in SOFT_404_PATTERNS:
                if re.search(_s404, head):
                    return None  # Confirmed soft 404 — discard

            # ── Signature validation ───────────────────────────────────────────
            # OR logic: ANY one signature match = confirmed genuine exposure.
            # Each signature is specific enough that a single match is conclusive.
            sigs = MODULE_SIGNATURES.get(module, [])
            evidence: List[str] = []

            if sigs:
                search_zone = content[:8000]  # check first 8KB for speed
                # ── OR logic: ANY one signature match = confirmed exposure ──────
                # Each signature is specific enough that a single match is conclusive.
                # Different files in the same module (e.g. .git/HEAD vs .git/config
                # vs packed-refs) each match different patterns — AND logic would
                # require ALL to match simultaneously which is impossible for
                # single-file responses. OR logic is correct here.
                first_match = None
                for sig in sigs:
                    m = re.search(sig, search_zone, re.MULTILINE)
                    if m:
                        first_match = m
                        break
                if not first_match:
                    return None  # No signature matched — not a genuine exposure
                # Extract evidence: full line containing the match (shows real context)
                # This replaces the old "bare matched word" approach that showed
                # evidence like "• head" instead of "• ref: refs/heads/main"
                for sig in sigs:
                    m = re.search(sig, search_zone, re.MULTILINE)
                    if not m:
                        continue
                    m_pos      = m.start()
                    line_start = search_zone.rfind('\n', 0, m_pos) + 1
                    line_end   = search_zone.find('\n', m.end())
                    if line_end == -1:
                        line_end = min(m_pos + 200, len(search_zone))
                    raw_line   = search_zone[line_start:line_end].strip()
                    # Strip HTML tags for clean display in Telegram/reports
                    clean_line = re.sub(r'<[^>]+>', ' ', raw_line)
                    clean_line = re.sub(r'\s+', ' ', clean_line).strip()
                    if not clean_line:
                        clean_line = m.group(0)[:80].strip()
                    if clean_line and clean_line not in evidence:
                        evidence.append(clean_line[:120])
                    if len(evidence) >= 4:
                        break
            else:
                # No signatures defined for this module — trust HTTP 200 only
                # if the content is substantial (not a redirect/error page)
                if len(content) < 200:
                    return None
                # Additional guard: reject if it looks like an HTML page
                # when we expected a raw file (backup, key, etc.)
                if re.search(r'<html|<!doctype', content[:200], re.IGNORECASE):
                    return None

            label            = SCAN_MODULES.get(module, {}).get("label", module)
            page             = ExposedPage(url, resp.status_code, len(resp.content),
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
                is_new = self.state_db.mark_seen_atomic(env)

                if self.args.verbose:
                    rc    = {"CRITICAL": "red", "HIGH": "yellow",
                             "MEDIUM": "cyan", "LOW": "green"}.get(env.risk_level, "white")
                    badge = "[bold green][NEW][/bold green]   " if is_new else "[dim][KNOWN][/dim] "
                    console.print(f"  {badge}[bold {rc}]✓ .env [{env.risk_level}] {url}[/bold {rc}]")

                if self.notifier and is_new and env.risk_level != "LOW":
                    self.notifier.send_finding(env, target, is_new=True)
                    with self.lock:
                        self.stats["new_findings"] += 1

            if self.args.delay:
                time.sleep(random.uniform(self.args.delay * 0.5, self.args.delay))

        # ── Phase 2: Web exposure scanning (added v4.0) ─────────────────────
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
                    is_new = self.state_db.mark_seen_page_atomic(page)

                    if self.args.verbose:
                        rc    = {"CRITICAL": "red", "HIGH": "yellow",
                                 "MEDIUM": "cyan", "LOW": "green"}.get(page.risk_level, "white")
                        badge = "[bold green][NEW][/bold green]   " if is_new else "[dim][KNOWN][/dim] "
                        console.print(
                            f"  {badge}[bold {rc}]✓ {page.label} [{page.risk_level}] {url}[/bold {rc}]"
                        )

                    if self.notifier and is_new and page.risk_level not in ("LOW",):
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
                                self.stats["exposed"] += len(result.exposed_envs)
                                for env in result.exposed_envs:
                                    if env.risk_level == "CRITICAL":
                                        self.stats["critical"] += 1
                            # pages_found inside lock — thread safe
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
            # Include target if it has ANY finding — env OR page exposure
            if not r.exposed_envs and not r.exposed_pages:
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
                    # BUG 7 FIX: include targets with page findings even if no .env
                    if not r.exposed_envs and not r.exposed_pages:
                        continue
                    exposed_count += 1
                    f.write(f"TARGET: {r.target}  [source: {r.source}]\n")
                    # .env file findings
                    for env in r.exposed_envs:
                        f.write(f"  [.ENV FILE]\n")
                        f.write(f"  URL:        {env.url}\n")
                        f.write(f"  HTTP:       {env.status_code}\n")
                        f.write(f"  Size:       {env.content_length}B\n")
                        f.write(f"  Risk Level: {env.risk_level}\n")
                        for cat, lines in env.findings.items():
                            f.write(f"  [{cat}]\n")
                            for ln in lines:
                                f.write(f"    {ln}\n")
                        f.write("\n")
                    # Web exposure page findings — BUG 7: indentation was broken
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
                    f.write("No exposures found.\n")
            console.print(f"[bold green]✔[/bold green] TXT  → [cyan]{path}[/cyan]")
        except OSError as e:
            console.print(f"[red]  [!] Could not write TXT: {e}[/red]")

    def save_html(self, path: str):
        rows = ""
        for r in self.results:
            # BUG FIX: don't skip targets that only have page findings
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
    .stats-bar{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0 24px;justify-content:center}}
    .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center;min-width:90px}}
    .stat.critical{{border-color:#7f1d1d}}
    .stat.high{{border-color:#78350f}}
    .stat-val{{display:block;font-size:1.6rem;font-weight:bold;color:#58a6ff}}
    .stat.critical .stat-val{{color:#fca5a5}}
    .stat.high .stat-val{{color:#fcd34d}}
    .stat-lbl{{display:block;font-size:.75rem;color:#8b949e;margin-top:2px;text-transform:uppercase;letter-spacing:.05em}}
  </style>
</head>
<body>
  <h1>🔍 EnvHunter Report</h1>
  <p class="meta">
    By {AUTHOR} | {TG_HANDLE} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
  </p>
  <div class="stats-bar">
    <div class="stat"><span class="stat-val">{self.stats.get("scanned",0)}</span><span class="stat-lbl">Targets Scanned</span></div>
    <div class="stat critical"><span class="stat-val">{self.stats.get("exposed",0)}</span><span class="stat-lbl">.env Exposed</span></div>
    <div class="stat high"><span class="stat-val">{self.stats.get("pages_found",0)}</span><span class="stat-lbl">Web Exposures</span></div>
    <div class="stat critical"><span class="stat-val">{self.stats.get("critical",0)}</span><span class="stat-lbl">Critical Risk</span></div>
    <div class="stat"><span class="stat-val">{self.stats.get("new_findings",0)}</span><span class="stat-lbl">New Findings</span></div>
  </div>
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
        reporter.print_findings()        # .env file exposures
        reporter.print_page_findings()   # web exposures
        reporter.print_stats()

        out_dir = self.args.output
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        base = os.path.join(out_dir, f"scheduled_{ts}")
        # Respect output flags — save only what the user asked for
        if self.args.json or self.args.all_reports: reporter.save_json(base + ".json")
        if self.args.txt  or self.args.all_reports: reporter.save_txt(base  + ".txt")
        if self.args.html or self.args.all_reports: reporter.save_html(base + ".html")
        # If no output flags set, default to saving all for scheduled runs
        if not (self.args.json or self.args.txt or self.args.html or self.args.all_reports):
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
    """Load and validate targets file. Warns on bad lines without aborting."""
    if not os.path.isfile(path):
        console.print(f"[red]  [!] File not found: {path}[/red]")
        sys.exit(1)
    from urllib.parse import urlparse as _urlparse
    valid = []
    skipped = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if " " in line or "\t" in line:
                console.print(f"[yellow]  [!] Line {lineno} skipped (whitespace in URL): {line!r}[/yellow]")
                skipped += 1
                continue
            candidate = line if "://" in line else "https://" + line
            try:
                p = _urlparse(candidate)
                if p.scheme not in ("http", "https") or not p.netloc:
                    raise ValueError("bad scheme or host")
                valid.append(line)
            except Exception:
                console.print(f"[yellow]  [!] Line {lineno} skipped (invalid URL): {line}[/yellow]")
                skipped += 1
    if skipped:
        console.print(f"[yellow]  [!] {skipped} line(s) skipped from {path}[/yellow]")
    return valid

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
    t.add_column("Type",       justify="center",    min_width=10)
    t.add_column("URL",        style="cyan",        no_wrap=False, max_width=55)
    t.add_column("Risk",       justify="center",    min_width=8)
    t.add_column("Category / Label",  style="yellow", no_wrap=False, max_width=28)
    t.add_column("First Seen", min_width=19)
    t.add_column("Last Seen",  min_width=19)
    for row in rows:
        url, risk, cats, kind, first_seen, last_seen = row[0], row[1], row[2], row[3], row[4], row[5]
        rc = RISK_COLORS.get(risk, "white")
        # Use the 'kind' column written by mark_seen_atomic ('env') / mark_seen_page_atomic ('page')
        type_label = "[bold green].env File[/bold green]" if kind == "env" else "[bold cyan]Web Exposure[/bold cyan]"
        t.add_row(type_label, url, f"[{rc}]{risk}[/{rc}]", cats[:40], first_seen[:19], last_seen[:19])
    console.print(t)


# ─── INTERACTIVE WIZARD ───────────────────────────────────────────────────────
def interactive_wizard():
    console.print(BANNER)
    console.print(Panel(
        f"[bold white]EnvHunter v{VERSION} — Web Exposure & Secrets Recon Framework[/bold white]\n"
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
        from urllib.parse import urlparse as _wup
        while True:
            raw_t = Prompt.ask("  Enter target URL (e.g. https://example.com)").strip()
            if not raw_t:
                console.print("  [yellow]  Please enter a URL.[/yellow]")
                continue
            if " " in raw_t or "\t" in raw_t:
                console.print("  [yellow]  URL cannot contain spaces.[/yellow]")
                continue
            _cand = raw_t if "://" in raw_t else "https://" + raw_t
            try:
                _pp = _wup(_cand)
                if _pp.scheme not in ("http", "https") or not _pp.netloc:
                    raise ValueError()
            except Exception:
                console.print(f"  [yellow]  Invalid URL: {raw_t!r} — try https://example.com[/yellow]")
                continue
            manual_targets.append(raw_t)
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
    args.verbose      = Confirm.ask("  Verbose output (print each URL checked)?",   default=False)
    args.show_content = Confirm.ask("  Print raw .env content in terminal?",        default=False)

    proxy_raw = Prompt.ask("  Proxy URL (leave blank to skip)  e.g. http://127.0.0.1:8080", default="")
    if proxy_raw.strip():
        px = proxy_raw.strip()
        # Auto-add http:// scheme if user typed just host:port
        if px and not px.startswith(("http://", "https://", "socks5://", "socks4://")):
            px = "http://" + px
            console.print(f"  [dim]  Proxy normalised to: {px}[/dim]")
        args.proxy = px

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
            return _dedup_targets(t)

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
        all_targets = _dedup_targets(all_targets)

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
        return _dedup_targets(t)

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
