# 🔍 EnvHunter v4.0

> **Web Exposure & Secrets Recon Framework**  
> **Author:** g33l0 | **Telegram:** @x0x0h33l0  
> **Version:** 4.0

---

```
╔════════════════════════════════════════════════════════════╗
║   ███████╗███╗   ██╗██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗    ║
║   ██╔════╝████╗  ██║██║   ██║██║  ██║██║   ██║████╗  ██║     ║
║   █████╗  ██╔██╗ ██║██║   ██║███████║██║   ██║██╔██╗ ██║      ║
║   ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██╔══██║██║   ██║██║╚██╗██║      ║
║   ███████╗██║ ╚████║ ╚████╔╝ ██║  ██║╚██████╔╝██║ ╚████║     ║
║   ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝    ║
╚════════════════════════════════════════════════════════════╝
  Web Exposure & Secrets Recon Framework  v4.0
  Author : g33l0  |  Telegram : @x0x0h33l0
```

---

## 📌 Overview

**EnvHunter** is a professional web exposure scanner for security teams to proactively audit their entire web infrastructure before attackers can exploit accidentally exposed resources.

**v4.0 expands far beyond `.env` files.** The tool now detects 14 categories of exposure across 280+ paths — covering `.env` secrets, phpMyAdmin, admin panels, database dumps, Git repositories, SSH keys, debug pages, config files, log files, Docker/DevOps files, WordPress misconfigurations, API documentation, and server status pages.

**v3.x brought:** Shodan/Censys/crt.sh/HackerTarget/OTX asset discovery, Telegram alerting with SQLite deduplication, and a built-in scheduler.

**v4.0 adds:** 13 new scan modules, smart signature validation to eliminate false positives, dual-phase scan engine, expanded detection patterns (22 categories), and a second report table for web exposure findings.

---

## ⚠️ Legal Disclaimer

> **Authorized use ONLY.**
> EnvHunter is a defensive security tool. Only scan systems you own or have explicit written permission to test. Unauthorized scanning violates computer misuse laws in most jurisdictions including the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent legislation worldwide. The author assumes zero liability for misuse.

---

## ✨ Feature Overview

| Feature | Description |
|---|---|
| 🔎 **14 Scan Modules** | `.env` files, phpMyAdmin, admin panels, PHP info, server status, config files, backups, Git repos, log files, SSH keys, package files, Docker/DevOps, API docs, WordPress |
| 🌐 **280+ Paths** | Comprehensive path coverage across all 14 modules |
| 🧠 **22 Detection Categories** | Regex-based pattern matching for all secret and exposure types |
| ✅ **Signature Validation** | Per-module content signatures reject soft 404s — no false positives |
| 🚫 **False-Positive Filter** | Skips comments, empty values, placeholders, and template vars |
| 🎯 **Risk Scoring** | CRITICAL / HIGH / MEDIUM / LOW per finding — module-aware |
| 🌐 **Asset Discovery** | Shodan, Censys, crt.sh, HackerTarget, AlienVault OTX |
| 🔒 **Optional Redaction** | Only masks secrets when you pass `--redact` |
| ⚡ **Multi-threaded** | Concurrent scanning with configurable thread count |
| 🕰️ **Scheduler / Cron** | Repeat scans every N hours — fully automated |
| 📲 **Telegram Alerts** | Real-time alerts for NEW findings only — both `.env` and web exposures |
| 🗄️ **State Database** | SQLite deduplication across all runs — view history with `--history` |
| 🕵️ **Proxy Support** | Burp Suite, SOCKS5, or any HTTP proxy |
| 🎭 **UA Rotation** | Randomised User-Agent per request |
| 📊 **3 Report Formats** | JSON (SIEM-ready), TXT (human-readable), HTML (dark UI — two tables) |
| 🖥️ **Interactive Wizard** | Guided CLI menu — no flags needed |

---

## 🚀 Installation

**Requirements:** Python 3.8+

```bash
# 1. Clone
git clone https://github.com/g33l0/envhunter.git
cd envhunter

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Make executable — Linux/macOS only
chmod +x envhunter.py
```

---

## 🖥️ Usage

### Interactive Mode — Recommended for new users
```bash
python3 envhunter.py
```
Launches a full guided wizard covering target input, discovery sources, scan settings, Telegram setup, output format, and scheduling.

---

### CLI Mode — For scripting and automation

#### Basic single-target scan:
```bash
python3 envhunter.py -u https://example.com
```

#### Bulk scan from file with all reports:
```bash
python3 envhunter.py -f targets.txt --all-reports -v
```

#### Tuned scan for managed client sites:
```bash
python3 envhunter.py -f targets.txt --threads 15 --delay 0.5 --all-reports -v
```

#### Auto-discover subdomains then scan (free sources):
```bash
python3 envhunter.py --discover example.com --all-reports -v
```

#### Discover via Shodan + crt.sh + scan:
```bash
python3 envhunter.py \
  --discover example.com \
  --shodan-key YOUR_KEY \
  --shodan-query "hostname:example.com http.status:200" \
  --all-reports --verbose
```

#### Scheduled scan every 24 hours with Telegram alerts:
```bash
python3 envhunter.py \
  -f targets.txt \
  --schedule 24 \
  --tg-token YOUR_BOT_TOKEN \
  --tg-chat YOUR_CHAT_ID \
  --all-reports
```

#### Fully automated — discovery + scheduler + Telegram:
```bash
python3 envhunter.py \
  --discover example.com \
  --shodan-key YOUR_KEY \
  --shodan-query "hostname:example.com" \
  --schedule 12 \
  --tg-token YOUR_BOT_TOKEN \
  --tg-chat YOUR_CHAT_ID \
  --all-reports \
  --output ./reports
```

#### Test Telegram connection:
```bash
python3 envhunter.py --tg-token YOUR_TOKEN --tg-chat YOUR_CHAT_ID --tg-test
```

#### View all historically found exposures:
```bash
python3 envhunter.py --history
```

#### Scan with secret redaction enabled:
```bash
python3 envhunter.py -f targets.txt --all-reports --redact
```

#### Route through Burp Suite for traffic inspection:
```bash
python3 envhunter.py -u https://example.com --proxy http://127.0.0.1:8080
```

---

## 📦 Scan Modules (v4.0)

EnvHunter v4.0 uses a named module system. Each module covers a specific exposure category with its own path list, content signatures, and default risk level.

| Module | Paths | Default Risk | What It Detects |
|---|---|---|---|
| `env_files` | 35 | Varies | `.env`, `.env.local`, `.env.prod`, `.env.backup` and 30+ variants |
| `phpmyadmin` | 20 | 🔴 CRITICAL | phpMyAdmin, Adminer, `/pma/`, `/dbadmin/`, `/myadmin/` |
| `admin_panels` | 33 | 🟠 HIGH | `/admin/`, `/administrator/`, `/wp-admin/`, `/cpanel/`, `/backend/` |
| `php_info` | 14 | 🟠 HIGH | `phpinfo.php`, Laravel Telescope, Debugbar, `/_profiler/` |
| `server_status` | 24 | 🟡 MEDIUM | Apache/Nginx status, Spring Boot Actuator, Elasticsearch, Jolokia |
| `config_files` | 29 | 🟠 HIGH | `wp-config.php`, `config.php`, `settings.php`, `parameters.yml` |
| `backup_files` | 21 | 🔴 CRITICAL | `.sql`, `.sql.gz`, `.zip`, `.tar.gz` — database dumps and archives |
| `git_exposure` | 16 | 🔴 CRITICAL | `/.git/config`, `/.git/HEAD`, `.gitignore`, SVN, Mercurial |
| `log_files` | 19 | 🟡 MEDIUM | `laravel.log`, `error.log`, `debug.log`, `npm-debug.log` |
| `ssh_keys` | 14 | 🔴 CRITICAL | `id_rsa`, `id_ed25519`, `authorized_keys`, `.pem`, `server.key` |
| `package_files` | 12 | 🟡 MEDIUM | `composer.json`, `package.json`, `requirements.txt`, `Gemfile` |
| `devops_files` | 17 | 🟠 HIGH | `docker-compose.yml`, `Dockerfile`, `Jenkinsfile`, `terraform.tfvars` |
| `api_exposure` | 18 | 🟡 MEDIUM | Swagger UI, OpenAPI docs, GraphQL playground, `/graphiql` |
| `wordpress` | 11 | 🟡 MEDIUM | WP user enumeration, `xmlrpc.php`, `debug.log`, `/?author=1` |

**Total: 280+ unique paths scanned per target.**

---

## 🧠 Signature Validation

Every non-`.env` module uses content signatures to confirm the page is genuinely exposed — not a soft 404 or catch-all returning HTTP 200.

```
Request → HTTP 200 received
         ↓
Content checked against module signatures
         ↓
Match?  YES → ExposedPage recorded + Telegram alert fired
        NO  → Silently discarded (false positive prevented)
```

Examples:
- **phpMyAdmin** — must contain `phpMyAdmin` or `mariadb` in response body
- **Git exposure** — must contain `repositoryformatversion` or `ref:`
- **SSH keys** — must contain `-----BEGIN` or `OPENSSH PRIVATE`
- **Backup files** — must contain `INSERT INTO` or `CREATE TABLE`
- **PHP info** — must contain `PHP Version` or `php.ini`

---

## 🧠 Detection Categories (22 Total)

### Secret Detection in File Content
| Category | Patterns Matched |
|---|---|
| SMTP / Mail | `SMTP_*`, `MAIL_*`, `SENDGRID_KEY`, `MAILGUN_*` |
| Database Credentials | `DB_PASS`, `DATABASE_URL`, `MYSQL_PW`, `MONGO_URI` |
| API Keys | `API_KEY`, `API_SECRET`, `ACCESS_KEY`, `CLIENT_SECRET` |
| Cloud Credentials | `AWS_ACCESS_KEY`, `GCP_KEY`, `AZURE_CLIENT`, `DO_TOKEN` |
| Auth / JWT Secrets | `JWT_SECRET`, `APP_SECRET`, `ENCRYPTION_KEY` |
| OAuth / SSO | `OAUTH_*`, `GITHUB_TOKEN`, `GOOGLE_CLIENT_*` |
| Passwords | `PASSWORD=`, `PASSWD=`, `PWD=`, `PASSPHRASE` |
| Usernames | `USERNAME=`, `USER_NAME=`, `ADMIN_USER=` |
| Stripe / Payment | `STRIPE_SECRET`, `PAYPAL_SECRET`, `BRAINTREE_*` |
| Twilio / SMS | `TWILIO_*`, `VONAGE_API_*`, `NEXMO_KEY` |
| Private Keys/Certs | `PRIVATE_KEY`, `SSL_KEY`, `RSA_KEY`, `PEM_FILE` |
| Redis / Cache | `REDIS_URL`, `REDIS_PASSWORD`, `MEMCACHED_*` |
| Webhook Secrets | `WEBHOOK_SECRET`, `SLACK_TOKEN`, `DISCORD_TOKEN` |
| General Secrets | Any `KEY`/`SECRET`/`TOKEN`/`CREDENTIAL` with 6+ char value |

### New in v4.0
| Category | Patterns Matched |
|---|---|
| Docker / DevOps | `DOCKER_PASS`, `CI_TOKEN`, `DEPLOY_KEY`, `VAULT_TOKEN` |
| SSH / Private Keys | `-----BEGIN RSA PRIVATE`, `OPENSSH PRIVATE`, `ssh-rsa` |
| Spring Boot Actuator | `spring.datasource`, `spring.security`, `management.endpoints` |
| WordPress Secrets | `AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `table_prefix` |
| Laravel App Config | `APP_KEY=base64`, `APP_DEBUG=true`, `APP_ENV=local` |
| Database DSN | `mysql://`, `postgres://`, `mongodb://`, `redis://` |
| Internal IPs | DB/Redis/cache hosts pointing to `10.x`, `172.16-31.x`, `192.168.x` |
| Version Disclosure | `X-Powered-By`, `Server: apache/nginx/php` headers |

---

## 🎯 Risk Levels

### .env File Findings
| Level | Criteria |
|---|---|
| 🔴 **CRITICAL** | Database creds, API/Cloud keys, Auth secrets, Passwords, Private Keys |
| 🟠 **HIGH** | SMTP, OAuth, Payment processors, SMS/Twilio |
| 🟡 **MEDIUM** | Usernames, Redis, Webhooks, General secrets |
| 🟢 **LOW** | File exposed but no sensitive keywords detected |

### Web Exposure Findings (v4.0)
| Level | Modules |
|---|---|
| 🔴 **CRITICAL** | phpMyAdmin, Backup/SQL dumps, Git repos, SSH keys |
| 🟠 **HIGH** | Admin panels, Config files, PHP info/debug, Docker/DevOps |
| 🟡 **MEDIUM** | Server status, Log files, WordPress, API docs, Package manifests |

---

## 🌐 Asset Discovery Sources

| Source | Type | Cost | What it returns |
|---|---|---|---|
| **Shodan** | Search engine | Paid API key | Live hosts, ports, services matching query |
| **Censys** | Search engine | Free tier (250/mo) | Hosts/services with certificate data |
| **crt.sh** | Cert Transparency | Free | All subdomains from SSL certificate logs |
| **HackerTarget** | Passive DNS | Free (rate-limited) | Subdomains from DNS records |
| **AlienVault OTX** | Threat Intel | Free | Subdomains from passive DNS threat data |

All sources deduplicated into a single target list before scanning.

---

## 📲 Telegram Setup

1. Open Telegram → search **@BotFather** → `/newbot` → copy **Bot Token**
2. Start a chat with your bot, then visit:
   `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
   and copy your **Chat ID** from the JSON response
3. Pass both to EnvHunter:

```bash
python3 envhunter.py \
  -f targets.txt \
  --tg-token 123456:ABC-DEF1234 \
  --tg-chat 987654321 \
  --schedule 24
```

Telegram alerts fire for NEW findings only. Both `.env` exposures and web exposure findings send individual alerts. A summary is sent at the end of each run showing targets scanned, `.env` exposed, pages exposed, critical count, and new finding count.

---

## 🕰️ Scheduler / Cron Mode

```bash
# Scan every 6 hours with Telegram alerts
python3 envhunter.py \
  -f targets.txt \
  --schedule 6 \
  --tg-token TOKEN \
  --tg-chat ID \
  --all-reports
```

- First scan runs **immediately** on launch
- Subsequent scans every N hours (supports decimals — `0.5` = 30 minutes)
- Each run saves timestamped reports: `scheduled_YYYYMMDD_HHMMSS.*`
- Stop cleanly with `Ctrl+C`

Traditional cron alternative:
```cron
0 */6 * * * /usr/bin/python3 /opt/envhunter/envhunter.py -f /opt/envhunter/targets.txt --all-reports --tg-token TOK --tg-chat ID -q
```

---

## 📁 Output Structure

```
reports/
├── envhunter_20240315_142305.json     # SIEM-ready JSON
├── envhunter_20240315_142305.txt      # Human-readable summary
├── envhunter_20240315_142305.html     # Dark HTML — two tables:
│                                      #   Table 1: .env exposures
│                                      #   Table 2: web exposure findings
├── scheduled_20240316_020000.json     # Scheduled run — same formats
└── ...
envhunter_state.db                     # SQLite finding history (auto-created)
```

### JSON Structure (v4.0)
```json
{
  "target": "https://example.com",
  "exposed_env_files": [
    {
      "url": "https://example.com/.env",
      "risk_level": "CRITICAL",
      "findings": { "Passwords": ["DB_PASSWORD=secret"] }
    }
  ],
  "exposed_pages": [
    {
      "url": "https://example.com/phpmyadmin/",
      "module": "phpmyadmin",
      "label": "phpMyAdmin / DB Admin",
      "risk_level": "CRITICAL",
      "evidence": ["phpMyAdmin", "mysql"]
    }
  ]
}
```

---

## ⚙️ Full CLI Reference

```
Input:
  -u, --url             Single target URL
  -f, --file            File with target URLs (one per line)

Asset Discovery:
  --discover DOMAIN     Seed domains for subdomain enumeration
  --shodan-key KEY      Shodan API key
  --shodan-query Q      Shodan search query
  --shodan-pages N      Pages to fetch from Shodan (default: 1)
  --censys-id ID        Censys API ID
  --censys-secret S     Censys API secret
  --censys-query Q      Censys search query
  --no-crtsh            Disable crt.sh
  --no-hackertarget     Disable HackerTarget
  --no-otx              Disable AlienVault OTX

Scan Options:
  -t, --threads N       Concurrent threads (default: 10, recommended: 15-20)
  --timeout N           Request timeout seconds (default: 10)
  --delay N             Delay between requests, supports 0.5 etc. (default: 0)
  --proxy URL           HTTP/SOCKS proxy URL
  --aggressive          Disable content-type filter
  --extra-paths         Additional paths to probe
  -H, --headers         Custom HTTP headers

Telegram:
  --tg-token TOKEN      Bot token from @BotFather
  --tg-chat ID          Chat or group ID
  --tg-test             Send test message and exit

Scheduler:
  --schedule HOURS      Run every N hours (supports decimals)

Output:
  -o, --output DIR      Output directory (default: ./reports)
  --json                Save JSON report
  --txt                 Save TXT report
  --html                Save HTML report
  --all-reports         Save JSON + TXT + HTML
  --redact              Redact secret values in all output
  --show-content        Print raw content / page snippet to terminal
  --history             Show all stored findings and exit
  -v, --verbose         Print each URL as checked
  -q, --quiet           Suppress banner and non-essential output
```

---

## 🔒 Recommended Settings

### Managed client audit (999 sites):
```bash
python3 envhunter.py -f targets.txt --threads 15 --delay 0.5 --all-reports --tg-token TOK --tg-chat ID -v
```

### Scheduled overnight monitoring:
```bash
python3 envhunter.py -f targets.txt --threads 10 --delay 1.0 --schedule 24 --all-reports --tg-token TOK --tg-chat ID -q
```

### Single high-value target deep scan:
```bash
python3 envhunter.py -u https://target.com --discover target.com --threads 5 --delay 1.0 --aggressive --show-content --all-reports -v
```

---

## 📋 Changelog

### v4.0
- 14 scan modules — expanded from `.env` only to full web exposure coverage
- 280+ paths scanned per target (was 35)
- Signature validation per module — eliminates soft-404 false positives
- Dual-phase scan engine — Phase 1: `.env`, Phase 2: web exposures
- ExposedPage data model for non-`.env` findings
- 22 detection categories — 8 new patterns added
- HTML report two-table layout — `.env` findings and web exposures separated
- JSON report `exposed_env_files` and `exposed_pages` arrays
- Telegram `send_page_finding()` for web exposure alerts
- Stats panel shows `.env Exposed` and `Pages Exposed` separately

### v3.1
- Safe `_require()` import guard — helpful error instead of crash on missing deps
- `DefaultArgs` class — eliminates `AttributeError` across all code paths
- Fixed `--all-reports` not expanding in CLI mode
- Fixed signal handling for Windows (SIGINT only)
- Fixed HTML injection in report output
- `prompt_int()` and `prompt_float()` with retry loops — fixed crash on `0.5` delay input

### v3.0
- Shodan, Censys, crt.sh, HackerTarget, AlienVault OTX asset discovery
- Telegram alerting with new-findings-only deduplication
- SQLite state database and `--history` viewer
- Built-in scheduler / cron mode
- Redaction changed to opt-in (`--redact`)
- Interactive wizard mode

### v2.0
- Multi-threaded scanning
- Risk scoring
- JSON + TXT + HTML reports
- False-positive filtering
- Proxy support

### v1.0
- Initial release

---

## 🤝 Contributing

PRs welcome. Open an issue first for major changes.

Adding new scan modules: add entry to `SCAN_MODULES` dict and corresponding signatures to `MODULE_SIGNATURES` in `envhunter.py`. Test against real and known-clean targets before submitting.

---

## 📜 License

MIT — see `LICENSE`.

---

**Built with ❤️ by [g33l0](https://t.me/x0x0h33l0) for the defensive security community.**
