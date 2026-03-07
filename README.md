# 🔍 EnvHunter v4.12

> **Web Exposure & Secrets Recon Framework**  
> **Author:** g33l0 | **Telegram:** [@x0x0h33l0](https://t.me/x0x0h33l0)  
> **Version:** 4.12

---

```
╔════════════════════════════════════════════════════════════╗
║  ███████╗███╗   ██╗██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗  ║
║  ██╔════╝████╗  ██║██║   ██║██║  ██║██║   ██║████╗  ██║  ║
║  █████╗  ██╔██╗ ██║██║   ██║███████║██║   ██║██╔██╗ ██║  ║
║  ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██╔══██║██║   ██║██║╚██╗██║  ║
║  ███████╗██║ ╚████║ ╚████╔╝ ██║  ██║╚██████╔╝██║ ╚████║  ║
║  ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  ║
╚════════════════════════════════════════════════════════════╝
```

---

## 📌 Overview

**EnvHunter** is a professional security reconnaissance tool for proactively auditing web infrastructure before attackers do. It detects accidentally exposed `.env` files, admin panels, database backups, SSH keys, source code repositories, DevOps configs, and more — across your entire asset estate.

Built for **defensive security teams** running continuous monitoring programmes. A single scan covers 318 paths across 14 detection modules. Every finding is deduplicated against a local SQLite state database, so only genuinely new exposures trigger Telegram alerts — no noise on repeat scans.

**What it finds:**
- `.env` files with live database credentials, API keys, payment secrets, cloud tokens, JWT secrets, and private keys
- phpMyAdmin, cPanel, WHM, Plesk, DirectAdmin, and Webmin login panels
- Exposed `.git` repositories with full source code and commit history
- SQL dumps, tar archives, and zip backups containing production data
- SSH private keys and TLS certificates served publicly
- `docker-compose.yml`, `Dockerfile`, and CI/CD configs with embedded secrets
- `phpinfo()` debug pages, server-status endpoints, Swagger/OpenAPI schemas
- WordPress user enumeration endpoints and XML-RPC

---

## ⚠️ Legal Disclaimer

> **Authorised use only.**  
> EnvHunter is a defensive security tool. Only scan systems you own or have explicit written permission to test. Unauthorised scanning violates computer misuse laws in most jurisdictions. The author assumes zero liability for misuse.

---

## ✨ Feature Summary

| Feature | Detail |
|---|---|
| 🌐 **Asset Discovery** | Shodan, Censys, crt.sh, HackerTarget, AlienVault OTX |
| 🔎 **318 Path Coverage** | 45 `.env` variants + 273 paths across 13 page modules |
| 🧠 **21 Detection Categories** | Regex-based extraction for all secret types |
| 🏗️ **14 Scan Modules** | .env, phpMyAdmin, Admin Panels, PHP Info, Server Status, Config Files, Backups, Git, Logs, SSH Keys, Packages, Docker/DevOps, API Docs, WordPress |
| 🚫 **False-Positive Filter** | Rejects comments, empty values, placeholders, `change_me`, `your-secret-key`, `example_*`, `SomeRandom*`, and `REPLACE_ME` patterns |
| 🎯 **Risk Scoring** | CRITICAL / HIGH / MEDIUM / LOW — based on what is directly exploitable *right now* |
| 📲 **Real-Time Telegram Alerts** | Per-finding alerts fire at discovery time with exact timestamp and risk explanation |
| 🔕 **Deduplication** | SQLite state DB — only NEW findings alert, regardless of scan frequency |
| ⚡ **Multi-Threaded** | 25 target threads × up to 50 path workers per target |
| 🕰️ **Built-In Scheduler** | Repeat scans every N hours — no crontab needed |
| 🔒 **Optional Redaction** | `--redact` masks secret values in all output formats |
| 🕵️ **Proxy Support** | Route through Burp Suite, SOCKS5, or any HTTP proxy |
| 🎭 **User-Agent Rotation** | Randomised per request |
| 📊 **3 Report Formats** | JSON (SIEM-ready), TXT (human-readable), HTML (dark UI) |
| 🖥️ **Interactive Wizard** | Guided setup — no flags needed |
| 👋 **Graceful Exit** | Ctrl+C banner + clean shutdown of TG drain queue |

---

## 🚀 Installation

**Requirements:** Python 3.8+

```bash
# Clone
git clone https://github.com/g33l0/envhunter.git
cd envhunter

# Install dependencies
pip install -r requirements.txt

# (Optional) make executable
chmod +x envhunter.py
```

---

## 🖥️ Usage

### Interactive Mode — recommended for first-time use

```bash
python3 envhunter.py
```

Launches a full guided wizard covering target input, discovery sources, scan settings, Telegram, output format, and scheduling.

---

### CLI Mode — for scripting and CI/CD

#### Single-target scan
```bash
python3 envhunter.py -u https://example.com
```

#### Bulk scan from file, all report formats
```bash
python3 envhunter.py -f targets.txt --all-reports -v
```

#### Auto-discover subdomains then scan (free sources only)
```bash
python3 envhunter.py --discover example.com --all-reports -v
```

#### Discover via Shodan + crt.sh + scan
```bash
python3 envhunter.py \
  --discover example.com \
  --shodan-key YOUR_KEY \
  --shodan-query "hostname:example.com http.status:200" \
  --all-reports --verbose
```

#### Scheduled scan every 24 hours with Telegram alerts
```bash
python3 envhunter.py \
  -f targets.txt \
  --schedule 24 \
  --tg-token YOUR_BOT_TOKEN \
  --tg-chat YOUR_CHAT_ID \
  --all-reports
```

#### Fully automated: discovery + scheduler + Telegram
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

#### Test Telegram connection
```bash
python3 envhunter.py --tg-token YOUR_TOKEN --tg-chat YOUR_CHAT_ID --tg-test
```

#### View all historically found exposures
```bash
python3 envhunter.py --history
```

#### Scan with secret value redaction
```bash
python3 envhunter.py -f targets.txt --all-reports --redact
```

#### Route through Burp Suite
```bash
python3 envhunter.py -u https://example.com --proxy http://127.0.0.1:8080
```

#### Increase path workers for faster scans on live hosts
```bash
python3 envhunter.py -f targets.txt --path-workers 30 --threads 30
```

---

## 📂 Targets File Format

```
# One URL per line — lines starting with # are ignored
https://example.com
https://api.example.com
https://staging.example.com
app.example.com          # https:// is added automatically
```

---

## 🌐 Asset Discovery Sources

| Source | Type | Cost | What it returns |
|---|---|---|---|
| **Shodan** | Search engine | Paid API key | Live hosts matching your query (IPs, ports, hostnames) |
| **Censys** | Search engine | Free tier | Hosts/services matching your query |
| **crt.sh** | Certificate Transparency | Free | Subdomains from SSL cert logs |
| **HackerTarget** | Passive DNS | Free (rate-limited) | Subdomains from DNS records |
| **AlienVault OTX** | Threat Intel Passive DNS | Free | Subdomains from OTX passive DNS |

All sources are combined and deduplicated into a single target list before scanning begins.

---

## 📲 Telegram Setup

1. Open Telegram → search **@BotFather** → `/newbot` → copy your **Bot Token**
2. Start a chat with your bot, then visit:  
   `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`  
   Copy your **Chat ID** from the `"id"` field in the JSON response
3. Pass both to EnvHunter:

```bash
python3 envhunter.py \
  -f targets.txt \
  --tg-token 123456:ABC-DEF1234 \
  --tg-chat 987654321 \
  --schedule 24
```

### Real-time alerts

Every new finding triggers an immediate Telegram alert at the **moment of discovery** — not at scan end. Each message includes:

- **Found at:** exact timestamp with seconds (`2026-03-05 17:23:41 UTC`)
- **Risk level badge** + plain-English explanation of what it means for that finding type
- **Evidence** — the matching signatures or keywords that confirmed the exposure
- **HTTP status and content size**

Risk explanation per level:

| Level | Context in Alert |
|---|---|
| 🔴 **CRITICAL** | *"Credentials or sensitive data directly readable — no authentication required. Immediate action needed."* |
| 🟠 **HIGH** | *"Sensitive structure exposed — source code, configs or secrets likely present. Manual inspection recommended."* |
| 🟡 **MEDIUM** | *"Login interface publicly reachable — an attacker still needs valid credentials to exploit this."* |
| 🟢 **LOW** | *"Version or schema disclosure only — no direct credential exposure, but useful for attacker reconnaissance."* |

The scan-complete summary opens with a dynamic headline:
- `🔴 CRITICAL FINDINGS — N critical items` 
- `⚠️ N new finding(s) — review required`
- `✅ Scan complete — no new findings`

**Deduplication:** Previously seen findings (`envhunter_state.db`) are silently skipped. Only genuinely new exposures fire alerts and increment the `New Findings` counter.

---

## 🕰️ Scheduler Mode

EnvHunter has a built-in scheduler — no crontab needed.

```bash
# Scan every 6 hours, save reports, alert via Telegram
python3 envhunter.py -f targets.txt --schedule 6 --tg-token TOK --tg-chat ID --all-reports
```

- Runs the first scan **immediately** on launch
- Subsequent scans run every N hours
- Each run saves timestamped reports in the output directory
- Stop with `Ctrl+C` — the goodbye banner and TG drain queue close cleanly

For traditional cron:
```cron
0 */6 * * * /usr/bin/python3 /opt/envhunter/envhunter.py -f /opt/envhunter/targets.txt --all-reports --tg-token TOK --tg-chat ID -q
```

---

## 🔍 Detection Categories

EnvHunter extracts 21 secret categories from exposed `.env` files:

| Category | Patterns Matched |
|---|---|
| **Database Credentials** | `DB_PASS`, `DATABASE_URL`, `MYSQL_PW`, `MONGO_URI`, `dbPassword`, `databaseUrl` |
| **API Keys** | `API_KEY`, `API_SECRET`, `ACCESS_KEY`, `CLIENT_SECRET`, `apiKey`, `secretKey` |
| **Cloud Credentials** | `AWS_ACCESS_KEY`, `AWS_SECRET`, `GCP_KEY`, `AZURE_CLIENT`, `DO_TOKEN` |
| **Auth / JWT Secrets** | `JWT_SECRET`, `APP_SECRET`, `AUTH_SECRET`, `ENCRYPTION_KEY`, `TOKEN_SECRET` |
| **Passwords** | `PASSWORD=`, `PASSWD=`, `PWD=`, `PASSPHRASE`, `adminPassword`, `dbPassword` |
| **Private Keys/Certs** | `PRIVATE_KEY`, `SSL_KEY`, `RSA_KEY`, `PEM_FILE` |
| **SSH / Private Keys** | `-----BEGIN`, `RSA PRIVATE KEY`, `OPENSSH PRIVATE`, `ssh-rsa`, `ssh-ed25519` |
| **SMTP / Mail** | `SMTP_*`, `MAIL_*`, `SENDGRID_KEY`, `MAILGUN_*`, `SES_KEY` |
| **OAuth / SSO** | `OAUTH_*`, `CLIENT_ID`, `GITHUB_TOKEN`, `GOOGLE_CLIENT_*`, `FACEBOOK_APP_*` |
| **Stripe / Payment** | `STRIPE_KEY`, `STRIPE_SECRET`, `PAYPAL_SECRET`, `BRAINTREE_*`, `SQUARE_TOKEN` |
| **Twilio / SMS** | `TWILIO_SID`, `TWILIO_TOKEN`, `VONAGE_API_*`, `NEXMO_KEY` |
| **Redis / Cache** | `REDIS_URL`, `REDIS_PASS`, `MEMCACHED_PASS` |
| **Webhook Secrets** | `WEBHOOK_SECRET`, `SLACK_TOKEN`, `DISCORD_TOKEN`, `TELEGRAM_BOT` |
| **Docker / DevOps** | `DOCKER_PASS`, `CI_TOKEN`, `DEPLOY_KEY`, `VAULT_TOKEN`, `TERRAFORM` |
| **Spring Boot Actuator** | `spring.datasource`, `spring.security`, `management.endpoints` |
| **WordPress Secrets** | `DB_PASSWORD`, `AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY` |
| **Laravel App Config** | `APP_KEY=base64:`, `APP_DEBUG=true`, `APP_ENV=local` |
| **Database DSN** | `mysql://`, `postgres://`, `mongodb://`, `redis://`, `sqlite://` |
| **Internal IPs** | `DB_HOST`/`REDIS_HOST`/`MQ_HOST` pointing to `10.x`, `172.16-31.x`, `192.168.x` |
| **Usernames** | `USERNAME=`, `USER_NAME=`, `LOGIN_USER=`, `ADMIN_USER=` |
| **General Secrets** | Any `KEY`/`SECRET`/`TOKEN`/`CREDENTIAL`/`PASSWD` with 8+ char value |

---

## 📊 Risk Levels

### For `.env` file exposures

| Level | Triggered by |
|---|---|
| 🔴 **CRITICAL** | Database Credentials, API Keys, Cloud Credentials, Auth/JWT Secrets, Passwords, Private Keys/Certs |
| 🟠 **HIGH** | SMTP/Mail, OAuth/SSO, Stripe/Payment, Twilio/SMS |
| 🟡 **MEDIUM** | Any other matched category (General Secrets, Webhooks, Redis, etc.) |
| 🟢 **LOW** | File accessible but no sensitive keywords detected |

### For page/panel exposures

Risk is based on **what is directly exploitable right now**, not theoretical attack chains:

| Level | Module | Rationale |
|---|---|---|
| 🔴 **CRITICAL** | Config Files | Signature requires `DB_PASSWORD=` / `API_KEY=` with a real value present |
| 🔴 **CRITICAL** | Backup / Dump Files | SQL dump confirmed via `INSERT INTO` / `CREATE TABLE` |
| 🔴 **CRITICAL** | SSH Keys | Private key header confirmed in response body |
| 🟠 **HIGH** | Git / VCS Exposure | Source code + full commit history readable with zero auth |
| 🟠 **HIGH** | Docker / DevOps Files | `docker-compose.yml` / `Dockerfile` frequently contains embedded passwords |
| 🟡 **MEDIUM** | phpMyAdmin | Login page reachable — attacker still needs valid credentials |
| 🟡 **MEDIUM** | Admin Panels | cPanel / WHM / Plesk / DirectAdmin / Webmin login |
| 🟡 **MEDIUM** | PHP Info | Server internals visible — no credentials directly exposed |
| 🟡 **MEDIUM** | Log Files | Stack traces may leak tokens — not guaranteed |
| 🟡 **MEDIUM** | WordPress | User list / XML-RPC reachable — not password disclosure |
| 🟢 **LOW** | Server Status | Connection counts and server version only |
| 🟢 **LOW** | API Docs | Swagger / OpenAPI schema only |
| 🟢 **LOW** | Package Files | Dependency list only (`package.json`, `composer.json`) |

---

## 📁 Output Structure

```
reports/
├── envhunter_20260305_170900.json     # SIEM/pipeline-ready
├── envhunter_20260305_170900.txt      # Human-readable summary
├── envhunter_20260305_170900.html     # Dark-themed browser report
└── ...                                # Timestamped per run

envhunter_state.db                     # SQLite finding history (auto-created)
```

---

## ⚙️ Full CLI Reference

```
Input:
  -u, --url URL             Single target URL
  -f, --file FILE           File with target URLs (one per line)

Asset Discovery:
  --discover DOMAIN [...]   Seed domains for subdomain enumeration
  --shodan-key KEY          Shodan API key
  --shodan-query Q [...]    Shodan search queries (multiple allowed)
  --shodan-pages N          Pages to fetch from Shodan (default: 1)
  --censys-id ID            Censys API ID
  --censys-secret SECRET    Censys API secret
  --censys-query Q [...]    Censys search queries
  --no-crtsh                Disable crt.sh enumeration
  --no-hackertarget         Disable HackerTarget enumeration
  --no-otx                  Disable AlienVault OTX enumeration

Scan Options:
  -t, --threads N           Target threads (default: 25, max recommended: 50)
  --path-workers N          Path workers per target (default: 10; auto-scaled 10-50)
  --timeout N               Request timeout in seconds (default: 10)
  --delay N                 Delay between requests in seconds (default: 0)
  --proxy URL               HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)
  --aggressive              Probe all content types, skip binary filter
  --extra-paths P [...]     Additional .env paths to probe
  -H, --headers K:V [...]   Custom HTTP headers

Telegram:
  --tg-token TOKEN          Telegram bot token
  --tg-chat ID              Telegram chat or group ID
  --tg-test                 Send a test message and exit

Scheduler:
  --schedule HOURS          Run repeatedly every N hours (first scan is immediate)

Output:
  -o, --output DIR          Output directory (default: ./reports)
  --json                    Save JSON report
  --txt                     Save TXT report
  --html                    Save HTML report
  --all-reports             Save JSON + TXT + HTML
  --redact                  Redact secret values in all output
  --show-content            Print raw .env content to terminal
  --history                 Show all stored findings from state DB and exit
  -v, --verbose             Verbose output (show each URL probed)
  -q, --quiet               Suppress banner and non-essential output
```

---

## 🗄️ State Database

EnvHunter maintains `envhunter_state.db` (SQLite) in the working directory. Each finding is stored by a SHA-256 fingerprint of the URL and finding type. On repeat scans, known findings are silently skipped — only genuinely new exposures increment the `New Findings` counter and trigger Telegram alerts.

```bash
# View full finding history at any time
python3 envhunter.py --history
```

---

## 🔄 Version History

| Version | Key Changes |
|---|---|
| **4.12** | Fixed: real-time per-finding TG alerts now fire for ALL risk levels — MEDIUM and LOW pages were silently dropped due to a gated threshold. Fixed: `New Findings` counter now counts every new finding, not just TG-alerted ones. Added: exact `Found at` timestamp with seconds in every alert. Added: plain-English risk explanation per finding type in every alert. Added: dynamic scan-complete summary headline. |
| **4.11** | TG page alert threshold corrected (HIGH/CRITICAL only). Context lines added to all TG messages. HTML report severity subtitle updated. Terminal output context notes per finding. |
| **4.10** | Risk reclassification: phpMyAdmin/cPanel correctly rated MEDIUM (login panels, not exploitable without credentials). CRITICAL reserved for directly exploitable files. Fixed cPanel redirect false positives. |
| **4.9** | Fixed TG drain deadlock. Fixed BOM handling (UTF-8/16 LE/BE). Fixed redirect-following that caused missed findings. |
| **4.8** | Added camelCase `.env` detection for Node.js apps. Added single high-signal line threshold. Fixed tight timeout values. |
| **3.0** | Shodan/Censys asset discovery. crt.sh + HackerTarget + OTX subdomain enumeration. Built-in scheduled scan engine. |

---

## 🤝 Contributing

PRs welcome. Open an issue first for major changes. New detection patterns must not increase false-positive rates. All submissions should pass the internal test suite before opening a PR.

---

## 📜 License

MIT — see `LICENSE`.

---

**Built with ❤️ by [g33l0](https://t.me/x0x0h33l0) for the defensive security community.**
