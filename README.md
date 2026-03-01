# 🔍 EnvHunter v3.1

> **.env Exposure & Secrets Recon Framework**  
> **Author:** g33l0 | **Telegram:** @x0x0h33l0  
> **Version:** 3.1

---

```
╔═══════════════════════════════════════════════════════════╗
║   ███████╗███╗   ██╗██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗    ║
║   ██╔════╝████╗  ██║██║   ██║██║  ██║██║   ██║████╗  ██║     ║
║   █████╗  ██╔██╗ ██║██║   ██║███████║██║   ██║██╔██╗ ██║       ║
║   ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██╔══██║██║   ██║██║╚██╗██║       ║
║   ███████╗██║ ╚████║ ╚████╔╝ ██║  ██║╚██████╔╝██║ ╚████║     ║
║   ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝    ║
╚═══════════════════════════════════════════════════════════╝
```

---

## 📌 Overview

**EnvHunter** is a professional `.env` file exposure scanner for security teams to proactively audit their entire web infrastructure before attackers can exploit accidentally exposed configuration files. These files commonly contain database credentials, API keys, SMTP settings, cloud tokens, payment secrets, and other high-value data.

**v3.1 brings:** Shodan/Censys asset discovery, crt.sh + HackerTarget + AlienVault OTX subdomain enumeration, Telegram alerting with new-findings-only deduplication, and a full scheduled/cron scan engine.

---

## ⚠️ Legal Disclaimer

> **Authorized use ONLY.**  
> EnvHunter is a defensive security tool. Only scan systems you own or have explicit written permission to test. Unauthorized scanning violates computer misuse laws in most jurisdictions. The author assumes zero liability for misuse.

---

## ✨ Feature Overview

| Feature | Description |
|---|---|
| 🌐 **Asset Discovery** | Auto-enumerate targets via Shodan, Censys, crt.sh, HackerTarget, OTX |
| 🔎 **35+ Path Coverage** | Probes all common `.env` path variants per target |
| 🧠 **15 Detection Categories** | Regex-based pattern matching for all secret types |
| 🚫 **False-Positive Filter** | Skips comments, empty values, placeholders, and template vars |
| 🎯 **Risk Scoring** | CRITICAL / HIGH / MEDIUM / LOW per exposed file |
| 🔒 **Optional Redaction** | Only masks secrets when YOU choose `--redact` |
| ⚡ **Multi-threaded** | Concurrent scanning with configurable threads |
| 🕰️ **Scheduler / Cron** | Repeat scans every N hours — fully automated |
| 📲 **Telegram Alerts** | Real-time notifications — NEW findings only (SQLite deduplication) |
| 🗄️ **State Database** | SQLite-backed finding history; view anytime with `--history` |
| 🕵️ **Proxy Support** | Route through Burp Suite, SOCKS, or any HTTP proxy |
| 🎭 **UA Rotation** | Randomised User-Agent per request |
| 📊 **3 Report Formats** | JSON (SIEM-ready), TXT (human-readable), HTML (dark UI) |
| 🖥️ **Interactive Wizard** | Guided CLI menu — no flags needed for beginners |

---

## 🚀 Installation

**Requirements:** Python 3.8+

```bash
# 1. Clone
git clone https://github.com/g33l0/envhunter.git
cd envhunter

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Make executable
chmod +x envhunter.py
```

---

## 🖥️ Usage

### Interactive Mode — Recommended for new users
```bash
python3 envhunter.py
```
Launches a full guided wizard covering target input, discovery, scan settings, Telegram, output format, and scheduling.

---

### CLI Mode — For scripting and CI/CD

#### Basic single-target scan:
```bash
python3 envhunter.py -u https://example.com
```

#### Bulk scan from file + all report formats:
```bash
python3 envhunter.py -f targets.txt --all-reports -v
```

#### Auto-discover subdomains then scan (free sources only):
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

#### Combine discovery + scheduler + Telegram (fully automated):
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

#### Scan with secret value redaction enabled:
```bash
python3 envhunter.py -f targets.txt --all-reports --redact
```

#### Route through Burp Suite for traffic inspection:
```bash
python3 envhunter.py -u https://example.com --proxy http://127.0.0.1:8080
```

---

## 📂 Targets File Format

```
# One URL per line — lines starting with # are ignored
https://example.com
https://api.example.com
https://staging.example.com
app.example.com          # https:// added automatically
```

---

## 🌐 Asset Discovery Sources

| Source | Type | Cost | What it returns |
|---|---|---|---|
| **Shodan** | Search engine | Paid API key | Live hosts matching your query (IPs, ports, hostnames) |
| **Censys** | Search engine | Free tier available | Hosts/services matching your query |
| **crt.sh** | Cert Transparency | Free | Subdomains from SSL certificate logs |
| **HackerTarget** | Passive DNS | Free (rate-limited) | Subdomains from DNS records |
| **AlienVault OTX** | Passive DNS | Free | Subdomains from threat intelligence passive DNS |

All sources are combined and deduplicated into a single target list before scanning begins.

---

## 📲 Telegram Setup

1. Open Telegram → search **@BotFather** → `/newbot` → follow prompts → copy your **Bot Token**
2. Start a chat with your bot, then visit:  
   `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`  
   to get your **Chat ID** from the JSON response
3. Pass both to EnvHunter:

```bash
python3 envhunter.py \
  -f targets.txt \
  --tg-token 123456:ABC-DEF1234 \
  --tg-chat 987654321 \
  --schedule 24
```

**Telegram only sends alerts for NEW findings.** Previously seen findings (tracked in `envhunter_state.db`) are silently skipped. A summary message is always sent at the end of each scheduled run.

---

## 🕰️ Scheduler / Cron Mode

EnvHunter has a built-in scheduler — no crontab needed.

```bash
# Scan every 6 hours, save reports, alert via Telegram
python3 envhunter.py -f targets.txt --schedule 6 --tg-token TOK --tg-chat ID --all-reports
```

- Runs the first scan **immediately** on launch
- Subsequent scans run every N hours
- Each run saves timestamped reports in the output directory
- Stop with `Ctrl+C`

If you prefer traditional cron:
```cron
0 */6 * * * /usr/bin/python3 /opt/envhunter/envhunter.py -f /opt/envhunter/targets.txt --all-reports --tg-token TOK --tg-chat ID -q
```

---

## 🔍 Detection Categories

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

---

## 📊 Risk Levels

| Level | Criteria |
|---|---|
| 🔴 **CRITICAL** | Database creds, API/Cloud keys, Auth secrets, Passwords, Private Keys |
| 🟠 **HIGH** | SMTP, OAuth, Payment processors, SMS/Twilio |
| 🟡 **MEDIUM** | Usernames, Redis, Webhooks, General secrets |
| 🟢 **LOW** | File exposed but no sensitive keywords detected |

---

## 📁 Output Structure

```
reports/
├── envhunter_20240315_142305.json     # SIEM/pipeline friendly
├── envhunter_20240315_142305.txt      # Human-readable summary
├── envhunter_20240315_142305.html     # Dark-themed browser report
├── scheduled_20240316_020000.json     # Scheduled run output
└── ...
envhunter_state.db                     # SQLite finding history (auto-created)
```

---

## ⚙️ Full CLI Reference

```
Input:
  -u, --url           Single target URL
  -f, --file          File with target URLs

Asset Discovery:
  --discover DOMAIN   Seed domains for subdomain enumeration (space-separated)
  --shodan-key KEY    Shodan API key
  --shodan-query Q    Shodan search query (can pass multiple)
  --shodan-pages N    Pages to fetch from Shodan (default: 1)
  --censys-id ID      Censys API ID
  --censys-secret S   Censys API secret
  --censys-query Q    Censys search query
  --no-crtsh          Disable crt.sh
  --no-hackertarget   Disable HackerTarget
  --no-otx            Disable AlienVault OTX

Scan Options:
  -t, --threads N     Concurrent threads (default: 10)
  --timeout N         Request timeout in seconds (default: 10)
  --delay N           Delay between requests (default: 0)
  --proxy URL         HTTP/SOCKS proxy URL
  --aggressive        Check all content types
  --extra-paths       Additional .env paths to probe
  -H, --headers       Custom HTTP headers

Telegram:
  --tg-token TOKEN    Telegram bot token
  --tg-chat ID        Telegram chat/group ID
  --tg-test           Send a test message and exit

Scheduler:
  --schedule HOURS    Run every N hours continuously

Output:
  -o, --output DIR    Output directory (default: ./reports)
  --json              Save JSON report
  --txt               Save TXT report
  --html              Save HTML report
  --all-reports       Save all formats
  --redact            Redact secret values in all output
  --show-content      Print raw .env content to terminal
  --history           Show all stored findings and exit
  -v, --verbose       Verbose output
  -q, --quiet         Suppress banner/non-essential output
```

---

## 🤝 Contributing

PRs welcome. Please open an issue first for major changes. New detection patterns must not increase false-positive rates. Test against known-exposed and known-clean targets before submitting.

---

## 📜 License

MIT — see `LICENSE`.

---

**Built with ❤️ by [g33l0](https://t.me/x0x0h33l0) for the defensive security community.**
