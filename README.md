# SUSP_URL

A containerized, non-technical-friendly web app for safely analysing suspicious URLs and domains.

Everything runs inside Docker (tested on OrbStack) — users do not need to install any tools on their machine.

## What it does

1. Paste a URL or domain on the start page.
2. If the URL was already analysed recently, choose between **viewing the cached report** or **analysing it again**.
3. During analysis you get a **live, isolated Firefox sandbox** where you can click around safely.
4. In the background a **headless scanner** visits the URL and up to 5 subpages of the same domain, takes screenshots, and computes a risk score.
5. The **report page** shows a simple verdict, score, one-sentence summary, and a scrollable thumbnail strip.

## Quick start

Requirements:
- Docker / OrbStack running on your machine
- `jlesage/firefox` image available locally (pulled automatically on first use)

```bash
# 1. Clone the repo
git clone https://github.com/BAD-IT/SUSP_URL.git
cd SUSP_URL

# 2. Point Docker Compose to your Docker socket
# OrbStack:
export DOCKER_SOCK=$HOME/.orbstack/run/docker.sock
# Docker Desktop:
# export DOCKER_SOCK=$HOME/.docker/run/docker.sock

# 3. Build and start the app
export APP_PORT=8080
docker compose up -d --build

# 4. Open the app
open http://localhost:8080
```

To stop:

```bash
docker compose down
```

## Configuration

Copy the example environment file and add your own API keys if you have them:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|---|---|---|
| `APP_PORT` | Host port for the web UI | `8080` |
| `DOCKER_SOCK` | Path to the Docker socket | `/var/run/docker.sock` |
| `SANDBOX_IMAGE` | Live sandbox image | `jlesage/firefox` |
| `REPORT_TTL_SECONDS` | Report freshness threshold | `3600` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key (optional) | - |
| `URLSCAN_API_KEY` | urlscan.io API key (optional) | - |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key (optional) | - |

API keys are optional. If they are missing, the app falls back to a built-in heuristic score.

## Architecture

- `susp_url-web` — Flask UI, SQLite database, Docker orchestration.
- `susp-sandbox-<id>` — ephemeral Firefox container for the live session.
- `susp-scanner-<id>` — ephemeral Playwright/Chromium crawler for screenshots and analysis.
- Shared Docker volume for screenshots.

See `docs/` for detailed architecture and development notes.

## License

MIT
