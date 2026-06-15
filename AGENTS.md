:
# AGENTS.md — Development guide

## Project overview

SUSP_URL is a containerized web app for safely analysing suspicious URLs and domains.  
Users paste a URL, get a short-lived isolated browser sandbox to click around in, and receive an automatic report with screenshots, a risk score, and a verdict.

Everything runs in Docker/Orchestrator (OrbStack) so that no tools need to be installed on the user's machine.

## Tech stack

- **Backend:** Python 3.12 + Flask + Gunicorn
- **Persistence:** SQLite (Docker volume)
- **Sandbox / live session:** `jlesage/firefox` with noVNC
- **Background scanner:** custom Playwright/Chromium container
- **Orchestration:** Docker Compose + Docker SDK for Python
- **Frontend:** server-rendered Jinja2 templates + vanilla JS

## Agent workflow

This project uses **feature-driven development** with GitHub issues and pull requests.

1. **Create a GitHub issue** describing the feature/bug.
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/<issue-number>-<short-desc>
   ```
3. **Implement** the feature with minimal, focused changes.
4. **Add or update tests** if the project has tests for the affected area.
5. **Run the app/feature locally** and verify it works end-to-end.
6. **Commit** with a clear message referencing the issue:
   ```bash
   git commit -m "feat(#1): add automatic scanner with screenshots"
   ```
7. **Push** the branch to `origin`.
8. **Open a pull request** with a short summary and link to the issue.
9. **After user approval**, merge the PR into `main`.
10. **Close the issue** and delete the remote branch.

## Code style & conventions

- Keep changes minimal and focused on the issue.
- Use environment variables for configuration and secrets.
- Never commit secrets, `.env` files, or local virtualenvs.
- Use type hints where they improve readability.
- Prefer explicit and simple code over clever abstractions.

## Environment variables

API keys and configurable behaviour are read from environment variables.  
The user provides real keys in a `.env` file at runtime. The agent code must gracefully handle missing keys.

Common variables:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask secret key |
| `SANDBOX_IMAGE` | Docker image for the live sandbox (default: `jlesage/firefox`) |
| `SANDBOX_NETWORK` | Docker network for scanner/sandbox containers (default: `susp-sandbox`) |
| `DOCKER_SOCK` | Host path to the Docker socket (OrbStack: `~/.orbstack/run/docker.sock`) |
| `APP_PORT` | Host port for the web UI (default: `8080`) |
| `REPORT_TTL_SECONDS` | How long a cached report is considered fresh (default: `3600`) |
| `VIRUSTOTAL_API_KEY` | Optional VirusTotal API key |
| `URLSCAN_API_KEY` | Optional urlscan.io API key |
| `ABUSEIPDB_API_KEY` | Optional AbuseIPDB API key |

## Testing before a PR

Before pushing a feature branch, verify at least:

1. `docker compose up -d --build` starts without errors.
2. Submitting a new URL starts both the live sandbox and the scanner.
3. The report page shows the verdict, score, and thumbnails.
4. Re-analysing an existing URL replaces the old report.
5. No leftover `susp-sandbox-*` or `susp-scanner-*` containers remain after the session ends.

## Documentation

Feature-level documentation belongs in `docs/`.  
High-level usage instructions belong in `README.md`.

When you add or change a feature, update the relevant `docs/*.md` file.
