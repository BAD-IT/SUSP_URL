# Architecture

SUSP_URL is designed to keep the user's machine completely separate from suspicious content. All analysis happens inside short-lived Docker containers.

## Components

### Web app (`susp_url-web`)

- Python 3.12 + Flask + Gunicorn
- Serves the three-page UI
- Manages the SQLite database
- Talks to the local Docker socket to start/stop sandbox and scanner containers
- Serves screenshots from a shared Docker volume

### Live sandbox (`susp-sandbox-<id>`)

- Based on `jlesage/firefox`
- Exposes a noVNC web UI on a random host port
- The user clicks around in this browser on Page 2
- Destroyed when the session ends or times out

### Background scanner (`susp-scanner-<id>`)

- Based on a custom Playwright/Chromium image
- Visits the target URL and up to 5 same-domain subpages
- Captures a screenshot of each page
- Writes results to the shared volume and signals completion via files
- Runs independently from the live sandbox

### SQLite database

- Stores one row per normalized URL
- Columns include: score, verdict, summary, timestamps
- Screenshot file names are stored in a related table
- Used for duplicate detection and caching

### Shared volume

- Named volume `susp-url-screenshots`
- Mounted at `/app/screenshots` in the web container
- Mounted at `/screenshots` in scanner containers
- Sandbox containers do not need access to it

## Data flow

1. User submits URL.
2. URL is normalized and looked up in SQLite.
3. If it exists, the user chooses to view the cached report or analyse again.
4. On new analysis:
   - a live sandbox container starts,
   - a scanner container starts,
   - both run concurrently.
5. The user interacts with the live sandbox on Page 2.
6. When the session ends, the live sandbox is destroyed.
7. The scanner finishes its queue (max 5 pages) and writes screenshots + metadata.
8. The web app computes a heuristic score, reads optional API results, and stores the report.
9. Page 3 displays the report.
