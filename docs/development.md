# Development

## Local setup

You do not need Python installed locally. All development happens inside Docker.

```bash
export DOCKER_SOCK=$HOME/.orbstack/run/docker.sock
docker compose up -d --build
```

## Feature workflow

See `AGENTS.md` for the full agent workflow.

Summary:

1. Create a GitHub issue.
2. Branch from `main`: `git checkout -b feature/<issue>-<desc>`.
3. Implement, test, commit.
4. Push and open a PR.
5. Merge after user approval.
6. Close the issue and delete the remote branch.

## Running tests

Currently the project relies on manual end-to-end tests. Run the app and verify:

- A new URL starts both the live sandbox and scanner.
- The report page displays score, verdict, and thumbnails.
- Re-analysing a URL overwrites the old report.
- No `susp-sandbox-*` or `susp-scanner-*` containers are left behind.

## Useful commands

```bash
# View web app logs
docker logs susp_url-web-1

# List running sandboxes/scanners
docker ps --filter name=susp-

# Inspect the database inside the container
docker exec -it susp_url-web-1 sqlite3 /app/data/susp_url.db

# Rebuild everything
docker compose down
docker compose up -d --build
```
