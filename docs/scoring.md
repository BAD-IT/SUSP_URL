# Scoring and verdict

The report shows a single 0-100 risk score and a verdict label.

## Heuristic scoring (always available)

Factors that increase risk:

- URL uses `http://` instead of `https://`
- Host is a raw IP address instead of a domain name
- URL is very long or heavily URL-encoded
- Many subdomains
- Suspicious keywords (`login`, `verify`, `secure`, `update`, `bank`, `account`, etc.)
- Redirects to a different domain

Factors that decrease risk:

- Short, clean URL
- Well-known TLD

## Optional API enrichment

If API keys are provided in `.env`, the score is also influenced by:

- **VirusTotal** — domain/URL reputation
- **urlscan.io** — scan results
- **AbuseIPDB** — IP reputation

If a key is missing, that module is skipped silently.

## Verdict labels

| Score | Label |
|---|---|
| 0-30 | Likely safe |
| 31-60 | Neutral / unknown |
| 61-85 | Suspicious |
| 86-100 | High risk |

The report shows only the final score and label, not the raw factor list, to keep it simple for non-technical users.
