# User workflow

## Page 1 — Submit URL

- User pastes a URL or domain.
- The app normalizes the input (adds `https://` if no scheme is given).
- If the URL was already analysed, a choice screen appears:
  - **View existing report** → Page 3 with the cached data.
  - **Analyse again** → start a fresh analysis, overwriting the old report.
- If the URL is new, analysis starts immediately.

## Page 2 — Live session + background scan

- A live Firefox sandbox is embedded via noVNC.
- The user can click, scroll, and navigate safely inside the sandbox.
- A timer starts at 2 minutes. The user can add time up to a total of 5 minutes.
- A small progress panel shows the background scan status:
  - pages visited,
  - screenshots captured,
- Clicking **Stop** ends the live session. The scanner is allowed to finish its queue.

## Page 3 — Report

- Shows a simple verdict and 0-100 risk score.
- Shows a one-sentence summary.
- Shows a horizontally scrollable strip of up to 5 thumbnails.
- Shows session metadata: start/end time, duration, container IDs.
