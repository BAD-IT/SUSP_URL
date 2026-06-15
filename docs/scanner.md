# Background scanner

The scanner is a separate container that runs while the user interacts with the live sandbox.

## Behaviour

- Starts from the submitted URL.
- Extracts all links on the page whose hostname matches the target domain.
- Visits up to 5 unique same-domain URLs (including the start page).
- Saves a full-page PNG screenshot for each visited URL.
- Writes a small JSON metadata file with visited URLs and page titles.

## Container

- Image: custom `susp_url-scanner` built from `scanner/Dockerfile`
- Based on `python:3.12-slim` with Playwright and Chromium
- Runs a single Python script: `scanner.py`
- Container is removed automatically after it exits

## Isolation

- The scanner container is attached to the same isolated `susp-sandbox` network as the live sandbox.
- It does not share runtime with the web app container.
- Resource limits are applied at container creation time.

## Output

All output is written to `/screenshots/<session-id>/`:

```
/screenshots/<session-id>/
  meta.json
  001_home.png
  002_about.png
  ...
```

The web container reads these files from the shared volume.
