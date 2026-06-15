import json
import logging
import os
import threading
import time
from typing import Optional

import docker

from url_utils import normalize_url

logger = logging.getLogger(__name__)

SCANNER_IMAGE = os.environ.get("SCANNER_IMAGE", "susp_url-scanner")
SCANNER_NETWORK = os.environ.get("SANDBOX_NETWORK", "susp-sandbox")
SCREENSHOTS_DIR = os.environ.get("SCREENSHOTS_DIR", "/app/screenshots")

docker_client = docker.from_env()


def _screenshots_host_path(sid: str) -> str:
    return os.path.join(SCREENSHOTS_DIR, sid)


def start_scanner(analysis_id: int, start_url: str, sid: str, max_pages: int = 5):
    container_name = f"susp-scanner-{sid}"
    try:
        container = docker_client.containers.run(
            SCANNER_IMAGE,
            name=container_name,
            environment={
                "SESSION_ID": sid,
                "START_URL": start_url,
                "MAX_PAGES": str(max_pages),
                "OUTPUT_DIR": "/screenshots",
            },
            volumes={
                "susp-url-screenshots": {"bind": "/screenshots", "mode": "rw"}
            },
            network=SCANNER_NETWORK,
            detach=True,
            auto_remove=True,
            mem_limit="1g",
            cpu_period=100000,
            cpu_quota=100000,
        )
        return container.id
    except Exception as e:
        logger.exception("Failed to start scanner container for %s", sid)
        raise RuntimeError(f"Failed to start scanner container: {e}")


def get_scanner_status(container_id: str, sid: str) -> str:
    """Return 'running', 'finished', or 'failed'."""
    try:
        container = docker_client.containers.get(container_id)
        if container.status == "running":
            return "running"
    except docker.errors.NotFound:
        pass

    meta_path = os.path.join(_screenshots_host_path(sid), "meta.json")
    if os.path.exists(meta_path):
        return "finished"
    return "failed"


def read_scan_results(sid: str) -> Optional[dict]:
    meta_path = os.path.join(_screenshots_host_path(sid), "meta.json")
    if not os.path.exists(meta_path):
        return None
    try:
        with open(meta_path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error("Failed to read scanner meta for %s: %s", sid, e)
        return None


def stop_scanner(container_id: str) -> None:
    try:
        container = docker_client.containers.get(container_id)
        container.stop(timeout=10)
    except docker.errors.NotFound:
        pass
    except Exception as e:
        logger.error("Error stopping scanner container %s: %s", container_id, e)


def cleanup_orphaned_scanners() -> None:
    try:
        for container in docker_client.containers.list(all=True, filters={"name": "susp-scanner-"}):
            try:
                container.stop(timeout=5)
            except Exception:
                pass
            try:
                container.remove(force=True)
            except Exception:
                pass
    except Exception as e:
        logger.error("Failed to clean up orphaned scanners: %s", e)
