import atexit
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import docker
from flask import Flask, redirect, render_template, request, jsonify, url_for

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Configuration
SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "jlesage/firefox")
SANDBOX_NETWORK = os.environ.get("SANDBOX_NETWORK", "bridge")
SANDBOX_PORT = 5800
DEFAULT_DURATION = timedelta(minutes=2)
MAX_DURATION = timedelta(minutes=5)
EXTEND_STEP = timedelta(minutes=1)

# In-process session store (single gunicorn worker with threads)
sessions = {}
sessions_lock = threading.Lock()
timers = {}

try:
    docker_client = docker.from_env()
except Exception as e:
    logger.error("Unable to connect to Docker: %s", e)
    docker_client = None


def now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("URL is required")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")
    if not parsed.netloc:
        raise ValueError("Invalid URL or domain")
    return raw


def format_duration(td: timedelta) -> str:
    total_seconds = int(td.total_seconds())
    minutes, seconds = divmod(total_seconds, 60)
    return f"{minutes}m {seconds}s"


def _cancel_timer(sid: str) -> None:
    t = timers.pop(sid, None)
    if t is not None:
        t.cancel()


def _schedule_expiry(sid: str) -> None:
    """Schedule or reschedule the expiry timer for a session."""
    _cancel_timer(sid)
    with sessions_lock:
        session = sessions.get(sid)
        if not session or session["status"] != "active":
            return
        seconds = (session["end_time"] - now()).total_seconds()
    if seconds <= 0:
        destroy_session(sid, "timeout")
    else:
        t = threading.Timer(seconds, lambda: destroy_session(sid, "timeout"))
        t.daemon = True
        t.start()
        timers[sid] = t


def _wait_for_port_assignment(container, timeout: int = 30) -> int:
    """Return the random host port mapped to the sandbox web UI."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        container.reload()
        ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
        binding = ports.get(f"{SANDBOX_PORT}/tcp")
        if binding and binding[0].get("HostPort"):
            return int(binding[0]["HostPort"])
        time.sleep(1)
    raise RuntimeError("Sandbox container did not publish a host port in time")


def _wait_for_running(container, timeout: int = 30) -> None:
    """Wait until Docker reports the container as running."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        container.reload()
        if container.status == "running":
            return
        time.sleep(1)
    raise RuntimeError("Sandbox container did not start in time")


def _wait_for_ui(container, timeout: int = 60) -> bool:
    """Wait until the sandbox's own web UI responds (checked inside the container)."""
    cmd = ["/bin/sh", "-c", "wget -qO- http://localhost:5800 >/dev/null 2>&1"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            exit_code, _ = container.exec_run(cmd, demux=False)
            if exit_code == 0:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def create_session(target_url: str, host: str) -> str:
    if docker_client is None:
        raise RuntimeError("Docker is not available")

    sid = secrets.token_urlsafe(12)
    container_name = f"susp-sandbox-{sid}"
    start = now()

    session = {
        "sid": sid,
        "target_url": target_url,
        "container_name": container_name,
        "container_id": None,
        "host": host,
        "host_port": None,
        "vnc_url": None,
        "start_time": start,
        "end_time": start + DEFAULT_DURATION,
        "max_end_time": start + MAX_DURATION,
        "status": "active",
        "reason": None,
        "ended_at": None,
        "ready": False,
    }

    with sessions_lock:
        sessions[sid] = session

    try:
        container = docker_client.containers.run(
            SANDBOX_IMAGE,
            name=container_name,
            environment={
                "FF_OPEN_URL": target_url,
                "FF_KIOSK": "0",
            },
            ports={f"{SANDBOX_PORT}/tcp": ("0.0.0.0", None)},
            network=SANDBOX_NETWORK,
            detach=True,
            auto_remove=True,
            mem_limit="1g",
            cpu_period=100000,
            cpu_quota=100000,
        )
    except Exception as e:
        logger.exception("Failed to start sandbox container for %s", sid)
        with sessions_lock:
            sessions[sid]["status"] = "failed"
            sessions[sid]["reason"] = str(e)
        raise RuntimeError(f"Failed to start sandbox container: {e}")

    with sessions_lock:
        sessions[sid]["container_id"] = container.id

    try:
        host_port = _wait_for_port_assignment(container)
        _wait_for_running(container)
    except Exception as e:
        destroy_session(sid, "failed")
        raise RuntimeError(f"Sandbox did not expose a web port: {e}")

    vnc_url = f"http://{host}:{host_port}"

    with sessions_lock:
        sessions[sid]["host_port"] = host_port
        sessions[sid]["vnc_url"] = vnc_url

    # Wait for the noVNC UI to actually respond before exposing it to the user.
    if _wait_for_ui(container):
        with sessions_lock:
            sessions[sid]["ready"] = True
    else:
        logger.warning("Sandbox UI for %s did not become ready in time", sid)
        with sessions_lock:
            sessions[sid]["ready"] = True

    _schedule_expiry(sid)
    return sid


def destroy_session(sid: str, reason: str) -> None:
    with sessions_lock:
        session = sessions.get(sid)
        if not session or session["status"] != "active":
            return
        session["status"] = reason
        session["reason"] = reason
        session["ended_at"] = now()
        session["ready"] = False
        container_id = session.get("container_id")
        container_name = session.get("container_name")

    _cancel_timer(sid)

    if container_id:
        try:
            container = docker_client.containers.get(container_id)
            container.stop(timeout=10)
            logger.info("Stopped sandbox container %s (%s)", container_name, reason)
        except docker.errors.NotFound:
            logger.info("Sandbox container %s already removed", container_name)
        except Exception as e:
            logger.error("Error stopping sandbox container %s: %s", container_name, e)


def get_session(sid: str):
    with sessions_lock:
        return sessions.get(sid)


def destroy_all_sessions():
    with sessions_lock:
        active = [sid for sid, s in sessions.items() if s["status"] == "active"]
    for sid in active:
        destroy_session(sid, "shutdown")

atexit.register(destroy_all_sessions)


def cleanup_orphaned_sandboxes() -> None:
    """Remove any leftover sandbox containers from a previous run."""
    if docker_client is None:
        return
    try:
        for container in docker_client.containers.list(all=True, filters={"name": "susp-sandbox-"}):
            try:
                container.stop(timeout=5)
            except Exception:
                pass
            try:
                container.remove(force=True)
            except Exception:
                pass
    except Exception as e:
        logger.error("Failed to clean up orphaned sandboxes: %s", e)


cleanup_orphaned_sandboxes()


@app.route("/", methods=["GET"])
def index():
    return render_template("page1.html", error=None)


@app.route("/start", methods=["POST"])
def start():
    raw = request.form.get("url", "")
    try:
        url = normalize_url(raw)
    except ValueError as e:
        return render_template("page1.html", error=str(e)), 400

    host = request.host.split(":")[0]
    try:
        sid = create_session(url, host)
    except Exception as e:
        logger.exception("Start session failed")
        return render_template("page1.html", error=str(e)), 500

    return redirect(url_for("session_page", sid=sid))


@app.route("/session/<sid>")
def session_page(sid):
    session = get_session(sid)
    if not session:
        return render_template("page1.html", error="Session not found"), 404
    if session["status"] != "active":
        return redirect(url_for("report", sid=sid))
    return render_template("page2.html", sid=sid, target_url=session["target_url"])


@app.route("/session/<sid>/status")
def session_status(sid):
    session = get_session(sid)
    if not session:
        return jsonify({"active": False}), 404
    remaining = max(0, int((session["end_time"] - now()).total_seconds()))
    return jsonify({
        "active": session["status"] == "active",
        "ready": session["ready"],
        "vnc_url": session["vnc_url"],
        "end_time": int(session["end_time"].timestamp() * 1000),
        "max_end_time": int(session["max_end_time"].timestamp() * 1000),
        "remaining_seconds": remaining,
    })


@app.route("/session/<sid>/extend", methods=["POST"])
def extend_session(sid):
    session = get_session(sid)
    if not session or session["status"] != "active":
        return jsonify({"error": "Session is not active"}), 400

    with sessions_lock:
        new_end = session["end_time"] + EXTEND_STEP
        if new_end > session["max_end_time"]:
            remaining = int((session["max_end_time"] - session["end_time"]).total_seconds())
            return jsonify({
                "error": f"Cannot extend beyond the maximum session length. Remaining extendable time: {remaining}s"
            }), 400
        session["end_time"] = new_end

    _schedule_expiry(sid)
    remaining = max(0, int((session["end_time"] - now()).total_seconds()))
    return jsonify({
        "end_time": int(session["end_time"].timestamp() * 1000),
        "remaining_seconds": remaining,
    })


@app.route("/session/<sid>/stop", methods=["POST"])
def stop_session(sid):
    destroy_session(sid, "stopped")
    return jsonify({"redirect": url_for("report", sid=sid)})


@app.route("/report/<sid>")
def report(sid):
    session = get_session(sid)
    if not session:
        return render_template("page1.html", error="Session not found"), 404

    ended_at = session["ended_at"] or now()
    duration = ended_at - session["start_time"]
    return render_template(
        "page3.html",
        sid=sid,
        target_url=session["target_url"],
        status=session["status"],
        start_time=session["start_time"].strftime("%Y-%m-%d %H:%M:%S UTC"),
        ended_at=ended_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        duration=format_duration(duration),
        container_name=session["container_name"],
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
