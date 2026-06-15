import atexit
import logging
import os
import secrets
import shutil
import threading
import time
from datetime import datetime, timezone, timedelta

import docker
from flask import Flask, redirect, render_template, request, jsonify, url_for, send_from_directory, abort

import database
import scanner_mgr
import scoring
from url_utils import normalize_url, get_domain

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Configuration
SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "jlesage/firefox")
SANDBOX_NETWORK = os.environ.get("SANDBOX_NETWORK", "susp-sandbox")
SANDBOX_PORT = 5800
SCANNER_MAX_PAGES = int(os.environ.get("SCANNER_MAX_PAGES", "5"))

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

# Initialise database schema on startup.
database.init_db()


def now() -> datetime:
    return datetime.now(timezone.utc)


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


def _wait_for_ui(container, timeout: int = 90) -> bool:
    """Wait until the sandbox's own web UI responds reliably.

    Require two consecutive successful fetches a few seconds apart to avoid
    marking the session ready during a transient startup state.
    """
    cmd = ["/bin/sh", "-c", "wget -qO- http://localhost:5800 >/dev/null 2>&1"]
    deadline = time.time() + timeout
    consecutive = 0
    while time.time() < deadline:
        try:
            exit_code, _ = container.exec_run(cmd, demux=False)
            if exit_code == 0:
                consecutive += 1
                if consecutive >= 2:
                    return True
            else:
                consecutive = 0
        except Exception:
            consecutive = 0
        time.sleep(3)
    return False


def _delete_screenshot_files(sid: str) -> None:
    path = os.path.join(scanner_mgr.SCREENSHOTS_DIR, sid)
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)


def _process_scan_results(sid: str) -> None:
    """Wait for scanner to finish and persist results. Runs in a background thread."""
    with sessions_lock:
        session = sessions.get(sid)
        if not session:
            return
        scanner_id = session.get("scanner_container_id")
        analysis_id = session["analysis_id"]

    if not scanner_id:
        database.fail_analysis(analysis_id)
        return

    # Poll until scanner finishes or times out (max 5 minutes).
    deadline = time.time() + 300
    while time.time() < deadline:
        status = scanner_mgr.get_scanner_status(scanner_id, sid)
        if status == "finished":
            break
        if status == "failed":
            database.fail_analysis(analysis_id)
            return
        time.sleep(2)
    else:
        logger.warning("Scanner for %s did not finish in time", sid)
        database.fail_analysis(analysis_id)
        return

    meta = scanner_mgr.read_scan_results(sid)
    if not meta:
        database.fail_analysis(analysis_id)
        return

    pages = [p for p in meta.get("pages", []) if p.get("filename")]
    score, verdict, summary = scoring.calculate_score(session["target_url"], pages)

    database.clear_screenshots(analysis_id)
    os.makedirs(os.path.join(scanner_mgr.SCREENSHOTS_DIR, sid), exist_ok=True)

    for idx, page in enumerate(pages, start=1):
        # Store the relative path so the web app can serve the file and clean it up later.
        rel_path = f"{sid}/{page['filename']}"
        database.add_screenshot(
            analysis_id=analysis_id,
            url=page["url"],
            title=page.get("title"),
            filename=rel_path,
            order_index=idx,
        )

    database.complete_analysis(
        analysis_id=analysis_id,
        score=score,
        verdict=verdict,
        summary=summary,
        report={"pages": meta.get("pages", []), "page_count": len(pages)},
    )
    logger.info("Analysis %s completed: score=%s verdict=%s", analysis_id, score, verdict)


def create_session(target_url: str, host: str, analysis_id: int) -> str:
    if docker_client is None:
        raise RuntimeError("Docker is not available")

    sid = secrets.token_urlsafe(12)
    container_name = f"susp-sandbox-{sid}"
    start = now()

    session = {
        "sid": sid,
        "analysis_id": analysis_id,
        "target_url": target_url,
        "container_name": container_name,
        "container_id": None,
        "scanner_container_id": None,
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
        "scan_status": "pending",
    }

    with sessions_lock:
        sessions[sid] = session

    # Start live sandbox
    try:
        container = docker_client.containers.run(
            SANDBOX_IMAGE,
            name=container_name,
            environment={
                "FF_OPEN_URL": target_url,
                "FF_KIOSK": "0",
            },
            ports={f"{SANDBOX_PORT}/tcp": ("127.0.0.1", None)},
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
        database.fail_analysis(analysis_id)
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
        sessions[sid]["ready"] = True

    # Start background scanner
    try:
        scanner_id = scanner_mgr.start_scanner(analysis_id, target_url, sid, SCANNER_MAX_PAGES)
        with sessions_lock:
            sessions[sid]["scanner_container_id"] = scanner_id
            sessions[sid]["scan_status"] = "running"
        threading.Thread(target=_process_scan_results, args=(sid,), daemon=True).start()
    except Exception as e:
        logger.exception("Failed to start scanner for %s", sid)
        with sessions_lock:
            sessions[sid]["scan_status"] = "failed"

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


scanner_mgr.cleanup_orphaned_scanners()
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

    existing = database.find_analysis(url)
    if existing:
        return redirect(url_for("url_exists", url=url))

    analysis_id = database.create_or_reset_analysis(url)
    # Bind the live sandbox UI to the host loopback so the browser can reach it
    # reliably via IPv4 and avoid IPv6/localhost resolution issues.
    host = "127.0.0.1"
    try:
        sid = create_session(url, host, analysis_id)
    except Exception as e:
        logger.exception("Start session failed")
        database.fail_analysis(analysis_id)
        return render_template("page1.html", error=str(e)), 500

    return redirect(url_for("session_page", sid=sid))


@app.route("/url-exists")
def url_exists():
    raw = request.args.get("url", "")
    try:
        url = normalize_url(raw)
    except ValueError:
        return render_template("page1.html", error="Invalid URL"), 400

    analysis = database.find_analysis(url)
    if not analysis:
        return redirect(url_for("index"))

    fresh = database.is_fresh(analysis)
    return render_template(
        "page_exists.html",
        url=url,
        analysis=analysis,
        fresh=fresh,
    )


@app.route("/analyse-again", methods=["POST"])
def analyse_again():
    raw = request.form.get("url", "")
    try:
        url = normalize_url(raw)
    except ValueError as e:
        return render_template("page1.html", error=str(e)), 400

    analysis_id = database.create_or_reset_analysis(url)
    _delete_screenshot_files_for_analysis(analysis_id)
    database.clear_screenshots(analysis_id)

    host = "127.0.0.1"
    try:
        sid = create_session(url, host, analysis_id)
    except Exception as e:
        logger.exception("Start re-analysis failed")
        database.fail_analysis(analysis_id)
        return render_template("page1.html", error=str(e)), 500

    return redirect(url_for("session_page", sid=sid))


def _delete_screenshot_files_for_analysis(analysis_id: int) -> None:
    """Delete old screenshot files for an analysis before re-analysing."""
    base = scanner_mgr.SCREENSHOTS_DIR
    for shot in database.get_screenshots(analysis_id):
        path = os.path.join(base, shot["filename"])
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    # Clean up empty session directories.
    if os.path.isdir(base):
        for name in os.listdir(base):
            path = os.path.join(base, name)
            if os.path.isdir(path) and not os.listdir(path):
                shutil.rmtree(path, ignore_errors=True)


@app.route("/session/<sid>")
def session_page(sid):
    session = get_session(sid)
    if not session:
        return render_template("page1.html", error="Session not found"), 404
    if session["status"] != "active":
        return redirect(url_for("report", analysis_id=session["analysis_id"]))
    return render_template(
        "page2.html",
        sid=sid,
        target_url=session["target_url"],
        analysis_id=session["analysis_id"],
    )


@app.route("/session/<sid>/status")
def session_status(sid):
    session = get_session(sid)
    if not session:
        return jsonify({"active": False}), 404

    remaining = max(0, int((session["end_time"] - now()).total_seconds()))

    scan_status = session.get("scan_status", "pending")
    if scan_status == "running" and session.get("scanner_container_id"):
        scan_status = scanner_mgr.get_scanner_status(
            session["scanner_container_id"], sid
        )
        with sessions_lock:
            sessions[sid]["scan_status"] = scan_status

    return jsonify({
        "active": session["status"] == "active",
        "ready": session["ready"],
        "vnc_url": session["vnc_url"],
        "end_time": int(session["end_time"].timestamp() * 1000),
        "max_end_time": int(session["max_end_time"].timestamp() * 1000),
        "remaining_seconds": remaining,
        "scan_status": scan_status,
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
    session = get_session(sid)
    if not session:
        return jsonify({"redirect": url_for("index")})
    destroy_session(sid, "stopped")
    return jsonify({"redirect": url_for("report", analysis_id=session["analysis_id"])})


@app.route("/report/<int:analysis_id>")
def report(analysis_id):
    analysis = database.get_analysis_by_id(analysis_id)
    if not analysis:
        return render_template("page1.html", error="Report not found"), 404

    screenshots = database.get_screenshots(analysis_id)
    fresh = database.is_fresh(analysis)
    ended_at_str = analysis.get("updated_at") or analysis.get("created_at") or now().isoformat()
    created_at_str = analysis.get("created_at") or ended_at_str
    ended_at = datetime.fromisoformat(ended_at_str)
    created_at = datetime.fromisoformat(created_at_str)
    duration = ended_at - created_at

    return render_template(
        "page3.html",
        analysis=analysis,
        screenshots=screenshots,
        fresh=fresh,
        duration=format_duration(duration),
        ended_at=ended_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


@app.route("/report/<int:analysis_id>/status")
def report_status(analysis_id):
    analysis = database.get_analysis_by_id(analysis_id)
    if not analysis:
        return jsonify({"found": False}), 404
    return jsonify({
        "found": True,
        "status": analysis["status"],
        "score": analysis["score"],
        "verdict": analysis["verdict"],
    })


@app.route("/screenshots/<path:filename>")
def serve_screenshot(filename):
    directory = scanner_mgr.SCREENSHOTS_DIR
    try:
        return send_from_directory(directory, filename)
    except FileNotFoundError:
        abort(404)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    database.init_db()
    app.run(host="0.0.0.0", port=5000, threaded=True)
