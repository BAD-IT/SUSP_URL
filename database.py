import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional

from url_utils import normalize_url, get_domain

DB_PATH = os.environ.get("DB_PATH", "/app/data/susp_url.db")
REPORT_TTL_SECONDS = int(os.environ.get("REPORT_TTL_SECONDS", "3600"))


@contextmanager
def _connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                domain TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                score INTEGER,
                verdict TEXT,
                summary TEXT,
                report_json TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                title TEXT,
                filename TEXT NOT NULL,
                order_index INTEGER NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_analyses_url ON analyses(url);
            CREATE INDEX IF NOT EXISTS idx_screenshots_analysis ON screenshots(analysis_id);
            """
        )


def now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in row.keys()}


def find_analysis(url: str) -> Optional[dict]:
    try:
        url = normalize_url(url)
    except ValueError:
        return None
    with _connection() as conn:
        row = conn.execute("SELECT * FROM analyses WHERE url = ?", (url,)).fetchone()
        if not row:
            return None
        return _row_to_dict(row)


def is_fresh(analysis: dict) -> bool:
    if analysis["status"] != "completed":
        return False
    updated = analysis.get("updated_at")
    if not updated:
        return False
    if isinstance(updated, str):
        updated = datetime.fromisoformat(updated.replace("Z", "+00:00"))
    return now() - updated < timedelta(seconds=REPORT_TTL_SECONDS)


def create_or_reset_analysis(url: str) -> int:
    url = normalize_url(url)
    domain = get_domain(url)
    with _connection() as conn:
        conn.execute(
            """
            INSERT INTO analyses (url, domain, status, score, verdict, summary, report_json, created_at, updated_at)
            VALUES (?, ?, 'pending', NULL, NULL, NULL, NULL, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                status = 'pending',
                score = NULL,
                verdict = NULL,
                summary = NULL,
                report_json = NULL,
                updated_at = excluded.updated_at
            """,
            (url, domain, now(), now()),
        )
        row = conn.execute("SELECT id FROM analyses WHERE url = ?", (url,)).fetchone()
        return row["id"]


def complete_analysis(
    analysis_id: int,
    score: int,
    verdict: str,
    summary: str,
    report: dict,
) -> None:
    with _connection() as conn:
        conn.execute(
            """
            UPDATE analyses
            SET status = 'completed',
                score = ?,
                verdict = ?,
                summary = ?,
                report_json = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (score, verdict, summary, json.dumps(report), now(), analysis_id),
        )


def fail_analysis(analysis_id: int) -> None:
    with _connection() as conn:
        conn.execute(
            "UPDATE analyses SET status = 'failed', updated_at = ? WHERE id = ?",
            (now(), analysis_id),
        )


def add_screenshot(analysis_id: int, url: str, title: Optional[str], filename: str, order_index: int) -> None:
    with _connection() as conn:
        conn.execute(
            "INSERT INTO screenshots (analysis_id, url, title, filename, order_index) VALUES (?, ?, ?, ?, ?)",
            (analysis_id, url, title, filename, order_index),
        )


def clear_screenshots(analysis_id: int) -> None:
    with _connection() as conn:
        conn.execute("DELETE FROM screenshots WHERE analysis_id = ?", (analysis_id,))


def get_screenshots(analysis_id: int) -> list:
    with _connection() as conn:
        rows = conn.execute(
            "SELECT * FROM screenshots WHERE analysis_id = ? ORDER BY order_index",
            (analysis_id,),
        ).fetchall()
        return [_row_to_dict(row) for row in rows]


def get_analysis_by_id(analysis_id: int) -> Optional[dict]:
    with _connection() as conn:
        row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        if not row:
            return None
        return _row_to_dict(row)
