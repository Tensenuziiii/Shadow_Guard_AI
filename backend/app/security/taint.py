from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from app.config import SESSION_TTL_SECONDS
from app.database import get_connection


class TaintEngine:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path

    def get_or_create_session(self, session_id: str | None, user_id: str) -> str:
        if not session_id:
            session_id = str(uuid.uuid4())
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                'SELECT id, user_id FROM sessions WHERE id = ?',
                (session_id,),
            ).fetchone()
            if row is None:
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    'INSERT INTO sessions (id, user_id, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
                    (session_id, user_id, 'CLEAN', now, now),
                )
                conn.commit()
            elif row['user_id'] != user_id:
                raise PermissionError('Session belongs to a different user.')
        finally:
            conn.close()
        return session_id

    def current_state(self, session_id: str) -> str:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute('SELECT state FROM sessions WHERE id = ?', (session_id,)).fetchone()
            return row['state'] if row else 'CLEAN'
        finally:
            conn.close()

    def is_tainted(self, session_id: str) -> bool:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute('SELECT state FROM sessions WHERE id = ?', (session_id,)).fetchone()
            return bool(row and row['state'] == 'TAINTED')
        finally:
            conn.close()

    def mark_tainted(
        self,
        session_id: str,
        source: str,
        tool_call_id: str | None = None,
        affected_fields: list[str] | None = None,
    ) -> None:
        conn = get_connection(self.db_path)
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                'UPDATE sessions SET state = ?, tainted_at = ?, taint_source = ?, updated_at = ? WHERE id = ?',
                ('TAINTED', now, source, now, session_id),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO taint_sources
                    (id, session_id, source_tool, tool_call_id, affected_fields_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    session_id,
                    source,
                    tool_call_id or str(uuid.uuid4()),
                    json.dumps(sorted(set(affected_fields or []))),
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_sources(self, session_id: str) -> list[dict[str, Any]]:
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                """
                SELECT source_tool, tool_call_id, affected_fields_json, created_at
                FROM taint_sources
                WHERE session_id = ?
                ORDER BY created_at, id
                """,
                (session_id,),
            ).fetchall()
            return [
                {
                    'source_tool': row['source_tool'],
                    'tool_call_id': row['tool_call_id'],
                    'affected_fields': json.loads(row['affected_fields_json']),
                    'created_at': row['created_at'],
                }
                for row in rows
            ]
        finally:
            conn.close()

    def can_access_tool(self, session_id: str, tool_zone: str) -> tuple[bool, str | None]:
        if tool_zone == 'HIGH' and self.is_tainted(session_id):
            return False, 'TAINTED_HIGH_TRUST_BLOCK'
        return True, None
