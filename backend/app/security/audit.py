from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from app.database import get_connection


class AuditLogger:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path

    def log_event(
        self,
        event_type: str,
        session_id: str,
        summary: str,
        details: dict[str, Any] | None = None,
        action_id: str | None = None,
        tool_name: str | None = None,
        policy_code: str | None = None,
        request_id: str | None = None,
        severity: str = 'info',
    ) -> str:
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        details = details or {}
        conn = get_connection(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO audit_events (
                    id, event_type, request_id, session_id, action_id,
                    tool_name, policy_code, severity, summary, details_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event_type,
                    request_id,
                    session_id,
                    action_id,
                    tool_name,
                    policy_code,
                    severity,
                    summary,
                    json.dumps(details, sort_keys=True),
                    timestamp,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return event_id

    def get_events(self, limit: int = 50) -> list[dict[str, Any]]:
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_dict(row) for row in rows]
        finally:
            conn.close()

    def get_trace(self, request_id: str) -> list[dict[str, Any]]:
        """Return all audit events for a single request, oldest first."""
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE request_id = ? ORDER BY created_at ASC",
                (request_id,),
            ).fetchall()
            return [self._row_to_dict(row) for row in rows]
        finally:
            conn.close()

    def get_request_ids(self, session_id: str, limit: int = 20) -> list[str]:
        """Return recent distinct request IDs for a session, newest first."""
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                """
                SELECT DISTINCT request_id
                FROM audit_events
                WHERE session_id = ? AND request_id IS NOT NULL
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
            return [row['request_id'] for row in rows]
        finally:
            conn.close()

    def get_provenance(self, session_id: str, limit: int = 50) -> list[dict[str, Any]]:
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                """
                SELECT details_json, created_at
                FROM audit_events
                WHERE session_id = ? AND event_type = 'tool_call_provenance'
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
            return [
                {
                    **json.loads(row['details_json'] or '{}'),
                    'created_at': row['created_at'],
                }
                for row in reversed(rows)
            ]
        finally:
            conn.close()

    @staticmethod
    def _row_to_dict(row: Any) -> dict[str, Any]:
        return {
            'id': row['id'],
            'event_type': row['event_type'],
            'request_id': row['request_id'],
            'session_id': row['session_id'],
            'action_id': row['action_id'],
            'tool_name': row['tool_name'],
            'policy_code': row['policy_code'],
            'severity': row['severity'],
            'summary': row['summary'],
            'details': json.loads(row['details_json'] or '{}'),
            'created_at': row['created_at'],
        }
