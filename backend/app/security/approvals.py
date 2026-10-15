from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from app.config import APPROVAL_TIMEOUT_SECONDS
from app.database import get_connection
from app.security.risk_engine import analyze_sql
from app.security.shadow_state import ShadowStateManager

logger = logging.getLogger(__name__)


class ApprovalManager:
    def __init__(self, db_path: str | None = None, timeout_seconds: int = APPROVAL_TIMEOUT_SECONDS):
        self.db_path = db_path
        self.timeout_seconds = timeout_seconds

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _hash(self, value: str) -> str:
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def create_pending(
        self,
        session_id: str,
        user_id: str,
        tool_name: str,
        sql_text: str,
        shadow_result: dict[str, Any],
        arguments: dict[str, Any] | None = None,
        taint_override_required: bool = False,
        taint_sources: list[dict[str, Any]] | None = None,
        approval_kind: str = 'one_time',
        operation: str | None = None,
        target_resource: str | None = None,
        destination_mcp: str | None = None,
        permitted_capabilities: list[str] | None = None,
        grant_duration_seconds: int | None = None,
        request_id: str | None = None,
        user_objective: str | None = None,
    ) -> dict[str, Any]:
        action_id = str(uuid.uuid4())
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=self.timeout_seconds)).isoformat()
        approval_kind = approval_kind if approval_kind in {'one_time', 'persistent_grant'} else 'one_time'
        operation = operation or ('SQL' if sql_text else 'tool_call')
        target_resource = target_resource or tool_name
        destination_mcp = destination_mcp or tool_name
        permitted_capabilities = permitted_capabilities or []
        staged = dict(shadow_result)
        staged['_action'] = {
            'integrity_version': 2,
            'arguments': arguments if arguments is not None else ({'sql': sql_text} if sql_text else {}),
            'taint_override_required': taint_override_required,
            'taint_sources': taint_sources or [],
            'approval_kind': approval_kind,
            'operation': operation,
            'target_resource': target_resource,
            'destination_mcp': destination_mcp,
            'permitted_capabilities': permitted_capabilities,
            'grant_duration_seconds': grant_duration_seconds,
        }
        action_hash = self._staged_action_hash(session_id, tool_name, sql_text, staged)
        conn = get_connection(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO approvals (
                    id, request_id, session_id, user_id, user_objective,
                    tool_name, action_hash, sql_text, status,
                    approval_kind, operation, target_resource, destination_mcp,
                    permitted_capabilities_json, grant_duration_seconds,
                    created_at, expires_at, snapshot_fingerprint, staged_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    request_id,
                    session_id,
                    user_id,
                    user_objective,
                    tool_name,
                    action_hash,
                    sql_text,
                    approval_kind,
                    operation,
                    target_resource,
                    destination_mcp,
                    json.dumps(permitted_capabilities),
                    grant_duration_seconds,
                    self._now(),
                    expires_at,
                    shadow_result.get('snapshot_fingerprint'),
                    json.dumps(staged, sort_keys=True),
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return {
            'approval_id': action_id,
            'status': 'PENDING_APPROVAL',
            'expires_at': expires_at,
            'action_hash': action_hash,
            'details': shadow_result,
        }

    def _staged_action_hash(self, session_id: str, tool_name: str, sql_text: str, staged: dict[str, Any]) -> str:
        integrity_data = {key: value for key, value in staged.items() if key != '_agent_context'}
        if isinstance(integrity_data.get('_action'), dict):
            action = dict(integrity_data['_action'])
            for grant_key in ('approval_kind', 'grant_duration_seconds', 'permitted_capabilities'):
                action.pop(grant_key, None)
            integrity_data['_action'] = action
        payload = json.dumps(
            {
                'session_id': session_id,
                'tool_name': tool_name,
                'sql_text': sql_text,
                'staged': integrity_data,
            },
            sort_keys=True,
            separators=(',', ':'),
        )
        return self._hash(payload)

    def get_by_id(self, approval_id: str) -> sqlite3.Row | None:
        conn = get_connection(self.db_path)
        try:
            return conn.execute('SELECT * FROM approvals WHERE id = ?', (approval_id,)).fetchone()
        finally:
            conn.close()

    def get_pending(self) -> list[dict[str, Any]]:
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute("SELECT * FROM approvals WHERE status = 'PENDING_APPROVAL' ORDER BY created_at DESC").fetchall()
            pending = []
            for row in rows:
                item = dict(row)
                staged = json.loads(item['staged_json'] or '{}')
                staged.pop('_agent_context', None)
                item['staged_json'] = json.dumps(staged, sort_keys=True)
                # Surface these at the top level for the approval UI
                item.setdefault('request_id', item.get('request_id'))
                item.setdefault('user_objective', item.get('user_objective'))
                pending.append(item)
            return pending
        finally:
            conn.close()

    def attach_agent_context(self, approval_id: str, context: dict[str, Any]) -> None:
        conn = get_connection(self.db_path)
        try:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute(
                "SELECT staged_json FROM approvals WHERE id = ? AND status = 'PENDING_APPROVAL'",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise ValueError('Pending approval was not found while storing agent continuation.')
            staged = json.loads(row['staged_json'] or '{}')
            staged['_agent_context'] = context
            conn.execute(
                "UPDATE approvals SET staged_json = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                (json.dumps(staged, sort_keys=True), approval_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_agent_context(self, approval_id: str) -> dict[str, Any] | None:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute('SELECT staged_json FROM approvals WHERE id = ?', (approval_id,)).fetchone()
            if row is None:
                return None
            staged = json.loads(row['staged_json'] or '{}')
            context = staged.get('_agent_context')
            return context if isinstance(context, dict) else None
        finally:
            conn.close()

    def decide(
        self,
        approval_id: str,
        decision: str,
        session_id: str,
        user_id: str,
        db_path: str,
        raw_tools: dict[str, Any] | None = None,
        approval_kind: str | None = None,
        grant_duration_seconds: int | None = None,
    ) -> dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            normalized_decision = decision.lower()
            if normalized_decision not in {'approve', 'reject'}:
                return {'isError': True, 'status': 'FAILED', 'message': 'Decision must be approve or reject', 'policy_code': 'INVALID_DECISION'}

            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT * FROM approvals WHERE id = ?', (approval_id,)).fetchone()
            if row is None:
                conn.rollback()
                return {'isError': True, 'status': 'FAILED', 'message': 'Unknown approval id', 'policy_code': 'UNKNOWN_APPROVAL'}
            if row['session_id'] != session_id or row['user_id'] != user_id:
                conn.rollback()
                return {'isError': True, 'status': 'FAILED', 'message': 'Session mismatch for approval', 'policy_code': 'SESSION_MISMATCH'}
            if row['status'] != 'PENDING_APPROVAL':
                conn.rollback()
                return {'isError': True, 'status': row['status'], 'message': 'Approval was already resolved', 'policy_code': 'APPROVAL_ALREADY_RESOLVED'}
            if datetime.now(timezone.utc).isoformat() > row['expires_at']:
                conn.execute(
                    "UPDATE approvals SET status = 'EXPIRED', rejected_at = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                    (self._now(), approval_id),
                )
                conn.commit()
                return {'isError': True, 'status': 'EXPIRED', 'message': 'Approval expired', 'policy_code': 'APPROVAL_EXPIRED'}
            if normalized_decision == 'reject':
                conn.execute(
                    "UPDATE approvals SET status = 'REJECTED', rejected_at = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                    (self._now(), approval_id),
                )
                conn.commit()
                return {'isError': True, 'status': 'REJECTED', 'message': 'Human rejected the staged action', 'policy_code': 'APPROVAL_REJECTED'}

            sql_text = row['sql_text'] or ''
            staged = json.loads(row['staged_json'] or '{}')
            action = staged.get('_action', {})
            selected_approval_kind = approval_kind or row['approval_kind'] or action.get('approval_kind') or 'one_time'
            if selected_approval_kind not in {'one_time', 'persistent_grant'}:
                conn.rollback()
                return {'isError': True, 'status': 'FAILED', 'message': 'Unsupported approval kind', 'policy_code': 'INVALID_APPROVAL_KIND'}
            selected_grant_duration = grant_duration_seconds or row['grant_duration_seconds'] or action.get('grant_duration_seconds') or 3600
            if selected_approval_kind == 'persistent_grant' and (selected_grant_duration <= 0 or selected_grant_duration > 86400):
                conn.rollback()
                return {'isError': True, 'status': 'FAILED', 'message': 'Persistent grants must last between 1 second and 24 hours', 'policy_code': 'INVALID_GRANT_DURATION'}
            action['approval_kind'] = selected_approval_kind
            action['grant_duration_seconds'] = selected_grant_duration if selected_approval_kind == 'persistent_grant' else None
            staged['_action'] = action
            if action.get('integrity_version') == 2:
                expected_hash = self._staged_action_hash(
                    row['session_id'],
                    row['tool_name'],
                    sql_text,
                    staged,
                )
            else:
                expected_hash = self._hash(
                    f'{row["session_id"]}:{row["tool_name"]}:{sql_text}:{row["snapshot_fingerprint"] or ""}'
                )
            if (
                row['tool_name'] not in {'production_database', 'github_reader', 'weather_api'}
                or (row['tool_name'] == 'production_database' and not sql_text)
                or not hmac.compare_digest(expected_hash, row['action_hash'])
            ):
                conn.execute(
                    "UPDATE approvals SET status = 'CANCELLED', result_json = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                    (json.dumps({'reason': 'Staged action integrity check failed'}), approval_id),
                )
                conn.commit()
                return {'isError': True, 'status': 'CANCELLED', 'message': 'The staged action failed integrity validation', 'policy_code': 'ACTION_INTEGRITY_FAILED'}

            session = conn.execute(
                'SELECT user_id, state FROM sessions WHERE id = ?',
                (session_id,),
            ).fetchone()
            tool = conn.execute(
                'SELECT enabled, trust_zone FROM tool_registry WHERE name = ?',
                (row['tool_name'],),
            ).fetchone()
            taint_override_required = action.get('taint_override_required') is True
            expected_sources = self._normalize_taint_sources(action.get('taint_sources', []))
            current_sources = self._current_taint_sources(conn, session_id)
            taint_policy_valid = (
                session is not None
                and (
                    (session['state'] == 'TAINTED'
                     and taint_override_required
                     and bool(expected_sources)
                     and current_sources == expected_sources)
                    or (session['state'] != 'TAINTED' and not taint_override_required)
                )
            )
            if (
                session is None
                or session['user_id'] != user_id
                or not taint_policy_valid
                or tool is None
                or not tool['enabled']
                or (row['tool_name'] == 'production_database' and tool['trust_zone'] != 'HIGH')
            ):
                conn.execute(
                    "UPDATE approvals SET status = 'CANCELLED', result_json = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                    (json.dumps({'reason': 'Current session or tool policy denied execution'}), approval_id),
                )
                conn.commit()
                return {'isError': True, 'status': 'CANCELLED', 'message': 'Current session or integration policy no longer permits execution', 'policy_code': 'POLICY_REVALIDATION_FAILED'}

            action_arguments = action.get('arguments', {'sql': sql_text})
            execution_result: dict[str, Any] = {}
            if row['tool_name'] == 'production_database':
                if action_arguments != {'sql': sql_text}:
                    conn.execute(
                        "UPDATE approvals SET status = 'CANCELLED', result_json = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                        (json.dumps({'reason': 'Staged SQL arguments do not match the action text'}), approval_id),
                    )
                    conn.commit()
                    return {'isError': True, 'status': 'CANCELLED', 'message': 'The staged SQL arguments changed; request a new approval', 'policy_code': 'ACTION_INTEGRITY_FAILED'}

                risk = analyze_sql(sql_text)
                executable_mutation = (
                    risk['destructive']
                    and risk['statement_type'] in {'INSERT', 'UPDATE', 'DELETE'}
                )
                approved_read = (
                    taint_override_required
                    and risk['statement_type'] == 'SELECT'
                )
                if not risk['allowed'] or not (executable_mutation or approved_read):
                    conn.execute(
                        "UPDATE approvals SET status = 'CANCELLED', result_json = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                        (json.dumps({'reason': 'SQL policy rejected the staged statement', 'policy': risk}), approval_id),
                    )
                    conn.commit()
                    return {'isError': True, 'status': 'CANCELLED', 'message': 'The staged SQL no longer satisfies policy', 'policy_code': 'SQL_POLICY_REVALIDATION_FAILED'}

                if staged.get('snapshot_fingerprint') != row['snapshot_fingerprint']:
                    conn.execute(
                        "UPDATE approvals SET status = 'CANCELLED', result_json = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                        (json.dumps({'reason': 'Stored snapshot fingerprint does not match the staged action'}), approval_id),
                    )
                    conn.commit()
                    return {'isError': True, 'status': 'CANCELLED', 'message': 'The staged action failed snapshot validation', 'policy_code': 'SNAPSHOT_INTEGRITY_FAILED'}

                real_db = sqlite3.connect(db_path, timeout=10)
                try:
                    real_db.execute('BEGIN IMMEDIATE')
                    current_fingerprint = ShadowStateManager(db_path).snapshot_fingerprint(real_db)
                    if not hmac.compare_digest(current_fingerprint, row['snapshot_fingerprint']):
                        real_db.rollback()
                        conn.execute(
                            "UPDATE approvals SET status = 'CANCELLED', result_json = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                            (json.dumps({'reason': 'Production database changed after simulation'}), approval_id),
                        )
                        conn.commit()
                        return {'isError': True, 'status': 'CANCELLED', 'message': 'Production data changed after simulation; request a new approval', 'policy_code': 'SNAPSHOT_CHANGED'}

                    changed = conn.execute(
                        "UPDATE approvals SET status = 'EXECUTING', approved_at = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                        (self._now(), approval_id),
                    ).rowcount
                    if changed != 1:
                        real_db.rollback()
                        conn.rollback()
                        return {'isError': True, 'status': 'FAILED', 'message': 'Approval is no longer pending', 'policy_code': 'APPROVAL_ALREADY_RESOLVED'}
                    conn.commit()

                    cursor = real_db.execute(sql_text)
                    if risk['statement_type'] == 'SELECT':
                        columns = [column[0] for column in cursor.description or []]
                        selected_rows = cursor.fetchmany(101)
                        execution_result = {
                            'rows': [dict(zip(columns, result_row)) for result_row in selected_rows[:100]],
                            'truncated': len(selected_rows) > 100,
                        }
                    else:
                        execution_result = {'rows_affected': int(cursor.rowcount if cursor.rowcount >= 0 else 0)}
                    real_db.commit()
                except sqlite3.Error as exc:
                    real_db.rollback()
                    conn.execute(
                        "UPDATE approvals SET status = 'FAILED', result_json = ? WHERE id = ? AND status = 'EXECUTING'",
                        (json.dumps({'error': str(exc)}), approval_id),
                    )
                    conn.commit()
                    return {'isError': True, 'status': 'FAILED', 'message': f'Execution failed: {exc}', 'policy_code': 'EXECUTION_FAILED'}
                finally:
                    real_db.close()
            else:
                if row['tool_name'] == 'github_reader':
                    valid_arguments = (
                        isinstance(action_arguments, dict)
                        and set(action_arguments) in ({'repo'}, {'repo', 'path'})
                    )
                    parameter_value = action_arguments.get('repo') if valid_arguments else None
                    path = action_arguments.get('path') if valid_arguments else None
                    path_valid = (
                        path is None
                        or isinstance(path, str)
                        and bool(path)
                        and len(path) <= 512
                        and not path.startswith('/')
                        and all(part not in {'', '.', '..'} for part in path.split('/'))
                    )
                else:
                    valid_arguments = (
                        isinstance(action_arguments, dict)
                        and set(action_arguments) == {'city'}
                    )
                    parameter_value = action_arguments.get('city') if valid_arguments else None
                    path_valid = True
                if (
                    not taint_override_required
                    or not valid_arguments
                    or not isinstance(parameter_value, str)
                    or len(parameter_value) > 256
                    or not path_valid
                    or raw_tools is None
                    or not callable(raw_tools.get(row['tool_name']))
                ):
                    conn.execute(
                        "UPDATE approvals SET status = 'CANCELLED', result_json = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                        (json.dumps({'reason': 'The staged tool action is not supported'}), approval_id),
                    )
                    conn.commit()
                    return {'isError': True, 'status': 'CANCELLED', 'message': 'The staged tool action is not supported', 'policy_code': 'UNSUPPORTED_APPROVAL_ACTION'}

                changed = conn.execute(
                    "UPDATE approvals SET status = 'EXECUTING', approved_at = ? WHERE id = ? AND status = 'PENDING_APPROVAL'",
                    (self._now(), approval_id),
                ).rowcount
                if changed != 1:
                    conn.rollback()
                    return {'isError': True, 'status': 'FAILED', 'message': 'Approval is no longer pending', 'policy_code': 'APPROVAL_ALREADY_RESOLVED'}
                conn.commit()
                try:
                    execution_result = raw_tools[row['tool_name']](**action_arguments)
                    if not isinstance(execution_result, dict):
                        raise TypeError('Approved tool returned an unsupported result.')
                    if execution_result.get('isError') or execution_result.get('status') == 'error':
                        raise RuntimeError(execution_result.get('message') or execution_result.get('error') or 'Approved tool execution failed.')
                except Exception as exc:
                    logger.exception('Approved tool execution failed for approval %s', approval_id)
                    conn.execute(
                        "UPDATE approvals SET status = 'FAILED', result_json = ? WHERE id = ? AND status = 'EXECUTING'",
                        (json.dumps({'error': str(exc)}), approval_id),
                    )
                    conn.commit()
                    return {'isError': True, 'status': 'FAILED', 'message': f'Execution failed: {exc}', 'policy_code': 'EXECUTION_FAILED'}

            conn.execute(
                "UPDATE approvals SET status = 'COMPLETED', result_json = ? WHERE id = ? AND status = 'EXECUTING'",
                (json.dumps({'executed': True, 'result': execution_result}), approval_id),
            )
            if selected_approval_kind == 'persistent_grant':
                grant_id = str(uuid.uuid4())
                grant_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=int(selected_grant_duration))).isoformat()
                capabilities = action.get('permitted_capabilities') or [action.get('capability') or ('read' if row['tool_name'] != 'production_database' else 'write')]
                conn.execute(
                    """
                    INSERT INTO trust_grants (
                        id, user_id, session_id, source_mcp, destination_mcp, operation,
                        target_resource, capabilities_json, created_at, expires_at,
                        approval_id, action_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        grant_id,
                        user_id,
                        session_id,
                        action.get('source_mcp') or 'user',
                        action.get('destination_mcp') or row['tool_name'],
                        action.get('operation') or row['operation'] or 'tool_call',
                        action.get('target_resource') or row['target_resource'] or row['tool_name'],
                        json.dumps(capabilities),
                        self._now(),
                        grant_expires_at,
                        approval_id,
                        row['action_hash'],
                    ),
                )
            conn.commit()
            return {
                'isError': False,
                'status': 'COMPLETED',
                'message': 'Approved action executed',
                'policy_code': None,
                'result': execution_result,
                'approval_kind': selected_approval_kind,
            }
        finally:
            conn.close()

    @staticmethod
    def _normalize_taint_sources(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            (
                {
                    'source_tool': source['source_tool'],
                    'tool_call_id': source['tool_call_id'],
                    'affected_fields': sorted(source.get('affected_fields', [])),
                }
                for source in sources
            ),
            key=lambda source: (source['source_tool'], source['tool_call_id']),
        )

    def _current_taint_sources(self, conn: sqlite3.Connection, session_id: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT source_tool, tool_call_id, affected_fields_json
            FROM taint_sources
            WHERE session_id = ?
            ORDER BY created_at, id
            """,
            (session_id,),
        ).fetchall()
        return self._normalize_taint_sources(
            [
                {
                    'source_tool': row['source_tool'],
                    'tool_call_id': row['tool_call_id'],
                    'affected_fields': json.loads(row['affected_fields_json']),
                }
                for row in rows
            ]
        )
