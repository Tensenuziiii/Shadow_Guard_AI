"""
Regression tests for bugs fixed in this audit pass.

Covers:
- risk_engine.py: SELECT JOIN on allowed tables was incorrectly blocked (len(tables) <= 1)
- shadow_state.py: _samples_for_tables used PRAGMA cid (int) instead of column name
- shadow_state.py: percentage_affected calculated against after-count, not before-count
- mcp_server.py: github_reader retained UTF-8 BOM causing UNSUPPORTED_STATEMENT
- interceptor.py: WebSocket event stream redacts raw arguments and result payloads
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile

import pytest

from app.database import initialize_database
from app.security.action_classifier import classify_action, detect_sensitive_text
from app.security.audit import AuditLogger
from app.security.approvals import ApprovalManager
from app.security.interceptor import ShadowGuardInterceptor
from app.security.registry import TrustRegistry
from app.security.risk_engine import ALLOWED_TABLES, analyze_sql
from app.security.shadow_state import ShadowStateManager
from app.security.taint import TaintEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def temp_dbs(tmp_path):
    app_db = str(tmp_path / 'app.db')
    production_db = str(tmp_path / 'prod.db')
    initialize_database(app_db)
    conn = sqlite3.connect(production_db)
    conn.execute(
        'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE)'
    )
    conn.executemany(
        'INSERT INTO users (id, name, email) VALUES (?, ?, ?)',
        [
            (1, 'Alice', 'alice@example.com'),
            (2, 'Bob', 'bob@example.com'),
            (3, 'Charlie', 'charlie@example.com'),
        ],
    )
    conn.execute(
        'CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL)'
    )
    conn.executemany(
        'INSERT INTO orders (id, user_id, amount) VALUES (?, ?, ?)',
        [(1, 1, 10.0), (2, 2, 20.0)],
    )
    conn.commit()
    conn.close()
    return app_db, production_db


# ---------------------------------------------------------------------------
# Bug 1: SELECT JOIN on allowed tables was blocked
# ---------------------------------------------------------------------------

class TestSelectJoinFix:
    def test_single_allowed_table_select_is_allowed(self):
        result = analyze_sql('SELECT id, name FROM users WHERE id = 1')
        assert result['allowed'] is True
        assert result['destructive'] is False

    def test_join_on_two_allowed_tables_is_now_allowed(self):
        """Regression: previously blocked because len(tables) > 1."""
        sql = 'SELECT u.id, o.id FROM users u JOIN orders o ON u.id = o.user_id'
        result = analyze_sql(sql)
        assert result['allowed'] is True, (
            f'JOIN on two allowed tables must be allowed, got reasons={result["reasons"]}'
        )
        assert result['destructive'] is False
        assert set(result['tables']).issubset(ALLOWED_TABLES)

    def test_subquery_on_allowed_tables_is_now_allowed(self):
        """Regression: previously blocked because len(tables) > 1."""
        sql = 'SELECT id FROM users WHERE id IN (SELECT user_id FROM orders)'
        result = analyze_sql(sql)
        assert result['allowed'] is True, (
            f'Subquery on allowed tables must be allowed, got reasons={result["reasons"]}'
        )

    def test_join_with_unauthorized_table_is_blocked(self):
        """Security regression: joining an unauthorized table must still be blocked."""
        sql = 'SELECT u.id FROM users u JOIN secret_tokens s ON u.id = s.user_id'
        result = analyze_sql(sql)
        assert result['allowed'] is False
        assert 'UNAUTHORIZED_TABLE' in result['reasons']

    def test_select_on_unauthorized_table_is_blocked(self):
        sql = 'SELECT * FROM sqlite_master'
        result = analyze_sql(sql)
        assert result['allowed'] is False
        assert 'UNAUTHORIZED_TABLE' in result['reasons']

    def test_pure_expression_select_is_allowed(self):
        result = analyze_sql('SELECT 1 + 1')
        assert result['allowed'] is True
        assert result['tables'] == []


# ---------------------------------------------------------------------------
# Bug 2 & 3: _samples_for_tables column names + percentage_affected denominator
# ---------------------------------------------------------------------------

class TestShadowStateFixes:
    def test_before_after_use_column_names_not_indices(self, temp_dbs):
        """Regression: PRAGMA table_info desc[0] is cid (int), desc[1] is name."""
        _, production_db = temp_dbs
        mgr = ShadowStateManager(production_db)
        result = mgr.evaluate_statement('DELETE FROM users WHERE id = 1')
        assert result['before']['users'], 'before must be non-empty'
        first_row = result['before']['users'][0]
        assert 'id' in first_row, f'Expected column name "id", got keys {list(first_row.keys())}'
        assert 'name' in first_row, f'Expected column name "name", got keys {list(first_row.keys())}'
        # The integer-key bug would produce {0: ..., 1: ...}
        assert 0 not in first_row, 'Column index 0 must not appear as a key'

    def test_after_uses_column_names_not_indices(self, temp_dbs):
        _, production_db = temp_dbs
        mgr = ShadowStateManager(production_db)
        result = mgr.evaluate_statement('DELETE FROM users WHERE id = 1')
        if result['after']['users']:
            first_remaining = result['after']['users'][0]
            assert 'id' in first_remaining, f'After rows must use column names, got {list(first_remaining.keys())}'

    def test_percentage_affected_uses_before_count_as_denominator(self, temp_dbs):
        """Regression: previously used after-count, yielding 50% instead of 33.33%."""
        _, production_db = temp_dbs
        mgr = ShadowStateManager(production_db)
        # 3 rows exist; delete 1 → should be 33.33%, not 50%
        result = mgr.evaluate_statement('DELETE FROM users WHERE id = 1')
        assert result['affected_rows'] == 1
        assert result['total_rows'] == 3, (
            f'total_rows must reflect the before-count (3), got {result["total_rows"]}'
        )
        assert result['remaining_rows'] == 2, (
            f'remaining_rows must reflect the after-count (2), got {result["remaining_rows"]}'
        )
        assert result['percentage_affected'] == pytest.approx(33.33, abs=0.01), (
            f'percentage_affected should be 33.33% (1 of 3), got {result["percentage_affected"]}'
        )

    def test_simulation_does_not_modify_production_db(self, temp_dbs):
        _, production_db = temp_dbs
        mgr = ShadowStateManager(production_db)
        mgr.evaluate_statement('DELETE FROM users WHERE id = 1')
        with sqlite3.connect(production_db) as conn:
            count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        assert count == 3, 'Simulation must not modify the real production database'


# ---------------------------------------------------------------------------
# Bug 4: BOM in cleanup_script.sql caused UNSUPPORTED_STATEMENT
# ---------------------------------------------------------------------------

class TestGithubReaderBomFix:
    def test_github_reader_script_has_no_bom(self):
        """Regression: reading with utf-8 kept the BOM, breaking analyze_sql."""
        from app.mcp_server import github_reader
        result = github_reader()
        script = result['script']
        assert not script.startswith('\ufeff'), (
            'github_reader script must not start with a UTF-8 BOM character'
        )

    def test_github_reader_script_sql_is_parseable(self):
        """The script contains multiple statements (correctly blocked by policy)."""
        from app.mcp_server import github_reader
        import sqlparse
        result = github_reader()
        script = result['script'].strip()
        # With BOM gone the script should be parseable (even if multi-statement)
        stmts = sqlparse.parse(script)
        assert len(stmts) > 0
        # The statement type should be recognised (not UNKNOWN due to BOM)
        first_token_type = stmts[0].get_type()
        assert first_token_type is not None or stmts[0].value.strip().upper().startswith('DELETE'), (
            'First statement should be recognisable without BOM'
        )


# ---------------------------------------------------------------------------
# Bug 5: WebSocket event stream must not expose raw arguments or full results
# ---------------------------------------------------------------------------

class TestEventStreamRedaction:
    """Verify that _emit calls do not leak raw tool arguments or result payloads."""

    def _make_interceptor(self, app_db, production_db):
        events = []

        class RecordingHub:
            def publish(self, event_type, session_id, summary, details=None, action_id=None, tool_name=None, policy_code=None, **kwargs):
                events.append({'event_type': event_type, 'details': details or {}})

        taint = TaintEngine(app_db)
        audit = AuditLogger(app_db)
        approvals = ApprovalManager(app_db)
        interceptor = ShadowGuardInterceptor(
            app_db,
            TrustRegistry(app_db),
            taint,
            ShadowStateManager(production_db),
            approvals,
            audit,
            RecordingHub(),
            {'weather_api': lambda city: {'temperature': 18, 'condition': 'clear'}},
        )
        return interceptor, events

    def test_prohibited_action_event_does_not_contain_raw_arguments(self, temp_dbs):
        """Regression: security_error event used to include the full arguments dict."""
        app_db, production_db = temp_dbs
        interceptor, events = self._make_interceptor(app_db, production_db)
        # .env in SQL arg -> PROHIBITED
        interceptor.execute(
            'production_database',
            {'sql': 'SELECT * FROM users WHERE token = (SELECT secret FROM .env)'},
            'session-redact-1',
            'user-1',
        )
        security_errors = [e for e in events if e['event_type'] == 'security_error']
        assert security_errors, 'Expected at least one security_error event'
        for event in security_errors:
            assert 'arguments' not in event['details'], (
                'Raw arguments must not appear in security_error WebSocket event'
            )
            # argument_fields (just the key names) are acceptable
            assert 'argument_fields' in event['details']

    def test_tool_allowed_event_does_not_contain_full_result(self, temp_dbs):
        """Regression: tool_call_allowed event used to include the complete result dict."""
        app_db, production_db = temp_dbs
        interceptor, events = self._make_interceptor(app_db, production_db)
        interceptor.execute('weather_api', {'city': 'Seattle'}, 'session-redact-2', 'user-1')
        allowed_events = [e for e in events if e['event_type'] == 'tool_call_allowed']
        assert allowed_events, 'Expected tool_call_allowed event'
        event = allowed_events[0]
        # 'result' dict should not be present; only 'result_fields' (key names)
        assert 'result' not in event['details'], (
            'Full result payload must not appear in tool_call_allowed WebSocket event'
        )
        assert 'result_fields' in event['details']

    def test_approval_required_event_omits_sql_and_row_data(self, temp_dbs):
        """Regression: approval_required event included raw SQL and before/after rows."""
        app_db, production_db = temp_dbs
        interceptor, events = self._make_interceptor(app_db, production_db)
        # Override raw_tools to include production_database
        interceptor.raw_tools['production_database'] = lambda sql: {'rows_affected': 1}
        interceptor.execute(
            'production_database',
            {'sql': 'DELETE FROM users WHERE id = 1'},
            'session-redact-3',
            'user-1',
        )
        approval_events = [e for e in events if e['event_type'] == 'approval_required']
        assert approval_events, 'Expected approval_required event'
        event = approval_events[0]
        assert 'sql' not in event['details'], (
            'Raw SQL must not appear in approval_required WebSocket event'
        )
        blast = event['details'].get('blast_radius', {})
        assert 'before' not in blast, 'before rows must not appear in WebSocket event'
        assert 'after' not in blast, 'after rows must not appear in WebSocket event'
        assert 'snapshot_fingerprint' not in blast, 'fingerprint must not appear in WebSocket event'
        # Impact metrics are safe to include
        assert 'affected_rows' in blast or 'action_type' in blast


# ---------------------------------------------------------------------------
# Additional security regression tests
# ---------------------------------------------------------------------------

class TestSecurityRegressions:
    def test_env_reference_in_sql_is_prohibited(self):
        tool = {'trust_zone': 'HIGH', 'data_sensitivity': 'protected'}
        result = classify_action(
            'production_database',
            {'sql': 'SELECT * FROM users WHERE email = (SELECT token FROM .env)'},
            tool,
        )
        assert result['classification'] == 'PROHIBITED'
        assert 'SECRET_OR_CREDENTIAL_REFERENCE' in result['reasons']

    def test_env_reference_in_repo_arg_is_prohibited(self):
        tool = {'trust_zone': 'HIGH', 'data_sensitivity': 'internal'}
        result = classify_action('github_reader', {'repo': '../.env'}, tool)
        assert result['classification'] == 'PROHIBITED'

    def test_sensitive_text_detection(self):
        hits = detect_sensitive_text({'sql': 'SELECT * FROM users WHERE token = ?'})
        assert any('token' in p for p in hits)

    def test_multi_statement_sql_is_rejected(self):
        result = analyze_sql('DELETE FROM users WHERE id=1; DROP TABLE users')
        assert result['allowed'] is False
        assert 'MULTIPLE_STATEMENTS_NOT_ALLOWED' in result['reasons']

    def test_unscoped_delete_is_rejected(self):
        result = analyze_sql('DELETE FROM users')
        assert result['allowed'] is False
        assert 'UNSCOPED_DELETE' in result['reasons']

    def test_prohibited_pragma_is_rejected(self):
        result = analyze_sql('PRAGMA user_version')
        assert result['allowed'] is False

    def test_explain_is_unsupported(self):
        result = analyze_sql('EXPLAIN SELECT * FROM users')
        assert result['allowed'] is False
        assert 'UNSUPPORTED_STATEMENT' in result['reasons']

    def test_empty_sql_is_rejected(self):
        result = analyze_sql('')
        assert result['allowed'] is False
        assert 'EMPTY_SQL' in result['reasons']

    def test_select_on_allowed_tables_is_not_destructive(self):
        result = analyze_sql('SELECT id, name FROM users WHERE id = 1')
        assert result['allowed'] is True
        assert result['destructive'] is False
