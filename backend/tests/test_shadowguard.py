import sqlite3

import app.database as database_module
import app.main as main_module
import app.security.operator_auth as operator_auth
import pytest
from fastapi.testclient import TestClient

app = main_module.app
OPERATOR_TOKEN = 'test-approval-operator-token-with-at-least-32-bytes'
OPERATOR_HEADERS = {'Authorization': f'Bearer {OPERATOR_TOKEN}'}


@pytest.fixture
def isolated_databases(tmp_path, monkeypatch):
    app_db = tmp_path / 'shadowguard.db'
    production_db = tmp_path / 'production.db'
    monkeypatch.setattr(main_module, 'DB_PATH', app_db)
    monkeypatch.setattr(main_module, 'PRODUCTION_DB_PATH', production_db)
    monkeypatch.setattr(database_module, 'DB_PATH', app_db)
    monkeypatch.setattr(database_module, 'PRODUCTION_DB_PATH', production_db)
    return str(production_db)


def reset_production_db(test_db):
    conn = sqlite3.connect(test_db)
    conn.execute(
        'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE)'
    )
    conn.execute('DELETE FROM users')
    conn.executemany('INSERT INTO users (id, name, email) VALUES (?, ?, ?)', [
        (1, 'Alice', 'alice@example.com'),
        (2, 'Bob', 'bob@example.com'),
        (3, 'Charlie', 'charlie@example.com'),
    ])
    conn.commit()
    conn.close()




def test_session_starts_clean_and_low_trust_taints_session(isolated_databases):
    reset_production_db(isolated_databases)
    with TestClient(app) as client:
        session_id = 'session-clean-1'
        result = app.state.interceptor.execute('weather_api', {'city': 'Seattle'}, session_id, 'demo-user')
        assert result.get('tool') == 'weather_api'
        assert app.state.taint_engine.current_state(session_id) == 'TAINTED'


def test_high_trust_github_server_content_is_still_tainted(isolated_databases):
    reset_production_db(isolated_databases)
    with TestClient(app):
        session_id = 'session-github-taint-1'
        result = app.state.interceptor.execute(
            'github_reader',
            {'repo': 'demo'},
            session_id,
            'demo-user',
            user_objective='Read repository demo',
            authorized_capabilities=['read'],
        )

        assert result.get('source') == 'local-fixture'
        assert app.state.taint_engine.current_state(session_id) == 'TAINTED'


def test_tainted_session_blocks_high_trust_tool(isolated_databases):
    reset_production_db(isolated_databases)
    with TestClient(app) as client:
        session_id = 'session-block-1'
        app.state.interceptor.execute('weather_api', {'city': 'Seattle'}, session_id, 'demo-user')
        blocked = app.state.interceptor.execute('production_database', {'sql': 'SELECT * FROM users'}, session_id, 'demo-user')
        assert blocked['isError'] is True
        assert blocked['policy_code'] == 'TAINTED_HIGH_TRUST_BLOCK'


def test_destructive_sql_returns_pending_approval_and_reject_keeps_db_unchanged(
    isolated_databases, monkeypatch
):
    monkeypatch.setattr(operator_auth, 'APPROVAL_OPERATOR_TOKEN', OPERATOR_TOKEN)
    reset_production_db(isolated_databases)
    with TestClient(app) as client:
        session_id = 'session-approval-1'
        pending = app.state.interceptor.execute(
            'production_database', {'sql': 'DELETE FROM users WHERE id = 1'},
            session_id, 'demo-user',
            authorized_capabilities=['delete'],
        )
        assert pending['isError'] is False
        assert pending['status'] == 'pending_approval'
        approval_id = pending['approval_id']

        conn = sqlite3.connect(isolated_databases)
        rowcount_before = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        conn.close()
        assert rowcount_before == 3

        unauthorized = client.post(
            f'/api/approvals/{approval_id}/decision',
            json={'decision': 'reject', 'session_id': session_id, 'user_id': 'demo-user'},
        )
        assert unauthorized.status_code == 401
        response = client.post(
            f'/api/approvals/{approval_id}/decision',
            json={'decision': 'reject', 'session_id': session_id, 'user_id': 'demo-user'},
            headers=OPERATOR_HEADERS,
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload['status'] == 'REJECTED'

        conn = sqlite3.connect(isolated_databases)
        rowcount_after = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        conn.close()
        assert rowcount_after == 3


def test_approved_sql_executes_transactionally_once(isolated_databases, monkeypatch):
    monkeypatch.setattr(operator_auth, 'APPROVAL_OPERATOR_TOKEN', OPERATOR_TOKEN)
    reset_production_db(isolated_databases)
    with TestClient(app) as client:
        session_id = 'session-approve-1'
        pending = app.state.interceptor.execute(
            'production_database', {'sql': 'DELETE FROM users WHERE id = 2'},
            session_id, 'demo-user',
            authorized_capabilities=['delete'],
        )
        approval_id = pending['approval_id']

        response = client.post(
            f'/api/approvals/{approval_id}/decision',
            json={'decision': 'approve', 'session_id': session_id, 'user_id': 'demo-user'},
            headers=OPERATOR_HEADERS,
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload['status'] == 'EXECUTED'

        conn = sqlite3.connect(isolated_databases)
        remaining = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        assert remaining == 2
        conn.close()


def test_app_startup_preserves_existing_production_database_rows(isolated_databases):
    reset_production_db(isolated_databases)
    with sqlite3.connect(isolated_databases) as conn:
        conn.execute(
            'INSERT INTO users (id, name, email) VALUES (?, ?, ?)',
            (4, 'Existing', 'existing@example.com'),
        )

    with TestClient(app):
        with sqlite3.connect(isolated_databases) as conn:
            count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]

    assert count == 4


def test_health_endpoint(isolated_databases):
    with TestClient(app) as client:
        response = client.get('/api/health')

    assert response.status_code == 200
    assert response.json() == {'status': 'ok', 'service': 'shadowguard-ai'}


def test_websocket_stream_receives_security_events(isolated_databases):
    with TestClient(app) as client:
        with client.websocket_connect('/ws') as websocket:
            event = app.state.event_hub.publish(
                'test_event',
                'session-websocket-1',
                'WebSocket delivery check',
            )
            received = websocket.receive_json()

    assert received['event_id'] == event['event_id']
    assert received['event_type'] == 'test_event'
