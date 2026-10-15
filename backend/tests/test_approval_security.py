import json
import sqlite3
import threading
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic_ai import Agent
from pydantic_ai.exceptions import ModelHTTPError

from app.database import initialize_database
import app.api.approvals as approvals_api
import app.api.chat as chat_api
from app.agent import PendingApprovalRequested
from app.api.approvals import router as approvals_router
from app.api.chat import router as chat_router
from app.api.events import EventHub
from app.security.approvals import ApprovalManager
from app.security.audit import AuditLogger
from app.security.interceptor import ShadowGuardInterceptor
from app.security.registry import TrustRegistry
from app.security.risk_engine import analyze_sql
from app.security.shadow_state import ShadowStateManager
from app.security.taint import TaintEngine
import app.security.operator_auth as operator_auth


OPERATOR_TOKEN = 'test-approval-operator-token-with-at-least-32-bytes'
OPERATOR_HEADERS = {'Authorization': f'Bearer {OPERATOR_TOKEN}'}


@pytest.fixture
def database_paths(tmp_path):
    app_db = tmp_path / 'shadowguard.db'
    production_db = tmp_path / 'production.db'
    initialize_database(str(app_db))
    with sqlite3.connect(production_db) as conn:
        conn.execute(
            'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE)'
        )
        conn.executemany(
            'INSERT INTO users (id, name, email) VALUES (?, ?, ?)',
            [(1, 'Alice', 'alice@example.com'), (2, 'Bob', 'bob@example.com')],
        )
    return str(app_db), str(production_db)


def stage_delete(app_db, production_db, session_id='session-1', user_id='user-1'):
    TaintEngine(app_db).get_or_create_session(session_id, user_id)
    shadow = ShadowStateManager(production_db)
    sql = 'DELETE FROM users WHERE id = 1'
    simulation = shadow.evaluate_statement(sql)
    manager = ApprovalManager(app_db)
    action = manager.create_pending(
        session_id,
        user_id,
        'production_database',
        sql,
        simulation,
    )
    return manager, action['approval_id']


def count_users(production_db):
    with sqlite3.connect(production_db) as conn:
        return conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]


def test_approval_requires_matching_user_and_unchanged_full_snapshot(database_paths):
    app_db, production_db = database_paths
    manager, approval_id = stage_delete(app_db, production_db)

    wrong_user = manager.decide(approval_id, 'approve', 'session-1', 'other-user', production_db)
    assert wrong_user['policy_code'] == 'SESSION_MISMATCH'
    assert count_users(production_db) == 2

    with sqlite3.connect(production_db) as conn:
        conn.execute("UPDATE users SET name = 'Alicia' WHERE id = 1")

    stale = manager.decide(approval_id, 'approve', 'session-1', 'user-1', production_db)
    assert stale['status'] == 'CANCELLED'
    assert stale['policy_code'] == 'SNAPSHOT_CHANGED'
    assert count_users(production_db) == 2


def test_approval_expires_and_cannot_be_replayed(database_paths):
    app_db, production_db = database_paths
    manager, approval_id = stage_delete(app_db, production_db)
    with sqlite3.connect(app_db) as conn:
        conn.execute(
            'UPDATE approvals SET expires_at = ? WHERE id = ?',
            ('2000-01-01T00:00:00+00:00', approval_id),
        )

    expired = manager.decide(approval_id, 'approve', 'session-1', 'user-1', production_db)
    replay = manager.decide(approval_id, 'approve', 'session-1', 'user-1', production_db)

    assert expired['status'] == 'EXPIRED'
    assert expired['policy_code'] == 'APPROVAL_EXPIRED'
    assert replay['policy_code'] == 'APPROVAL_ALREADY_RESOLVED'
    assert count_users(production_db) == 2


def test_approval_rechecks_tool_policy_and_staged_action_integrity(database_paths):
    app_db, production_db = database_paths
    manager, approval_id = stage_delete(app_db, production_db)
    with sqlite3.connect(app_db) as conn:
        conn.execute("UPDATE tool_registry SET enabled = 0 WHERE name = 'production_database'")

    disabled = manager.decide(approval_id, 'approve', 'session-1', 'user-1', production_db)
    assert disabled['status'] == 'CANCELLED'
    assert disabled['policy_code'] == 'POLICY_REVALIDATION_FAILED'
    assert count_users(production_db) == 2

    with sqlite3.connect(app_db) as conn:
        conn.execute("UPDATE tool_registry SET enabled = 1 WHERE name = 'production_database'")
    manager, approval_id = stage_delete(app_db, production_db, 'tainted-session')
    TaintEngine(app_db).mark_tainted('tainted-session', 'weather_api', 'weather-call', ['temperature'])
    tainted = manager.decide(approval_id, 'approve', 'tainted-session', 'user-1', production_db)
    assert tainted['status'] == 'CANCELLED'
    assert tainted['policy_code'] == 'POLICY_REVALIDATION_FAILED'

    manager, approval_id = stage_delete(app_db, production_db, 'integrity-session')
    with sqlite3.connect(app_db) as conn:
        conn.execute(
            'UPDATE approvals SET sql_text = ? WHERE id = ?',
            ('DELETE FROM users WHERE id = 2', approval_id),
        )

    tampered = manager.decide(approval_id, 'approve', 'integrity-session', 'user-1', production_db)
    assert tampered['status'] == 'CANCELLED'
    assert tampered['policy_code'] == 'ACTION_INTEGRITY_FAILED'
    assert count_users(production_db) == 2


def test_tainted_database_write_waits_for_approval_and_executes_exact_staged_sql(database_paths):
    app_db, production_db = database_paths
    session_id = 'tainted-write-session'
    taint = TaintEngine(app_db)
    taint.get_or_create_session(session_id, 'user-1')
    taint.mark_tainted(session_id, 'weather_api', 'weather-call', ['condition'])
    manager = ApprovalManager(app_db)
    sql = 'DELETE FROM users WHERE id = 1'
    action = manager.create_pending(
        session_id,
        'user-1',
        'production_database',
        sql,
        ShadowStateManager(production_db).evaluate_statement(sql),
        arguments={'sql': sql},
        taint_override_required=True,
        taint_sources=taint.get_sources(session_id),
    )

    assert count_users(production_db) == 2
    staged = json.loads(manager.get_pending()[0]['staged_json'])['_action']
    assert staged['taint_override_required'] is True
    assert staged['arguments'] == {'sql': sql}

    rejected = manager.decide(
        action['approval_id'], 'reject', session_id, 'user-1', production_db,
    )
    assert rejected['status'] == 'REJECTED'
    assert count_users(production_db) == 2

    approved_action = manager.create_pending(
        session_id,
        'user-1',
        'production_database',
        sql,
        ShadowStateManager(production_db).evaluate_statement(sql),
        arguments={'sql': sql},
        taint_override_required=True,
        taint_sources=taint.get_sources(session_id),
    )
    approved = manager.decide(
        approved_action['approval_id'], 'approve', session_id, 'user-1', production_db,
    )
    assert approved['status'] == 'COMPLETED'
    assert count_users(production_db) == 1


def test_tainted_database_read_is_not_run_until_approved_and_new_taint_invalidates_approval(database_paths):
    app_db, production_db = database_paths
    session_id = 'tainted-read-session'
    taint = TaintEngine(app_db)
    taint.get_or_create_session(session_id, 'user-1')
    taint.mark_tainted(session_id, 'weather_api', 'weather-call', ['condition'])
    manager = ApprovalManager(app_db)
    sql = 'SELECT id, name FROM users ORDER BY id'
    action = manager.create_pending(
        session_id,
        'user-1',
        'production_database',
        sql,
        ShadowStateManager(production_db).evaluate_statement(sql),
        arguments={'sql': sql},
        taint_override_required=True,
        taint_sources=taint.get_sources(session_id),
    )
    taint.mark_tainted(session_id, 'github_reader', 'github-call', ['script'])

    stale = manager.decide(
        action['approval_id'], 'approve', session_id, 'user-1', production_db,
    )
    assert stale['status'] == 'CANCELLED'
    assert stale['policy_code'] == 'POLICY_REVALIDATION_FAILED'

    clean_snapshot_action = manager.create_pending(
        session_id,
        'user-1',
        'production_database',
        sql,
        ShadowStateManager(production_db).evaluate_statement(sql),
        arguments={'sql': sql},
        taint_override_required=True,
        taint_sources=taint.get_sources(session_id),
    )
    approved = manager.decide(
        clean_snapshot_action['approval_id'], 'approve', session_id, 'user-1', production_db,
    )
    assert approved['status'] == 'COMPLETED'
    assert approved['result']['rows'] == [
        {'id': 1, 'name': 'Alice'},
        {'id': 2, 'name': 'Bob'},
    ]
    assert count_users(production_db) == 2


def test_rejection_does_not_execute_and_approval_executes_once(database_paths):
    app_db, production_db = database_paths
    manager, approval_id = stage_delete(app_db, production_db, 'reject-session')

    rejected = manager.decide(approval_id, 'reject', 'reject-session', 'user-1', production_db)
    assert rejected['status'] == 'REJECTED'
    assert rejected['isError'] is True
    assert count_users(production_db) == 2

    manager, approval_id = stage_delete(app_db, production_db, 'approve-session')
    approved = manager.decide(approval_id, 'approve', 'approve-session', 'user-1', production_db)
    assert approved['status'] == 'COMPLETED'
    assert approved['isError'] is False
    assert count_users(production_db) == 1


def test_agent_resume_context_is_not_exposed_in_pending_approval_payload(database_paths):
    app_db, production_db = database_paths
    manager, approval_id = stage_delete(app_db, production_db)
    context = {
        'message_history': '[{"private":"continuation"}]',
        'tool_call_id': 'guarded-call',
        'session_id': 'session-1',
        'user_id': 'user-1',
    }
    manager.attach_agent_context(approval_id, context)

    pending = manager.get_pending()
    assert len(pending) == 1
    assert '_agent_context' not in json.loads(pending[0]['staged_json'])
    assert manager.get_agent_context(approval_id) == context


def test_chat_pending_action_resumes_after_real_approval(database_paths, monkeypatch):
    monkeypatch.setattr(operator_auth, 'APPROVAL_OPERATOR_TOKEN', OPERATOR_TOKEN)
    app_db, production_db = database_paths
    taint = TaintEngine(app_db)
    audit = AuditLogger(app_db)
    manager = ApprovalManager(app_db)
    interceptor = ShadowGuardInterceptor(
        app_db,
        TrustRegistry(app_db),
        taint,
        ShadowStateManager(production_db),
        manager,
        audit,
        EventHub(),
        {'production_database': lambda sql: {'rows_affected': 1}},
    )

    def pending_agent(gateway):
        agent = Agent('test', output_type=str)

        async def guarded_db(ctx, sql: str) -> dict:
            result = gateway.execute(
                'production_database',
                {'sql': 'DELETE FROM users WHERE id = 1'},
                ctx.deps['session_id'],
                ctx.deps['user_id'],
                ctx.tool_call_id,
            )
            if result.get('status') == 'pending_approval':
                raise PendingApprovalRequested(result['approval_id'], ctx.tool_call_id)
            return result

        agent.tool(guarded_db)
        return agent

    monkeypatch.setattr(chat_api, 'build_agent', pending_agent)
    monkeypatch.setattr(approvals_api, 'build_agent', lambda gateway: Agent('test', output_type=str))

    app = FastAPI()
    app.include_router(chat_router)
    app.include_router(approvals_router)
    app.state.audit_logger = audit
    app.state.app_state = {
        'db_path': app_db,
        'production_db_path': production_db,
        'event_hub': EventHub(),
        'taint_engine': taint,
        'approval_manager': manager,
        'interceptor': interceptor,
    }

    with TestClient(app, headers=OPERATOR_HEADERS) as client:
        pending = client.post(
            '/api/chat',
            json={'message': 'Delete user 1', 'user_id': 'user-1'},
        )
        assert pending.status_code == 200
        pending_payload = pending.json()
        assert pending_payload['status'] == 'pending_approval'
        assert 'It has not run' in pending_payload['response']
        assert count_users(production_db) == 2

        approval_id = pending_payload['approval_id']
        decision = client.post(
            f'/api/approvals/{approval_id}/decision',
            json={
                'decision': 'approve',
                'session_id': pending_payload['session_id'],
                'user_id': 'user-1',
            },
        )

    assert decision.status_code == 200
    decision_payload = decision.json()
    assert decision_payload['status'] == 'EXECUTED'
    assert decision_payload['isError'] is False
    assert 'executed' in decision_payload['response'].lower()
    assert any(event['status'] == 'executed' for event in decision_payload['provenance'])
    assert count_users(production_db) == 1


def test_chat_reports_the_exact_action_and_reason_when_policy_blocks_it(database_paths, monkeypatch):
    app_db, production_db = database_paths
    taint = TaintEngine(app_db)
    audit = AuditLogger(app_db)
    manager = ApprovalManager(app_db)
    interceptor = ShadowGuardInterceptor(
        app_db,
        TrustRegistry(app_db),
        taint,
        ShadowStateManager(production_db),
        manager,
        audit,
        EventHub(),
        {'production_database': lambda sql: {'status': 'ok'}},
    )

    class BlockedAgent:
        async def run(self, message, deps):
            interceptor.execute(
                'production_database',
                {'sql': 'PRAGMA user_version'},
                deps['session_id'],
                deps['user_id'],
                'blocked-sql-call',
            )
            return SimpleNamespace(output='I checked the request.')

    monkeypatch.setattr(chat_api, 'build_agent', lambda gateway: BlockedAgent())
    app = FastAPI()
    app.include_router(chat_router)
    app.state.audit_logger = audit
    app.state.app_state = {
        'audit_logger': audit,
        'taint_engine': taint,
        'approval_manager': manager,
        'interceptor': interceptor,
    }

    with TestClient(app) as client:
        response = client.post(
            '/api/chat',
            json={'message': 'Run this database action', 'user_id': 'user-1'},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload['status'] == 'blocked'
    assert 'production_database was blocked' in payload['response']
    assert 'ACTION_PROHIBITED' in payload['response']
    assert 'PROHIBITED_OPERATION:PRAGMA' in payload['response']
    assert count_users(production_db) == 2


def test_approved_action_is_not_repeated_when_assistant_continuation_fails(
    database_paths, monkeypatch
):
    monkeypatch.setattr(operator_auth, 'APPROVAL_OPERATOR_TOKEN', OPERATOR_TOKEN)
    app_db, production_db = database_paths
    taint = TaintEngine(app_db)
    audit = AuditLogger(app_db)
    manager = ApprovalManager(app_db)
    interceptor = ShadowGuardInterceptor(
        app_db,
        TrustRegistry(app_db),
        taint,
        ShadowStateManager(production_db),
        manager,
        audit,
        EventHub(),
        {'production_database': lambda sql: {'rows_affected': 1}},
    )

    def pending_agent(gateway):
        agent = Agent('test', output_type=str)

        async def guarded_db(ctx, sql: str) -> dict:
            result = gateway.execute(
                'production_database',
                {'sql': 'DELETE FROM users WHERE id = 1'},
                ctx.deps['session_id'],
                ctx.deps['user_id'],
                ctx.tool_call_id,
            )
            if result.get('status') == 'pending_approval':
                raise PendingApprovalRequested(result['approval_id'], ctx.tool_call_id)
            return result

        agent.tool(guarded_db)
        return agent

    class FailedContinuationAgent:
        async def run(self, message, message_history, deps):
            raise ModelHTTPError(503, 'test-model')

    monkeypatch.setattr(chat_api, 'build_agent', pending_agent)
    monkeypatch.setattr(
        approvals_api,
        'build_agent',
        lambda gateway: FailedContinuationAgent(),
    )

    app = FastAPI()
    app.include_router(chat_router)
    app.include_router(approvals_router)
    app.state.audit_logger = audit
    app.state.app_state = {
        'db_path': app_db,
        'production_db_path': production_db,
        'event_hub': EventHub(),
        'taint_engine': taint,
        'approval_manager': manager,
        'interceptor': interceptor,
    }

    with TestClient(app, headers=OPERATOR_HEADERS) as client:
        pending_response = client.post(
            '/api/chat',
            json={'message': 'Delete user 1', 'user_id': 'user-1'},
        )
        pending = pending_response.json()
        decision = client.post(
            f'/api/approvals/{pending["approval_id"]}/decision',
            json={
                'decision': 'approve',
                'session_id': pending['session_id'],
                'user_id': 'user-1',
            },
        )

    assert pending_response.status_code == 200
    assert pending['status'] == 'pending_approval'
    assert decision.status_code == 200
    result = decision.json()
    assert result['status'] == 'EXECUTED'
    assert 'executed' in result['response'].lower()
    assert 'response generation failed' in result['response'].lower()
    assert result['continuation_error']
    assert count_users(production_db) == 1


def test_concurrent_approval_decisions_have_a_single_winner(database_paths):
    app_db, production_db = database_paths
    manager, approval_id = stage_delete(app_db, production_db, 'concurrent-session')
    barrier = threading.Barrier(2)
    results = []

    def decide():
        barrier.wait()
        results.append(
            manager.decide(
                approval_id,
                'approve',
                'concurrent-session',
                'user-1',
                production_db,
            )
        )

    threads = [threading.Thread(target=decide) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(not result['isError'] for result in results) == 1
    assert count_users(production_db) == 1


def test_taint_sources_preserve_call_and_field_provenance_and_hide_resume_data(database_paths):
    app_db, _ = database_paths
    taint = TaintEngine(app_db)
    session_id = taint.get_or_create_session('taint-session', 'user-1')
    taint.mark_tainted(session_id, 'weather_api', 'call-1', ['temperature', 'condition'])
    taint.mark_tainted(session_id, 'weather_api', 'call-2', ['wind'])

    sources = taint.get_sources(session_id)
    assert [(source['tool_call_id'], source['affected_fields']) for source in sources] == [
        ('call-1', ['condition', 'temperature']),
        ('call-2', ['wind']),
    ]
    with pytest.raises(PermissionError):
        taint.get_or_create_session('taint-session', 'other-user')


def test_interceptor_records_inherited_source_and_tool_call_provenance(database_paths):
    app_db, production_db = database_paths
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
        None,
        {
            'weather_api': lambda city: {'condition': 'clear', 'temperature': 18},
            'github_reader': lambda repo: {'repo': repo},
        },
    )
    session_id = 'provenance-session'
    interceptor.execute('weather_api', {'city': 'Seattle'}, session_id, 'user-1', 'weather-call')
    pending = interceptor.execute('github_reader', {'repo': 'demo'}, session_id, 'user-1', 'github-call')

    assert pending['status'] == 'pending_approval'
    provenance = audit.get_provenance(session_id)
    assert provenance[0]['tool_call_id'] == 'weather-call'
    assert provenance[0]['result_fields'] == ['condition', 'temperature']
    assert provenance[1]['tool_call_id'] == 'github-call'
    assert provenance[1]['status'] == 'pending_approval'
    assert provenance[1]['policy_code'] == 'TAINT_OVERRIDE_REQUIRED'
    assert provenance[1]['inherited_sources'][0]['source_tool'] == 'weather_api'
    assert provenance[1]['inherited_sources'][0]['affected_fields'] == ['condition', 'temperature']
    executed = approvals.decide(
        pending['approval_id'],
        'approve',
        session_id,
        'user-1',
        production_db,
        raw_tools={'github_reader': lambda repo: {'repo': repo}},
    )
    assert executed['status'] == 'COMPLETED'
    assert executed['result'] == {'repo': 'demo'}


def test_sql_policy_stages_inserts_and_rejects_unknown_statement_types():
    assert analyze_sql("INSERT INTO users (id, name, email) VALUES (3, 'Casey', 'casey@example.com')")['destructive']
    unknown = analyze_sql('EXPLAIN SELECT * FROM users')
    assert unknown['allowed'] is False
    assert 'UNSUPPORTED_STATEMENT' in unknown['reasons']
