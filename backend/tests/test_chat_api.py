from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic_ai import Agent
from pydantic_ai.exceptions import ModelHTTPError

import app.agent as agent_module
import app.api.chat as chat_api
from app.api.chat import router as chat_router


class FakeTaintEngine:
    def get_or_create_session(self, session_id, user_id):
        return session_id or 'test-session'

    def current_state(self, session_id):
        return 'CLEAN'


class FakeAuditLogger:
    def __init__(self):
        self.entries = []

    def get_provenance(self, session_id):
        return self.entries

    def log_event(self, *args, **kwargs):
        """Accept any signature; no-op for unit tests that don't need persistence."""


class FakeEventHub:
    def publish(self, *args, **kwargs):
        return {}


class StaticAgent:
    def __init__(self, output=None, error=None):
        self.output = output
        self.error = error

    async def run(self, message, deps):
        if self.error:
            raise self.error
        return SimpleNamespace(output=self.output)


@pytest.fixture
def chat_client():
    app = FastAPI()
    app.include_router(chat_router)
    app.state.audit_logger = FakeAuditLogger()
    app.state.app_state = {
        'taint_engine': FakeTaintEngine(),
        'interceptor': object(),
        'event_hub': FakeEventHub(),
        'approval_manager': SimpleNamespace(attach_agent_context=lambda *a, **k: None),
    }
    with TestClient(app) as client:
        yield client


def test_chat_returns_mocked_provider_response_and_frontend_schema(chat_client, monkeypatch):
    monkeypatch.setattr(chat_api, 'build_agent', lambda interceptor: Agent('test'))

    response = chat_client.post(
        '/api/chat',
        json={'message': 'Hello', 'user_id': 'test-user'},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload['response']
    assert payload['status'] == 'completed'
    assert payload['approval_id'] is None
    assert payload['session_id'] == 'test-session'
    assert payload['state'] == 'CLEAN'
    assert payload['provenance'] == []


def test_chat_reports_missing_key_as_configuration_error(chat_client, monkeypatch):
    monkeypatch.setattr(agent_module, 'MODEL_NAME', 'openai:gpt-4o-mini')
    monkeypatch.setattr(agent_module, 'OPENAI_API_KEY', '')
    monkeypatch.setattr(chat_api, 'build_agent', lambda interceptor: agent_module.build_agent(interceptor))

    response = chat_client.post('/api/chat', json={'message': 'Hello'})

    assert response.status_code == 503
    assert 'OPENAI_API_KEY' in response.json()['detail']
    assert 'key value' not in response.json()['detail']


@pytest.mark.parametrize(
    ('error', 'status_code', 'message'),
    [
        (ModelHTTPError(401, 'model', body={'detail': 'sk-test-secret'}), 503, 'authentication'),
        (ModelHTTPError(404, 'model'), 503, 'unavailable'),
        (ModelHTTPError(429, 'model'), 429, 'rate limit'),
        (httpx.ConnectError('sk-test-secret'), 503, 'network'),
    ],
)
def test_chat_handles_provider_errors_without_leaking_details(
    chat_client, monkeypatch, error, status_code, message
):
    monkeypatch.setattr(chat_api, 'build_agent', lambda interceptor: StaticAgent(error=error))

    response = chat_client.post('/api/chat', json={'message': 'Hello'})

    assert response.status_code == status_code
    assert message in response.json()['detail'].lower()
    assert 'sk-test-secret' not in response.text


def test_chat_reports_a_security_block_even_if_response_generation_fails(
    chat_client, monkeypatch
):
    class BlockedThenFailedAgent:
        async def run(self, message, deps):
            chat_client.app.state.audit_logger.entries.append(
                {
                    'tool_call_id': 'blocked-call',
                    'tool_name': 'production_database',
                    'status': 'blocked',
                    'message': 'Policy denied this database operation.',
                    'policy_code': 'SQL_POLICY_BLOCK',
                }
            )
            raise ModelHTTPError(503, 'test-model')

    monkeypatch.setattr(
        chat_api,
        'build_agent',
        lambda interceptor: BlockedThenFailedAgent(),
    )

    response = chat_client.post('/api/chat', json={'message': 'Run a query'})

    assert response.status_code == 503
    payload = response.json()
    assert payload['status'] == 'blocked'
    assert 'was blocked' in payload['response']
    assert 'those actions were not run' in payload['detail']
    assert payload['provenance'][0]['status'] == 'blocked'


def test_chat_logs_unexpected_errors_without_exposing_exception_text(
    chat_client, monkeypatch, caplog
):
    monkeypatch.setattr(
        chat_api,
        'build_agent',
        lambda interceptor: StaticAgent(error=RuntimeError('sk-private-secret')),
    )

    response = chat_client.post('/api/chat', json={'message': 'Hello'})

    assert response.status_code == 500
    assert 'sk-private-secret' not in response.text
    assert 'sk-private-secret' not in caplog.text
    assert 'RuntimeError' in caplog.text


def test_chat_rejects_invalid_request(chat_client):
    response = chat_client.post('/api/chat', json={'message': ''})

    assert response.status_code == 422
