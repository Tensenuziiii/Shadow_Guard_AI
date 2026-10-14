from __future__ import annotations

import pytest
from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.messages import ModelMessagesTypeAdapter, ModelRequest, ToolReturnPart

import app.agent as agent_module
from app.agent import build_agent


class RecordingInterceptor:
    def __init__(self):
        self.calls = []

    def execute(self, tool_name, arguments, session_id, user_id, tool_call_id=None, **kwargs):
        self.calls.append((tool_name, arguments, session_id, user_id, tool_call_id))
        return {'tool': tool_name}


def test_build_agent_uses_configured_openai_model_and_key(monkeypatch):
    monkeypatch.setattr(agent_module, 'MODEL_NAME', 'openai:gpt-4o-mini')
    monkeypatch.setattr(agent_module, 'OPENAI_API_KEY', 'test-key')
    provider_options = []
    openai_provider = agent_module.OpenAIProvider

    def record_provider(**kwargs):
        provider_options.append(kwargs.get('api_key'))
        return openai_provider(**kwargs)

    monkeypatch.setattr(agent_module, 'OpenAIProvider', record_provider)

    agent = build_agent(RecordingInterceptor())

    assert agent.model.model_name == 'gpt-4o-mini'
    assert provider_options == ['test-key']


def test_build_agent_routes_openrouter_model_with_configured_key(monkeypatch):
    monkeypatch.setattr(agent_module, 'MODEL_NAME', 'openrouter:openai/gpt-4o-mini')
    monkeypatch.setattr(agent_module, 'OPENROUTER_API_KEY', '')
    monkeypatch.setattr(agent_module, 'OPENAI_API_KEY', 'test-openrouter-key')
    provider_options = []
    openai_provider = agent_module.OpenAIProvider

    def record_provider(**kwargs):
        provider_options.append(kwargs)
        return openai_provider(**kwargs)

    monkeypatch.setattr(agent_module, 'OpenAIProvider', record_provider)

    agent = build_agent(RecordingInterceptor())

    assert agent.model.model_name == 'openai/gpt-4o-mini'
    assert provider_options == [
        {
            'base_url': 'https://openrouter.ai/api/v1',
            'api_key': 'test-openrouter-key',
        }
    ]


def test_build_agent_reports_missing_openai_key_without_exposing_it(monkeypatch):
    monkeypatch.setattr(agent_module, 'MODEL_NAME', 'openai:gpt-4o-mini')
    monkeypatch.setattr(agent_module, 'OPENAI_API_KEY', '')

    with pytest.raises(agent_module.AgentConfigurationError) as raised:
        build_agent(RecordingInterceptor())

    assert 'OPENAI_API_KEY' in str(raised.value)
    assert 'test-key' not in str(raised.value)


def test_openai_auth_error_names_setting_not_credential(monkeypatch):
    monkeypatch.setattr(agent_module, 'MODEL_NAME', 'openai:gpt-4o-mini')
    monkeypatch.setattr(agent_module, 'OPENAI_API_KEY', 'test-secret-key')

    status, message = agent_module.get_agent_error_details(
        ModelHTTPError(401, 'gpt-4o-mini', body={'message': 'test-secret-key'})
    )

    assert status == 503
    assert 'OPENAI_API_KEY' in message
    assert 'test-secret-key' not in message


@pytest.mark.parametrize(
    ('status_code', 'expected_status', 'expected_text'),
    [
        (401, 503, 'authentication failed'),
        (404, 503, 'model is unavailable'),
        (429, 429, 'rate limit'),
        (503, 503, 'temporarily unavailable'),
    ],
)
def test_provider_http_errors_are_safe_and_actionable(
    status_code, expected_status, expected_text, monkeypatch
):
    monkeypatch.setattr(agent_module, 'MODEL_NAME', 'openai:gpt-4o-mini')
    error = ModelHTTPError(status_code, 'gpt-4o-mini', body={'message': 'test-key'})

    status, message = agent_module.get_agent_error_details(error)

    assert status == expected_status
    assert expected_text in message.lower()
    assert 'test-key' not in message


@pytest.mark.asyncio
async def test_guarded_tools_receive_chat_session_context(monkeypatch):
    monkeypatch.setattr(agent_module, 'MODEL_NAME', 'test')
    interceptor = RecordingInterceptor()
    agent = build_agent(interceptor)

    await agent.run('Use the available tools.', deps={'session_id': 'chat-session', 'user_id': 'chat-user'})

    assert {call[0] for call in interceptor.calls} == {
        'github_reader',
        'weather_api',
        'production_database',
    }
    assert all(call[2:4] == ('chat-session', 'chat-user') for call in interceptor.calls)
    assert all(call[4] for call in interceptor.calls)


@pytest.mark.asyncio
async def test_pending_approval_aborts_agent_run_without_returning_success(monkeypatch):
    monkeypatch.setattr(agent_module, 'MODEL_NAME', 'test')

    class PendingInterceptor(RecordingInterceptor):
        def execute(self, tool_name, arguments, session_id, user_id, tool_call_id=None, **kwargs):
            self.calls.append((tool_name, arguments, session_id, user_id, tool_call_id))
            if tool_name == 'production_database':
                return {'status': 'pending_approval', 'approval_id': 'approval-1'}
            return {'tool': tool_name}

    interceptor = PendingInterceptor()
    agent = build_agent(interceptor)

    with capture_run_messages() as history:
        with pytest.raises(agent_module.PendingApprovalRequested) as raised:
            await agent.run(
                'Use the available tools.',
                deps={'session_id': 'chat-session', 'user_id': 'chat-user'},
            )

    assert raised.value.approval_id == 'approval-1'
    assert raised.value.tool_call_id
    assert any(call[0] == 'production_database' for call in interceptor.calls)

    restored = ModelMessagesTypeAdapter.validate_json(ModelMessagesTypeAdapter.dump_json(history))
    tool_call = next(
        part
        for message in restored
        for part in getattr(message, 'parts', [])
        if getattr(part, 'tool_call_id', None) == raised.value.tool_call_id
    )
    restored.append(
        ModelRequest(
            parts=[
                ToolReturnPart(
                    tool_name=tool_call.tool_name,
                    tool_call_id=tool_call.tool_call_id,
                    content='{"status":"executed","isError":false}',
                )
            ]
        )
    )
    resumed = await Agent('test', output_type=str).run(None, message_history=restored, deps={})
    assert 'executed' in resumed.output
