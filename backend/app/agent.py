from __future__ import annotations

import asyncio

from typing import Any

import httpx

from pydantic_ai import Agent, RunContext
from pydantic_ai.exceptions import ModelHTTPError, UserError
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider

from app.config import GITHUB_REPOSITORY, MODEL_NAME, OPENAI_API_KEY, OPENROUTER_API_KEY
from app.mcp_server import DEFAULT_GITHUB_PATH
from app.security.response_synthesizer import synthesize_error


class AgentConfigurationError(ValueError):
    pass


class PendingApprovalRequested(Exception):
    def __init__(self, approval_id: str, tool_call_id: str, tool_name: str | None = None):
        super().__init__(approval_id)
        self.approval_id = approval_id
        self.tool_call_id = tool_call_id
        self.tool_name = tool_name


def get_agent_error_details(error: Exception) -> tuple[int, str]:
    if isinstance(error, AgentConfigurationError):
        return 503, str(error)
    if isinstance(error, ModelHTTPError):
        if error.status_code in {401, 403}:
            if MODEL_NAME.startswith('openrouter:'):
                provider = 'OPENROUTER_API_KEY (or OPENAI_API_KEY)'
            elif MODEL_NAME.startswith('openai:'):
                provider = 'OPENAI_API_KEY'
            else:
                provider = 'the configured provider credentials'
            return (
                503,
                f'Model provider authentication failed. Check {provider} and confirm the key is authorized.',
            )
        if error.status_code == 404:
            return 503, 'The configured model is unavailable. Check MODEL_NAME and confirm the provider account has access.'
        if error.status_code == 429:
            return 429, 'The model provider rate limit or account quota was reached. Wait and retry, or check your provider quota.'
        if error.status_code >= 500:
            return 503, 'The model provider is temporarily unavailable. Check its service status and retry.'
        return 502, 'The model provider rejected the request. Check MODEL_NAME and its supported request settings.'
    if isinstance(error, httpx.RequestError):
        return 503, 'Could not reach the model provider. Check network connectivity and provider status, then retry.'
    if isinstance(error, UserError):
        return 503, 'The configured model is not supported. Check MODEL_NAME and the installed provider integration.'
    return 500, 'The chatbot encountered an internal error. Retry the request; server logs contain only a sanitized error type.'


def build_agent(interceptor: Any) -> Agent[dict[str, Any], str]:
    if not MODEL_NAME:
        raise AgentConfigurationError('MODEL_NAME is empty. Set it to a supported provider:model name.')

    if MODEL_NAME.startswith('openai:'):
        model_name = MODEL_NAME.removeprefix('openai:')
        if not model_name:
            raise AgentConfigurationError('MODEL_NAME must include an OpenAI model after "openai:".')
        if not OPENAI_API_KEY:
            raise AgentConfigurationError('OPENAI_API_KEY is missing. Set it in backend/.env before starting the backend.')
        model = OpenAIModel(model_name, provider=OpenAIProvider(api_key=OPENAI_API_KEY))
    elif MODEL_NAME.startswith('openrouter:'):
        model_name = MODEL_NAME.removeprefix('openrouter:')
        if not model_name:
            raise AgentConfigurationError(
                'MODEL_NAME must include an OpenRouter model after "openrouter:".'
            )
        api_key = OPENROUTER_API_KEY or OPENAI_API_KEY
        if not api_key:
            raise AgentConfigurationError(
                'Set OPENROUTER_API_KEY or OPENAI_API_KEY in backend/.env before starting the backend.'
            )
        model = OpenAIModel(
            model_name,
            provider=OpenAIProvider(
                base_url='https://openrouter.ai/api/v1',
                api_key=api_key,
            ),
        )
    else:
        model = MODEL_NAME

    agent = Agent(
        model=model,
        output_type=str,
        instructions=(
            'You are ShadowGuard AI. Always route all operations through the provided guarded tools. '
            'When the user asks to perform a database operation (such as deleting, updating, or inserting records), execute the guarded database tool directly so ShadowGuard can evaluate policy, simulate the blast radius, and stage human approval. '
            'Describe destructive database actions as pending until the tool result confirms execution. '
            'Never claim a rejected, blocked, or pending action succeeded. '
            'When the user asks to review, inspect or report, use read-only SELECT queries.'
        ),
    )

    async def call_guarded_tool(
        ctx: RunContext[dict[str, Any]],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        if ctx.deps.get('_approval_pending'):
            return synthesize_error(
                'APPROVAL_PENDING',
                'No further tools may run until the pending approval is decided.',
                'Wait for the human approval decision.',
            )
        if not ctx.tool_call_id:
            raise RuntimeError('Guarded tool invocation is missing its provider tool-call id.')
        tool_call_id = ctx.tool_call_id
        result = await asyncio.to_thread(
            interceptor.execute,
            tool_name,
            arguments,
            ctx.deps['session_id'],
            ctx.deps['user_id'],
            tool_call_id,
            request_id=ctx.deps.get('request_id'),
            user_objective=ctx.deps.get('user_objective', ''),
            authorized_capabilities=ctx.deps.get('authorized_capabilities', ['read']),
        )
        if result.get('status') == 'pending_approval':
            ctx.deps['_approval_pending'] = result['approval_id']
            raise PendingApprovalRequested(result['approval_id'], tool_call_id, tool_name)
        return result

    async def guarded_github_reader(
        ctx: RunContext[dict[str, Any]],
        repo: str = GITHUB_REPOSITORY,
        path: str = DEFAULT_GITHUB_PATH,
    ) -> dict[str, Any]:
        return await call_guarded_tool(
            ctx,
            'github_reader',
            {'repo': repo, 'path': path},
        )

    async def guarded_weather(ctx: RunContext[dict[str, Any]], city: str = 'Seattle') -> dict[str, Any]:
        return await call_guarded_tool(ctx, 'weather_api', {'city': city})

    async def guarded_db(ctx: RunContext[dict[str, Any]], sql: str) -> dict[str, Any]:
        return await call_guarded_tool(ctx, 'production_database', {'sql': sql})

    agent.tool(guarded_github_reader)
    agent.tool(guarded_weather)
    agent.tool(guarded_db)
    return agent
