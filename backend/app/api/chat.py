from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic_ai import capture_run_messages
from pydantic_ai.messages import ModelMessagesTypeAdapter

from app.agent import PendingApprovalRequested, build_agent, get_agent_error_details
from app.schemas import ChatRequest

router = APIRouter(prefix='/api')
logger = logging.getLogger(__name__)


def _error_response(
    request: Request,
    app_state: dict,
    session_id: str,
    prior_tool_call_ids: set[str],
    status_code: int,
    message: str,
    request_id: str | None = None,
) -> JSONResponse:
    provenance = request.app.state.audit_logger.get_provenance(session_id) if session_id else []
    new_provenance = [
        entry for entry in provenance
        if entry.get('tool_call_id') and entry['tool_call_id'] not in prior_tool_call_ids
    ]
    blocked_actions = [entry for entry in new_provenance if entry.get('status') == 'blocked']
    response = message
    status = 'failed'
    if blocked_actions:
        explanations = [
            f"- {entry.get('tool_name', 'A tool action')} was blocked: "
            f"{entry.get('message', 'The gateway policy did not allow this action.')} "
            f"{entry.get('guidance', '')} "
            f"(Policy: {entry.get('policy_code', 'POLICY_BLOCK')})."
            for entry in blocked_actions
        ]
        response = (
            f'{message}\n\nShadowGuard blocked {len(blocked_actions)} action(s); '
            f'those actions were not run:\n' + '\n'.join(explanations)
        )
        status = 'blocked'

    return JSONResponse(
        status_code=status_code,
        content={
            'detail': response,
            'response': response,
            'status': status,
            'approval_id': None,
            'request_id': request_id,
            'session_id': session_id or None,
            'state': app_state['taint_engine'].current_state(session_id) if session_id else None,
            'provenance': provenance,
        },
    )


@router.post('/chat')
async def chat(request: Request, payload: ChatRequest):
    app_state = request.app.state.app_state
    request_id = str(uuid.uuid4())
    session_id = payload.session_id or ''
    prior_tool_call_ids: set[str] = set()

    # Derive the authorized capabilities: default to read-only
    authorized_capabilities = [c.lower() for c in payload.authorized_capabilities] if payload.authorized_capabilities else ['read']
    user_objective = payload.message

    try:
        session_id = app_state['taint_engine'].get_or_create_session(payload.session_id, payload.user_id)
        prior_tool_call_ids = {
            entry.get('tool_call_id')
            for entry in request.app.state.audit_logger.get_provenance(session_id)
            if entry.get('tool_call_id')
        }

        # ---- REQUEST_RECEIVED --------------------------------------------
        request.app.state.audit_logger.log_event(
            'REQUEST_RECEIVED', session_id,
            f'User request received: {payload.message[:120]}',
            {
                'message_snippet': payload.message[:200],
                'authorized_capabilities': authorized_capabilities,
                'user_id': payload.user_id,
            },
            None, None, None,
            request_id=request_id, severity='info',
        )
        if event_hub := app_state.get('event_hub'):
            event_hub.publish(
                'REQUEST_RECEIVED', session_id,
                f'New request: {payload.message[:80]}',
                {
                    'authorized_capabilities': authorized_capabilities,
                    'user_id': payload.user_id,
                },
                None, None, None,
                request_id=request_id, severity='info',
            )

        agent = build_agent(app_state['interceptor'])
        with capture_run_messages() as history:
            try:
                result = await agent.run(
                    payload.message,
                    deps={
                        'session_id': session_id,
                        'user_id': payload.user_id,
                        'request_id': request_id,
                        'user_objective': user_objective,
                        'authorized_capabilities': authorized_capabilities,
                    },
                )
                response = str(result.output)
                status = 'completed'
                approval_id = None

                request.app.state.audit_logger.log_event(
                    'REQUEST_COMPLETED', session_id,
                    'Request completed successfully',
                    {'response_snippet': response[:120]},
                    None, None, None,
                    request_id=request_id, severity='info',
                )
                if event_hub := app_state.get('event_hub'):
                    event_hub.publish(
                        'REQUEST_COMPLETED', session_id,
                        'Request completed',
                        {}, None, None, None,
                        request_id=request_id, severity='info',
                    )
            except PendingApprovalRequested as pending:
                app_state['approval_manager'].attach_agent_context(
                    pending.approval_id,
                    {
                        'message_history': ModelMessagesTypeAdapter.dump_json(history).decode('utf-8'),
                        'tool_call_id': pending.tool_call_id,
                        'tool_name': pending.tool_name,
                        'session_id': session_id,
                        'user_id': payload.user_id,
                        'request_id': request_id,
                        'user_objective': user_objective,
                        'authorized_capabilities': authorized_capabilities,
                    },
                )
                response = 'This protected action is pending your approval. It has not run.'
                status = 'pending_approval'
                approval_id = pending.approval_id

                request.app.state.audit_logger.log_event(
                    'APPROVAL_STAGED', session_id,
                    f'Request is pending approval {pending.approval_id}',
                    {'approval_id': pending.approval_id, 'tool_name': pending.tool_name},
                    pending.approval_id, pending.tool_name, None,
                    request_id=request_id, severity='warning',
                )
    except PermissionError as exc:
        return _error_response(
            request, app_state, session_id, prior_tool_call_ids, 403, str(exc), request_id
        )
    except Exception as exc:
        status_code, message = get_agent_error_details(exc)
        logger.error('Agent execution failed (error_type=%s)', type(exc).__name__)
        request.app.state.audit_logger.log_event(
            'REQUEST_FAILED', session_id,
            f'Request failed: {type(exc).__name__}',
            {}, None, None, None,
            request_id=request_id, severity='error',
        )
        return _error_response(
            request, app_state, session_id, prior_tool_call_ids, status_code, message, request_id
        )

    provenance = request.app.state.audit_logger.get_provenance(session_id)
    new_provenance = [
        entry for entry in provenance
        if entry.get('tool_call_id') and entry['tool_call_id'] not in prior_tool_call_ids
    ]
    blocked_actions = [entry for entry in new_provenance if entry.get('status') == 'blocked']
    if blocked_actions:
        explanations = [
            f"- {entry.get('tool_name', 'A tool action')} was blocked: "
            f"{entry.get('message', 'The gateway policy did not allow this action.')} "
            f"{entry.get('guidance', '')} "
            f"(Policy: {entry.get('policy_code', 'POLICY_BLOCK')})."
            for entry in blocked_actions
        ]
        response = (
            f'{response}\n\nShadowGuard blocked {len(blocked_actions)} action(s); '
            f'those actions were not run:\n' + '\n'.join(explanations)
        )
        if status != 'pending_approval':
            status = 'blocked'
    return {
        'response': response,
        'status': status,
        'approval_id': approval_id,
        'request_id': request_id,
        'session_id': session_id,
        'state': app_state['taint_engine'].current_state(session_id),
        'provenance': provenance,
    }
