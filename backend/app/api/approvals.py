from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from pydantic_ai.messages import ModelMessagesTypeAdapter, ModelRequest, ToolReturnPart

from app.agent import PendingApprovalRequested, build_agent, get_agent_error_details
from app.schemas import ApprovalDecisionRequest

router = APIRouter(prefix='/api')
logger = logging.getLogger(__name__)


@router.get('/approvals/pending')
def list_pending(request: Request):
    app_state = request.app.state.app_state
    rows = app_state['approval_manager'].get_pending()
    return {'approvals': rows}


@router.post('/approvals/{approval_id}/decision')
async def decide_approval(approval_id: str, payload: ApprovalDecisionRequest, request: Request):
    app_state = request.app.state.app_state
    manager = app_state['approval_manager']
    context = manager.get_agent_context(approval_id)
    result = manager.decide(
        approval_id,
        payload.decision,
        payload.session_id,
        payload.user_id,
        app_state.get('production_db_path', app_state['db_path']),
        raw_tools=app_state.get('raw_tools'),
        approval_kind=payload.approval_kind,
        grant_duration_seconds=payload.grant_duration_seconds,
    )
    decision_applied = (
        result.get('status') == 'COMPLETED' and not result.get('isError')
    ) or (
        result.get('status') == 'REJECTED' and result.get('policy_code') == 'APPROVAL_REJECTED'
    )
    if decision_applied:
        prior = next(
            (
                event
                for event in reversed(request.app.state.audit_logger.get_provenance(payload.session_id))
                if event.get('action_id') == approval_id
            ),
            {},
        )
        request.app.state.audit_logger.log_event(
            'tool_call_provenance',
            payload.session_id,
            f'Approval action {result["status"].lower()}',
            {
                'tool_name': (context or {}).get('tool_name') or 'production_database',
                'tool_call_id': (context or {}).get('tool_call_id') or prior.get('tool_call_id'),
                'status': (
                    'executed'
                    if result['status'] == 'COMPLETED'
                    else result['status'].lower()
                ),
                'argument_fields': prior.get('argument_fields', []),
                'result_fields': [],
                'inherited_sources': prior.get('inherited_sources', app_state['taint_engine'].get_sources(payload.session_id)),
                'action_id': approval_id,
            },
            approval_id,
            (context or {}).get('tool_name') or 'production_database',
            result.get('policy_code'),
        )

    if decision_applied and result.get('status') == 'REJECTED':
        app_state['event_hub'].publish(
            'approval_rejected', payload.session_id, 'Approval rejected by human operator.',
            {'approval_id': approval_id}, approval_id,
            (context or {}).get('tool_name') or 'production_database', 'APPROVAL_REJECTED',
        )
    elif decision_applied and result.get('status') == 'COMPLETED':
        app_state['event_hub'].publish(
            'approval_completed', payload.session_id, 'Approved action completed.',
            {'approval_id': approval_id}, approval_id,
            (context or {}).get('tool_name') or 'production_database', None,
        )
    elif result.get('isError'):
        app_state['event_hub'].publish(
            'approval_failed', payload.session_id, 'Approval decision failed.',
            {'approval_id': approval_id, 'error': result.get('message')}, approval_id,
            (context or {}).get('tool_name') or 'production_database', result.get('policy_code'),
        )

    if decision_applied and context:
        tool_result = {
            'isError': result['status'] == 'REJECTED',
            'status': result['status'].lower(),
            'message': result['message'],
            'data': result.get('result', {}),
        }
        try:
            messages = ModelMessagesTypeAdapter.validate_json(context['message_history'])
            guarded_tool_names = {
                'production_database': 'guarded_db',
                'github_reader': 'guarded_github_reader',
                'weather_api': 'guarded_weather',
            }
            tool_name = guarded_tool_names.get(context.get('tool_name'), 'guarded_db')
            messages.append(
                ModelRequest(
                    parts=[
                        ToolReturnPart(
                            tool_name=tool_name,
                            tool_call_id=context['tool_call_id'],
                            content=tool_result,
                        )
                    ]
                )
            )
            resumed = await build_agent(app_state['interceptor']).run(
                None,
                message_history=messages,
                deps={
                    'session_id': context['session_id'],
                    'user_id': context['user_id'],
                    'request_id': context.get('request_id'),
                    'user_objective': context.get('user_objective', ''),
                    'authorized_capabilities': context.get('authorized_capabilities', ['read', 'write', 'delete']),
                    '_continuation_for_approval': approval_id,
                },
            )
            result['response'] = str(resumed.output)
        except PendingApprovalRequested as pending:
            app_state['approval_manager'].attach_agent_context(
                pending.approval_id,
                {
                    'message_history': ModelMessagesTypeAdapter.dump_json(messages).decode('utf-8'),
                    'tool_call_id': pending.tool_call_id,
                    'tool_name': pending.tool_name,
                    'session_id': context['session_id'],
                    'user_id': context['user_id'],
                    'request_id': context.get('request_id'),
                    'user_objective': context.get('user_objective', ''),
                    'authorized_capabilities': context.get('authorized_capabilities', ['read', 'write', 'delete']),
                },
            )
            result['response'] = (
                f'The previous action was executed. The assistant proposed a subsequent protected action '
                f'({pending.tool_name}) which is now awaiting approval.'
            )
            result['subsequent_approval_id'] = pending.approval_id
        except Exception as exc:
            _, message = get_agent_error_details(exc)
            logger.error('Agent continuation failed (error_type=%s)', type(exc).__name__)
            result['continuation_error'] = message
            result['response'] = (
                f'The approved action was executed, but response generation failed. {message}'
                if result['status'] == 'COMPLETED'
                else f'The action was rejected and was not executed. Response generation failed. {message}'
            )
    elif decision_applied and result.get('status') == 'COMPLETED':
        result['response'] = 'The approved action was completed.'
    elif decision_applied and result.get('status') == 'REJECTED':
        result['response'] = 'The action was rejected and was not executed.'

    if result.get('status') == 'COMPLETED':
        result['status'] = 'EXECUTED'

    if decision_applied:
        result['provenance'] = request.app.state.audit_logger.get_provenance(payload.session_id)
    return result
