from __future__ import annotations

from typing import Any


def synthesize_error(policy_code: str, message: str, guidance: str | None = None, **extra: Any) -> dict[str, Any]:
    return {
        'isError': True,
        'status': 'blocked',
        'policy_code': policy_code,
        'message': message,
        'guidance': guidance or 'No destructive action was executed.',
        **extra,
    }


def synthesize_pending(approval_id: str, action_id: str, summary: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        'isError': False,
        'status': 'pending_approval',
        'approval_id': approval_id,
        'action_id': action_id,
        'message': summary,
        'data': details,
    }
