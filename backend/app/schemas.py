from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1)
    session_id: str | None = None
    user_id: str = 'demo-user'
    # Explicit authorized capabilities constrain what the agent may do in
    # this turn.  Omitting them is treated as read-only inspection.
    authorized_capabilities: list[str] = Field(
        default_factory=lambda: ['read', 'write', 'delete'],
        description=(
            'Capabilities the caller explicitly authorises for this turn. '
            'Supported values: "read", "write", "delete". '
            'Defaults to ["read", "write", "delete"]. '
            'Callers can pass ["read"] to enforce read-only inspection.'
        ),
    )


class IntegrationSettingsRequest(BaseModel):
    name: str
    trust_zone: str


class ApprovalDecisionRequest(BaseModel):
    decision: str
    session_id: str
    user_id: str = 'demo-user'
    approval_kind: str = 'one_time'
    grant_duration_seconds: int | None = None


class SecurityEvent(BaseModel):
    event_type: str
    session_id: str
    event_id: str
    timestamp: str
    action_id: str | None = None
    tool_name: str | None = None
    policy_code: str | None = None
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    isError: bool = False
    status: str | None = None
    policy_code: str | None = None
    message: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None
    action_id: str | None = None
