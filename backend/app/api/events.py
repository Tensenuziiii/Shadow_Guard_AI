from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from starlette.websockets import WebSocketDisconnect


class EventHub:
    def __init__(self):
        self.connections: dict[Any, asyncio.AbstractEventLoop] = {}
        self.events: list[dict[str, Any]] = []

    def add_connection(self, ws):
        self.connections[ws] = asyncio.get_running_loop()

    def remove_connection(self, ws):
        self.connections.pop(ws, None)

    async def _send(self, ws, payload: str):
        try:
            await ws.send_text(payload)
        except (WebSocketDisconnect, RuntimeError, OSError):
            self.remove_connection(ws)

    def publish(
        self,
        event_type: str,
        session_id: str,
        summary: str,
        details: dict[str, Any] | None = None,
        action_id: str | None = None,
        tool_name: str | None = None,
        policy_code: str | None = None,
        request_id: str | None = None,
        severity: str = 'info',
    ) -> dict[str, Any]:
        event = {
            'event_type': event_type,
            'request_id': request_id,
            'session_id': session_id,
            'event_id': str(uuid.uuid4()),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action_id': action_id,
            'tool_name': tool_name,
            'policy_code': policy_code,
            'severity': severity,
            'summary': summary,
            'details': details or {},
        }
        self.events.append(event)
        payload = json.dumps(event)
        for ws, loop in list(self.connections.items()):
            if loop.is_closed():
                self.remove_connection(ws)
                continue
            loop.call_soon_threadsafe(
                lambda ws=ws, loop=loop: loop.create_task(self._send(ws, payload))
            )
        return event

    def get_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.events[-limit:]
