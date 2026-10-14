import json
import sqlite3
from typing import Any

from app.database import get_connection


TRUST_WEIGHTS = {
    'identity': 25,
    'permissions': 25,
    'behavior': 20,
    'data_handling': 20,
    'relationships': 10,
}
HIGH_TRUST_THRESHOLD = 80


class TrustRegistry:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path

    def list_tools(self) -> list[dict[str, Any]]:
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute('SELECT * FROM tool_registry ORDER BY name').fetchall()
            return [self._hydrate_tool(dict(row)) for row in rows]
        finally:
            conn.close()

    def get_tool(self, name: str) -> dict[str, Any] | None:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute('SELECT * FROM tool_registry WHERE name = ?', (name,)).fetchone()
            return self._hydrate_tool(dict(row)) if row else None
        finally:
            conn.close()

    def _hydrate_tool(self, tool: dict[str, Any]) -> dict[str, Any]:
        for key, fallback in {
            'capabilities_json': [],
            'permitted_resources_json': [],
            'observed_behavior_json': {},
            'outbound_permissions_json': [],
            'approved_relationships_json': [],
        }.items():
            public_key = key.removesuffix('_json')
            try:
                tool[public_key] = json.loads(tool.get(key) or json.dumps(fallback))
            except json.JSONDecodeError:
                tool[public_key] = fallback
        if tool.get('trust_score') is None:
            tool['trust_score'] = 0
        if not tool.get('trust_classification'):
            tool['trust_classification'] = 'LOW'
        return tool

    def evaluate_trust(self, tool: dict[str, Any]) -> dict[str, Any]:
        if not tool.get('identity_valid', 1):
            return {'score': 0, 'classification': 'DENY', 'reason': 'Invalid MCP identity', 'hard_deny': True}
        if tool.get('permissions_revoked'):
            return {'score': 0, 'classification': 'DENY', 'reason': 'Permissions were revoked', 'hard_deny': True}
        if tool.get('prohibited_behavior'):
            return {'score': 0, 'classification': 'DENY', 'reason': 'Confirmed prohibited behavior', 'hard_deny': True}

        capabilities = tool.get('capabilities') or []
        resources = tool.get('permitted_resources') or []
        violations = int(tool.get('permission_violations') or 0)
        outbound = tool.get('outbound_permissions') or []
        relationships = tool.get('approved_relationships') or []
        sensitivity = (tool.get('data_sensitivity') or 'public').lower()

        score = 0
        reasons = []
        if tool.get('authenticated') and tool.get('identity_valid', 1):
            score += TRUST_WEIGHTS['identity']
        else:
            reasons.append('identity/authentication evidence missing')

        if capabilities and resources and violations == 0:
            score += TRUST_WEIGHTS['permissions']
        else:
            reasons.append('least-privilege evidence incomplete or violations observed')

        behavior_score = max(0, TRUST_WEIGHTS['behavior'] - min(violations * 5, TRUST_WEIGHTS['behavior']))
        score += behavior_score
        if behavior_score < TRUST_WEIGHTS['behavior']:
            reasons.append('observed behavior reduced trust')

        if sensitivity in {'public', 'internal'} or (sensitivity == 'protected' and not outbound):
            score += TRUST_WEIGHTS['data_handling']
        else:
            reasons.append('sensitive data has outbound exposure')

        if relationships or not outbound:
            score += TRUST_WEIGHTS['relationships']
        else:
            reasons.append('outbound interaction patterns are not authorized')

        classification = 'HIGH' if score >= HIGH_TRUST_THRESHOLD else 'LOW'
        return {
            'score': min(score, 100),
            'classification': classification,
            'reason': '; '.join(reasons) if reasons else 'All configured trust evidence satisfied',
            'hard_deny': False,
        }

    def refresh_trust(self, name: str) -> dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute('SELECT * FROM tool_registry WHERE name = ?', (name,)).fetchone()
            if row is None:
                raise ValueError('Unknown tool')
            tool = self._hydrate_tool(dict(row))
            evaluation = self.evaluate_trust(tool)
            trust_zone = 'HIGH' if evaluation['classification'] == 'HIGH' else 'LOW'
            conn.execute(
                """
                UPDATE tool_registry
                SET trust_score = ?, trust_classification = ?, trust_reason = ?,
                    trust_zone = ?, trust_evaluated_at = datetime('now')
                WHERE name = ?
                """,
                (evaluation['score'], evaluation['classification'], evaluation['reason'], trust_zone, name),
            )
            conn.commit()
            updated = conn.execute('SELECT * FROM tool_registry WHERE name = ?', (name,)).fetchone()
            return self._hydrate_tool(dict(updated))
        finally:
            conn.close()

    def set_trust_zone(self, name: str, trust_zone: str) -> dict[str, Any]:
        allowed = {'HIGH', 'LOW', 'MEDIUM'}
        if trust_zone.upper() not in allowed:
            raise ValueError('Unsupported trust zone')
        conn = get_connection(self.db_path)
        try:
            conn.execute(
                'INSERT INTO tool_registry (name, trust_zone, enabled, description) VALUES (?, ?, 1, ?) ON CONFLICT(name) DO UPDATE SET trust_zone = excluded.trust_zone',
                (name, trust_zone.upper(), f'{name} trust assignment'),
            )
            conn.execute(
                'INSERT INTO integration_settings (name, trust_zone, updated_at) VALUES (?, ?, datetime("now")) ON CONFLICT(name) DO UPDATE SET trust_zone = excluded.trust_zone, updated_at = datetime("now")',
                (name, trust_zone.upper()),
            )
            conn.commit()
            return self.refresh_trust(name)
        finally:
            conn.close()

    def has_active_grant(
        self,
        user_id: str,
        session_id: str,
        source_mcp: str,
        destination_mcp: str,
        operation: str,
        target_resource: str,
        capability: str,
    ) -> bool:
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                """
                SELECT capabilities_json FROM trust_grants
                WHERE user_id = ? AND session_id = ? AND source_mcp = ? AND destination_mcp = ?
                  AND operation = ? AND target_resource = ? AND revoked_at IS NULL
                  AND datetime(expires_at) > datetime('now')
                """,
                (user_id, session_id, source_mcp, destination_mcp, operation, target_resource),
            ).fetchall()
            for row in rows:
                capabilities = json.loads(row['capabilities_json'] or '[]')
                if capability in capabilities:
                    return True
            return False
        finally:
            conn.close()
