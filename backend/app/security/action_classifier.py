from __future__ import annotations

import re
from typing import Any

from app.security.risk_engine import analyze_sql

SECRET_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r'\bapi[_-]?key\b',
        r'\bsecret\b',
        r'\bpassword\b',
        r'\btoken\b',
        r'\.env\b',
        r'id_rsa',
        r'credential',
    ]
]
SUSPICIOUS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r'ignore (all )?(previous|prior) instructions',
        r'exfiltrate',
        r'send .*secret',
        r'https?://[^\s]+',
        r'curl\s+https?://',
    ]
]


def detect_sensitive_text(value: Any) -> list[str]:
    text = value if isinstance(value, str) else repr(value)
    return [pattern.pattern for pattern in SECRET_PATTERNS if pattern.search(text)]


def detect_suspicious_content(value: Any) -> list[str]:
    text = value if isinstance(value, str) else repr(value)
    return [pattern.pattern for pattern in SUSPICIOUS_PATTERNS if pattern.search(text)]


def classify_action(
    tool_name: str,
    arguments: dict[str, Any],
    tool: dict[str, Any],
    destination_mcp: str | None = None,
) -> dict[str, Any]:
    destination = destination_mcp or tool_name
    operation = 'tool_call'
    target_resource = tool_name
    capability = 'execute'
    sensitivity = tool.get('data_sensitivity') or 'public'
    reasons: list[str] = []
    affected_records = 0
    external_side_effect = bool(destination_mcp and destination_mcp != tool_name)
    rollback_supported = False

    sensitive_hits = detect_sensitive_text(arguments)
    if sensitive_hits:
        return {
            'classification': 'PROHIBITED',
            'operation': operation,
            'target_resource': target_resource,
            'capability': capability,
            'destination_mcp': destination,
            'data_sensitivity': 'secret',
            'affected_records': affected_records,
            'external_side_effect': external_side_effect,
            'rollback_supported': False,
            'reasons': ['SECRET_OR_CREDENTIAL_REFERENCE'],
            'suspicious_content': [],
        }

    suspicious = detect_suspicious_content(arguments)
    if suspicious:
        reasons.append('SUSPICIOUS_CONTENT')

    if tool_name == 'production_database':
        sql = str(arguments.get('sql') or '')
        risk = analyze_sql(sql)
        operation = risk['statement_type']
        target_resource = ','.join(risk['tables']) if risk['tables'] else 'database'
        capability = 'read' if risk['statement_type'] == 'SELECT' else 'write'
        if not risk['allowed']:
            return {
                'classification': 'PROHIBITED',
                'operation': operation,
                'target_resource': target_resource,
                'capability': capability,
                'destination_mcp': destination,
                'data_sensitivity': sensitivity,
                'affected_records': affected_records,
                'external_side_effect': external_side_effect,
                'rollback_supported': False,
                'reasons': risk['reasons'],
                'suspicious_content': suspicious,
                'sql_risk': risk,
            }
        if risk['statement_type'] == 'SELECT':
            classification = 'IRREVERSIBLE_OR_UNCERTAIN' if suspicious else 'READ_ONLY'
        elif risk['statement_type'] in {'INSERT', 'UPDATE', 'DELETE'}:
            classification = 'REVERSIBLE_WRITE'
            rollback_supported = True
        else:
            classification = 'IRREVERSIBLE_OR_UNCERTAIN'
        if risk['destructive']:
            reasons.append('DATABASE_MUTATION')
        return {
            'classification': classification,
            'operation': operation,
            'target_resource': target_resource,
            'capability': capability,
            'destination_mcp': destination,
            'data_sensitivity': sensitivity,
            'affected_records': affected_records,
            'external_side_effect': external_side_effect,
            'rollback_supported': rollback_supported,
            'reasons': reasons,
            'suspicious_content': suspicious,
            'sql_risk': risk,
        }

    if tool_name in {'github_reader', 'weather_api'}:
        classification = 'IRREVERSIBLE_OR_UNCERTAIN' if suspicious else 'READ_ONLY'
        capability = 'read'
        target_resource = str(arguments.get('repo') or arguments.get('city') or tool_name)
    else:
        classification = 'IRREVERSIBLE_OR_UNCERTAIN'
        reasons.append('UNKNOWN_ACTION_REVERSIBILITY')

    return {
        'classification': classification,
        'operation': operation,
        'target_resource': target_resource,
        'capability': capability,
        'destination_mcp': destination,
        'data_sensitivity': sensitivity,
        'affected_records': affected_records,
        'external_side_effect': external_side_effect,
        'rollback_supported': rollback_supported,
        'reasons': reasons,
        'suspicious_content': suspicious,
    }
