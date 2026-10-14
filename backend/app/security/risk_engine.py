import re
from typing import Any

import sqlparse
from sqlparse import tokens

ALLOWED_TABLES = {'users', 'orders', 'audit_events', 'sessions', 'approvals'}
PROHIBITED_OPERATIONS = {'ATTACH', 'DETACH', 'VACUUM', 'PRAGMA', 'REINDEX'}


def _extract_tables(sql: str) -> list[str]:
    tables: set[str] = set()
    patterns = [
        r'\bFROM\s+([A-Za-z_][\w]*)',
        r'\bUPDATE\s+([A-Za-z_][\w]*)',
        r'\bINTO\s+([A-Za-z_][\w]*)',
        r'\bJOIN\s+([A-Za-z_][\w]*)',
        r'\bDELETE\s+FROM\s+([A-Za-z_][\w]*)',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, sql, re.IGNORECASE):
            table = match.group(1).lower()
            if table:
                tables.add(table)
    return sorted(tables)


def _detect_statement_type(sql: str) -> str:
    normalized = sql.strip().upper()
    for keyword in ['DROP', 'ALTER', 'UPDATE', 'DELETE', 'INSERT', 'CREATE', 'SELECT']:
        if normalized.startswith(keyword):
            return keyword
    return 'UNKNOWN'


def analyze_sql(sql: str) -> dict[str, Any]:
    if not sql or not sql.strip():
        return {
            'allowed': False,
            'destructive': False,
            'statement_type': 'UNKNOWN',
            'tables': [],
            'reasons': ['EMPTY_SQL'],
            'severity': 'none',
        }

    statements = sqlparse.parse(sql)
    if len(statements) != 1:
        return {
            'allowed': False,
            'destructive': False,
            'statement_type': 'UNKNOWN',
            'tables': [],
            'reasons': ['MULTIPLE_STATEMENTS_NOT_ALLOWED'],
            'severity': 'critical',
        }

    statement = statements[0]
    upper_sql = str(statement).upper()
    stmt_type = _detect_statement_type(str(statement))

    for operation in PROHIBITED_OPERATIONS:
        if operation in upper_sql:
            return {
                'allowed': False,
                'destructive': True,
                'statement_type': stmt_type,
                'tables': [],
                'reasons': [f'PROHIBITED_OPERATION:{operation}'],
                'severity': 'critical',
            }

    tables = _extract_tables(str(statement))
    reasons: list[str] = []

    if tables and any(table not in ALLOWED_TABLES for table in tables):
        reasons.append('UNAUTHORIZED_TABLE')

    if 'DELETE' in upper_sql and 'WHERE' not in upper_sql:
        reasons.append('UNSCOPED_DELETE')

    if 'DROP' in upper_sql or 'ALTER' in upper_sql or 'CREATE' in upper_sql:
        destructive = True
    elif stmt_type in {'DELETE', 'UPDATE', 'INSERT'}:
        destructive = True
    else:
        destructive = False

    supported_statement = stmt_type in {'SELECT', 'INSERT', 'UPDATE', 'DELETE'}
    if stmt_type == 'SELECT':
        # Allow any SELECT that only references authorised tables (including JOINs and
        # sub-queries).  An empty tables list means a pure expression query (e.g.
        # SELECT 1) which is safe.
        allowed = supported_statement and not reasons and set(tables).issubset(ALLOWED_TABLES)
    else:
        allowed = supported_statement and not reasons and (not tables or set(tables).issubset(ALLOWED_TABLES))
    if not supported_statement:
        reasons.append('UNSUPPORTED_STATEMENT')
        allowed = False

    return {
        'allowed': allowed,
        'destructive': destructive,
        'statement_type': stmt_type,
        'tables': tables,
        'reasons': reasons,
        'severity': 'critical' if destructive else 'low',
    }
