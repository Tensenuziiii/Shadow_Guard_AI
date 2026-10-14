from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from app.config import BASE_DIR, PRODUCTION_DB_PATH

mcp = FastMCP('shadowguard')


@mcp.tool()
def github_reader(repo: str = 'demo') -> dict[str, Any]:
    script_path = BASE_DIR / 'data' / 'cleanup_script.sql'
    # Use utf-8-sig to strip an optional BOM so the SQL is parseable downstream.
    with open(script_path, 'r', encoding='utf-8-sig') as handle:
        script = handle.read()
    return {
        'tool': 'github_reader',
        'repo': repo,
        'source': 'simulated-github-fixture',
        'provenance': {'source': 'local-fixture', 'trust_zone': 'HIGH'},
        'script': script,
    }


@mcp.tool()
def weather_api(city: str = 'Seattle') -> dict[str, Any]:
    return {
        'tool': 'weather_api',
        'city': city,
        'temperature_c': 18,
        'condition': 'light rain',
        'forecast': 'Cloudy with passing showers',
        'provenance': {'source': 'mock-weather-service', 'trust_zone': 'LOW'},
    }


@mcp.tool()
def production_database(sql: str, _guarded: bool = False) -> dict[str, Any]:
    import sqlite3

    if not _guarded:
        return {
            'tool': 'production_database',
            'status': 'error',
            'error': 'Direct access is disabled; route protected database actions through ShadowGuardInterceptor.',
            'isError': True,
            'policy_code': 'DIRECT_TOOL_ACCESS_BLOCKED',
        }
    conn = sqlite3.connect(str(PRODUCTION_DB_PATH))
    try:
        conn.execute('BEGIN')
        cursor = conn.execute(sql)
        rowcount = cursor.rowcount
        conn.commit()
        return {'tool': 'production_database', 'status': 'ok', 'sql': sql, 'rows_affected': rowcount}
    except Exception as exc:
        conn.rollback()
        return {'tool': 'production_database', 'status': 'error', 'error': str(exc), 'isError': True}
    finally:
        conn.close()
