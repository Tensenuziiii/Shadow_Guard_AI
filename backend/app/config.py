import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / '.env', override=False)

DB_PATH = Path(os.getenv('DB_PATH', str(BASE_DIR / 'data' / 'shadowguard.db')))
PRODUCTION_DB_PATH = Path(os.getenv('PRODUCTION_DB_PATH', str(BASE_DIR / 'data' / 'production.db')))
FRONTEND_ORIGIN = os.getenv('FRONTEND_ORIGIN', 'http://localhost:5173')
MODEL_NAME = os.getenv('MODEL_NAME', 'openai:gpt-4o-mini').strip()
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '').strip()
OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY', '').strip()
APPROVAL_OPERATOR_TOKEN = os.getenv('APPROVAL_OPERATOR_TOKEN', '').strip()
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '').strip()
GITHUB_REPOSITORY = os.getenv(
    'GITHUB_REPOSITORY',
    'Tensenuziiii/Shadow_Guard_AI',
).strip()
GITHUB_ALLOWED_REPOSITORIES = tuple(
    repository.strip().casefold()
    for repository in os.getenv(
        'GITHUB_ALLOWED_REPOSITORIES',
        GITHUB_REPOSITORY,
    ).split(',')
    if repository.strip()
)
INTEGRATION_MODE = os.getenv('SHADOWGUARD_INTEGRATION_MODE', 'live').strip().casefold()
if INTEGRATION_MODE not in {'live', 'fixture'}:
    raise ValueError('SHADOWGUARD_INTEGRATION_MODE must be "live" or "fixture".')
SESSION_TTL_SECONDS = int(os.getenv('SESSION_TTL_SECONDS', '3600'))
APPROVAL_TIMEOUT_SECONDS = int(os.getenv('APPROVAL_TIMEOUT_SECONDS', '300'))

DB_PATH.parent.mkdir(parents=True, exist_ok=True)
PRODUCTION_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_settings() -> dict[str, Any]:
    return {
        'db_path': str(DB_PATH),
        'frontend_origin': FRONTEND_ORIGIN,
        'model_name': MODEL_NAME,
        'session_ttl_seconds': SESSION_TTL_SECONDS,
        'approval_timeout_seconds': APPROVAL_TIMEOUT_SECONDS,
    }
