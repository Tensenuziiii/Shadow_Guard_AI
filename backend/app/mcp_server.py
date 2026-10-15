from __future__ import annotations

import base64
import binascii
import json
import math
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from fastmcp import FastMCP

from app.config import (
    BASE_DIR,
    GITHUB_ALLOWED_REPOSITORIES,
    GITHUB_REPOSITORY,
    GITHUB_TOKEN,
    INTEGRATION_MODE,
    PRODUCTION_DB_PATH,
)

mcp = FastMCP('shadowguard')
GITHUB_FILE_LIMIT_BYTES = 1_000_000
GEOCODE_CACHE_TTL_SECONDS = 24 * 60 * 60
GEOCODE_CACHE_MAX_ENTRIES = 128
DEFAULT_GITHUB_PATH = 'backend/data/cleanup_script.sql'
_REPOSITORY_PATTERN = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')


class RemoteIntegrations:
    def __init__(
        self,
        client: httpx.Client | None = None,
        github_token: str = GITHUB_TOKEN,
        allowed_repositories: tuple[str, ...] = GITHUB_ALLOWED_REPOSITORIES,
        mode: str = INTEGRATION_MODE,
    ):
        if mode not in {'live', 'fixture'}:
            raise ValueError('Integration mode must be "live" or "fixture".')
        self._client = client
        self._owns_client = client is None
        self._mode = mode
        self._client_lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._github_token = github_token
        self._allowed_repositories = {
            repo.strip().casefold()
            for repo in allowed_repositories
            if repo.strip()
        }
        self._geocode_cache: OrderedDict[
            str, tuple[float, float, float, str]
        ] = OrderedDict()
        self._metrics: dict[str, Any] = {
            'github': {'requests': 0, 'failures': 0, 'total_ms': 0.0},
            'weather': {'requests': 0, 'failures': 0, 'total_ms': 0.0},
            'geocode_cache': {'hits': 0, 'misses': 0, 'expirations': 0, 'evictions': 0},
        }

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    self._client = httpx.Client(
                        timeout=httpx.Timeout(8.0, connect=2.0),
                        limits=httpx.Limits(
                            max_connections=20,
                            max_keepalive_connections=10,
                        ),
                        headers={'User-Agent': 'ShadowGuard-AI/1.0'},
                    )
        return self._client

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def metrics_snapshot(self) -> dict[str, Any]:
        with self._metrics_lock:
            return json.loads(json.dumps(self._metrics))

    def _record_request(self, provider: str, started: float, failed: bool) -> None:
        elapsed_ms = (time.perf_counter() - started) * 1000
        with self._metrics_lock:
            metric = self._metrics[provider]
            metric['requests'] += 1
            metric['total_ms'] = round(metric['total_ms'] + elapsed_ms, 3)
            if failed:
                metric['failures'] += 1

    def _get_json(
        self,
        provider: str,
        url: str,
        params: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        started = time.perf_counter()
        try:
            response = self._get_client().get(url, params=params, headers=headers)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError('The integration returned an invalid response.')
        except httpx.TimeoutException:
            self._record_request(provider, started, failed=True)
            return None, f'{provider.title()} request timed out.'
        except httpx.HTTPStatusError as exc:
            self._record_request(provider, started, failed=True)
            status_code = exc.response.status_code
            return None, f'{provider.title()} request failed with HTTP {status_code}.'
        except httpx.RequestError:
            self._record_request(provider, started, failed=True)
            return None, f'{provider.title()} service is unavailable.'
        except ValueError:
            self._record_request(provider, started, failed=True)
            return None, f'{provider.title()} returned an invalid response.'
        self._record_request(provider, started, failed=False)
        return payload, None

    @staticmethod
    def _integration_error(
        tool: str,
        message: str,
        policy_code: str,
        **details: Any,
    ) -> dict[str, Any]:
        return {
            'tool': tool,
            'status': 'error',
            'isError': True,
            'error': message,
            'policy_code': policy_code,
            **details,
        }

    @staticmethod
    def _valid_repo_path(path: str) -> bool:
        if not isinstance(path, str) or not path or len(path) > 512:
            return False
        parts = path.split('/')
        return (
            not path.startswith('/')
            and all(part not in {'', '.', '..'} for part in parts)
        )

    def github_reader(
        self,
        repo: str = GITHUB_REPOSITORY,
        path: str = DEFAULT_GITHUB_PATH,
    ) -> dict[str, Any]:
        if self._mode == 'fixture':
            return github_reader_fixture(repo)
        if not isinstance(repo, str) or len(repo) > 200 or not _REPOSITORY_PATTERN.fullmatch(repo):
            return self._integration_error(
                'github_reader',
                'Repository must use the owner/repository format.',
                'GITHUB_REPOSITORY_INVALID',
            )
        if repo.casefold() not in self._allowed_repositories:
            return self._integration_error(
                'github_reader',
                'The requested repository is not in the configured allowlist.',
                'GITHUB_REPOSITORY_NOT_ALLOWED',
                repo=repo,
            )
        if not self._valid_repo_path(path):
            return self._integration_error(
                'github_reader',
                'Repository path is invalid.',
                'GITHUB_PATH_INVALID',
                repo=repo,
            )

        owner, name = repo.split('/', 1)
        encoded_path = '/'.join(quote(part, safe='') for part in path.split('/'))
        url = (
            f'https://api.github.com/repos/{quote(owner, safe="")}/'
            f'{quote(name, safe="")}/contents/{encoded_path}'
        )
        headers = {'Accept': 'application/vnd.github+json'}
        if self._github_token:
            headers['Authorization'] = f'Bearer {self._github_token}'
        payload, error = self._get_json('github', url, {}, headers)
        if error:
            return self._integration_error(
                'github_reader',
                error,
                'GITHUB_REQUEST_FAILED',
                repo=repo,
                path=path,
            )
        if (
            payload is None
            or payload.get('type') != 'file'
            or payload.get('encoding') != 'base64'
            or not isinstance(payload.get('content'), str)
        ):
            return self._integration_error(
                'github_reader',
                'The requested GitHub path is not a supported text file.',
                'GITHUB_FILE_UNSUPPORTED',
                repo=repo,
                path=path,
            )

        try:
            encoded_content = ''.join(payload['content'].split()).encode('ascii')
            if len(encoded_content) > ((GITHUB_FILE_LIMIT_BYTES + 2) // 3) * 4 + 8:
                raise ValueError('GitHub file exceeds the configured size limit.')
            content = base64.b64decode(encoded_content, validate=True)
            if len(content) > GITHUB_FILE_LIMIT_BYTES:
                raise ValueError('GitHub file exceeds the configured size limit.')
            text = content.decode('utf-8-sig')
        except (UnicodeDecodeError, ValueError, binascii.Error):
            return self._integration_error(
                'github_reader',
                'The requested GitHub file is invalid, binary, or larger than 1 MB.',
                'GITHUB_FILE_INVALID',
                repo=repo,
                path=path,
            )

        blob_sha = payload.get('sha')
        if not isinstance(blob_sha, str) or not blob_sha:
            return self._integration_error(
                'github_reader',
                'GitHub did not return a content revision for the requested file.',
                'GITHUB_REVISION_MISSING',
                repo=repo,
                path=path,
            )
        return {
            'tool': 'github_reader',
            'repo': repo,
            'path': path,
            'script': text,
            'source': 'github-api',
            'provenance': {
                'source': 'github-api',
                'trust_zone': 'LOW',
                'blob_sha': blob_sha,
                'path': path,
                'retrieved_at': datetime.now(timezone.utc).isoformat(),
            },
        }

    def _geocode(self, city: str) -> tuple[dict[str, Any] | None, str | None]:
        key = city.casefold()
        now = time.monotonic()
        with self._cache_lock:
            cached = self._geocode_cache.get(key)
            if cached and cached[0] > now:
                self._geocode_cache.move_to_end(key)
                with self._metrics_lock:
                    self._metrics['geocode_cache']['hits'] += 1
                return {
                    'latitude': cached[1],
                    'longitude': cached[2],
                    'name': cached[3],
                }, None
            if cached:
                del self._geocode_cache[key]
                with self._metrics_lock:
                    self._metrics['geocode_cache']['expirations'] += 1
            with self._metrics_lock:
                self._metrics['geocode_cache']['misses'] += 1

        payload, error = self._get_json(
            'weather',
            'https://geocoding-api.open-meteo.com/v1/search',
            {'name': city, 'count': 1, 'language': 'en', 'format': 'json'},
        )
        if error:
            return None, error
        results = payload.get('results') if payload else None
        if not isinstance(results, list) or not results:
            return None, 'No matching location was found.'
        location = results[0]
        if not isinstance(location, dict):
            return None, 'Open-Meteo returned an invalid location.'
        latitude = location.get('latitude')
        longitude = location.get('longitude')
        place_name = location.get('name')
        if (
            isinstance(latitude, bool)
            or isinstance(longitude, bool)
            or not isinstance(latitude, (int, float))
            or not isinstance(longitude, (int, float))
            or not math.isfinite(latitude)
            or not math.isfinite(longitude)
            or not isinstance(place_name, str)
        ):
            return None, 'Open-Meteo returned invalid coordinates.'
        with self._cache_lock:
            self._geocode_cache[key] = (
                time.monotonic() + GEOCODE_CACHE_TTL_SECONDS,
                float(latitude),
                float(longitude),
                place_name,
            )
            self._geocode_cache.move_to_end(key)
            if len(self._geocode_cache) > GEOCODE_CACHE_MAX_ENTRIES:
                self._geocode_cache.popitem(last=False)
                with self._metrics_lock:
                    self._metrics['geocode_cache']['evictions'] += 1
        return {
            'latitude': float(latitude),
            'longitude': float(longitude),
            'name': place_name,
        }, None

    @staticmethod
    def _weather_condition(code: Any) -> str:
        if isinstance(code, bool) or not isinstance(code, int):
            return 'Condition unavailable'
        if code == 0:
            return 'Clear sky'
        if code == 1:
            return 'Mainly clear'
        if code == 2:
            return 'Partly cloudy'
        if code == 3:
            return 'Overcast'
        if code in {45, 48}:
            return 'Fog'
        if code in {51, 53, 55, 56, 57}:
            return 'Drizzle'
        if code in {61, 63, 65, 66, 67, 80, 81, 82}:
            return 'Rain'
        if code in {71, 73, 75, 77, 85, 86}:
            return 'Snow'
        if code in {95, 96, 99}:
            return 'Thunderstorm'
        return 'Condition unavailable'

    def weather_api(self, city: str = 'Seattle') -> dict[str, Any]:
        if self._mode == 'fixture':
            return weather_api_fixture(city)
        if not isinstance(city, str) or not city.strip() or len(city) > 120:
            return self._integration_error(
                'weather_api',
                'City must be a non-empty name of at most 120 characters.',
                'WEATHER_CITY_INVALID',
            )
        city = ' '.join(city.split())
        location, error = self._geocode(city)
        if error:
            return self._integration_error(
                'weather_api',
                error,
                'WEATHER_LOCATION_FAILED',
                city=city,
            )
        payload, error = self._get_json(
            'weather',
            'https://api.open-meteo.com/v1/forecast',
            {
                'latitude': location['latitude'],
                'longitude': location['longitude'],
                'current': 'temperature_2m,weather_code',
                'daily': 'weather_code',
                'forecast_days': 1,
                'timezone': 'auto',
            },
        )
        if error:
            return self._integration_error(
                'weather_api',
                error,
                'WEATHER_REQUEST_FAILED',
                city=city,
            )
        current = payload.get('current') if payload else None
        daily = payload.get('daily') if payload else None
        temperature = current.get('temperature_2m') if isinstance(current, dict) else None
        weather_time = current.get('time') if isinstance(current, dict) else None
        current_code = current.get('weather_code') if isinstance(current, dict) else None
        daily_codes = daily.get('weather_code') if isinstance(daily, dict) else None
        if (
            isinstance(temperature, bool)
            or not isinstance(temperature, (int, float))
            or not math.isfinite(temperature)
            or not isinstance(weather_time, str)
            or not isinstance(daily_codes, list)
            or not daily_codes
        ):
            return self._integration_error(
                'weather_api',
                'Open-Meteo returned incomplete current conditions.',
                'WEATHER_RESPONSE_INVALID',
                city=city,
            )

        return {
            'tool': 'weather_api',
            'city': city,
            'temperature_c': float(temperature),
            'condition': self._weather_condition(current_code),
            'forecast': self._weather_condition(daily_codes[0]),
            'source': 'open-meteo',
            'provenance': {
                'source': 'open-meteo',
                'trust_zone': 'LOW',
                'resolved_location': location['name'],
                'weather_time': weather_time,
                'retrieved_at': datetime.now(timezone.utc).isoformat(),
                'cached_weather_data': False,
            },
        }


def github_reader_fixture(repo: str = 'demo') -> dict[str, Any]:
    script_path = BASE_DIR / 'data' / 'cleanup_script.sql'
    with open(script_path, 'r', encoding='utf-8-sig') as handle:
        script = handle.read()
    return {
        'tool': 'github_reader',
        'repo': repo,
        'source': 'local-fixture',
        'provenance': {'source': 'local-fixture', 'trust_zone': 'LOW'},
        'script': script,
    }


def weather_api_fixture(city: str = 'Seattle') -> dict[str, Any]:
    return {
        'tool': 'weather_api',
        'city': city,
        'temperature_c': 18,
        'condition': 'light rain',
        'forecast': 'Cloudy with passing showers',
        'source': 'local-fixture',
        'provenance': {'source': 'local-fixture', 'trust_zone': 'LOW'},
    }


_standalone_integrations = RemoteIntegrations()


@mcp.tool()
def github_reader(
    repo: str = GITHUB_REPOSITORY,
    path: str = DEFAULT_GITHUB_PATH,
) -> dict[str, Any]:
    return _standalone_integrations.github_reader(repo, path)


@mcp.tool()
def weather_api(city: str = 'Seattle') -> dict[str, Any]:
    return _standalone_integrations.weather_api(city)


@mcp.tool()
def production_database(sql: str, _guarded: bool = False) -> dict[str, Any]:
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
    except sqlite3.Error as exc:
        conn.rollback()
        return {'tool': 'production_database', 'status': 'error', 'error': str(exc), 'isError': True}
    finally:
        conn.close()
