from __future__ import annotations

import base64

import httpx

from app.mcp_server import GEOCODE_CACHE_TTL_SECONDS, RemoteIntegrations


def test_github_reader_uses_authenticated_api_and_preserves_content_contract():
    calls = []
    script = 'SELECT id, name FROM users;'

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200,
            json={
                'type': 'file',
                'encoding': 'base64',
                'content': base64.b64encode(script.encode()).decode() + '\n',
                'sha': 'blob-sha-123',
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        integration = RemoteIntegrations(
            client=client,
            github_token='test-token',
            allowed_repositories=('owner/repository',),
            mode='live',
        )
        result = integration.github_reader('owner/repository')
        metrics = integration.metrics_snapshot()

    assert result['script'] == script
    assert result['source'] == 'github-api'
    assert result['provenance']['blob_sha'] == 'blob-sha-123'
    assert result['provenance']['trust_zone'] == 'LOW'
    assert calls[0].url.path == '/repos/owner/repository/contents/backend/data/cleanup_script.sql'
    assert calls[0].headers['Authorization'] == 'Bearer test-token'
    assert metrics['github']['requests'] == 1
    assert metrics['github']['failures'] == 0


def test_github_reader_denies_unlisted_or_unsafe_repositories_without_network():
    calls = []
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: calls.append(request)
            or httpx.Response(200, json={}),
        ),
    )
    try:
        integration = RemoteIntegrations(
            client=client,
            allowed_repositories=('owner/allowed',),
            mode='live',
        )
        denied = integration.github_reader('owner/private')
        malformed = integration.github_reader('owner/allowed', '../.env')
    finally:
        client.close()

    assert denied['policy_code'] == 'GITHUB_REPOSITORY_NOT_ALLOWED'
    assert malformed['policy_code'] == 'GITHUB_PATH_INVALID'
    assert calls == []


def test_weather_uses_live_conditions_and_caches_only_geocoding():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.host == 'geocoding-api.open-meteo.com':
            return httpx.Response(
                200,
                json={
                    'results': [
                        {'name': 'Seattle', 'latitude': 47.6062, 'longitude': -122.3321},
                    ],
                },
            )
        return httpx.Response(
            200,
            json={
                'current': {
                    'temperature_2m': 14.2,
                    'weather_code': 3,
                    'time': '2026-10-15T00:00',
                },
                'daily': {'weather_code': [2]},
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        integration = RemoteIntegrations(client=client, mode='live')
        first = integration.weather_api(' Seattle ')
        second = integration.weather_api('Seattle')
        metrics = integration.metrics_snapshot()

    assert first['temperature_c'] == 14.2
    assert first['condition'] == 'Overcast'
    assert first['forecast'] == 'Partly cloudy'
    assert first['source'] == 'open-meteo'
    assert first['provenance']['cached_weather_data'] is False
    assert second['provenance']['weather_time'] == '2026-10-15T00:00'
    assert sum(request.url.host == 'geocoding-api.open-meteo.com' for request in calls) == 1
    assert sum(request.url.host == 'api.open-meteo.com' for request in calls) == 2
    assert metrics['weather']['requests'] == 3
    assert metrics['geocode_cache'] == {
        'hits': 1,
        'misses': 1,
        'expirations': 0,
        'evictions': 0,
    }


def test_geocode_cache_expiration_fetches_fresh_coordinates(monkeypatch):
    import app.mcp_server as mcp_server

    now = [10.0]
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200,
            json={
                'results': [
                    {'name': 'Seattle', 'latitude': 47.6, 'longitude': -122.3},
                ],
            },
        )

    monkeypatch.setattr(mcp_server.time, 'monotonic', lambda: now[0])
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        integration = RemoteIntegrations(client=client, mode='live')
        first, first_error = integration._geocode('Seattle')
        now[0] += GEOCODE_CACHE_TTL_SECONDS
        second, second_error = integration._geocode('Seattle')
        metrics = integration.metrics_snapshot()

    assert first_error is None
    assert second_error is None
    assert first == second
    assert len(calls) == 2
    assert metrics['geocode_cache'] == {
        'hits': 0,
        'misses': 2,
        'expirations': 1,
        'evictions': 0,
    }


def test_weather_failure_is_explicit_and_does_not_fabricate_conditions():
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout('test timeout')

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        integration = RemoteIntegrations(client=client, mode='live')
        result = integration.weather_api('Seattle')
        metrics = integration.metrics_snapshot()

    assert result['isError'] is True
    assert result['status'] == 'error'
    assert result['policy_code'] == 'WEATHER_LOCATION_FAILED'
    assert 'temperature_c' not in result
    assert metrics['weather']['requests'] == 1
    assert metrics['weather']['failures'] == 1


def test_github_http_errors_do_not_return_remote_body_or_credentials():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text='private-response-body')

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        integration = RemoteIntegrations(
            client=client,
            github_token='test-token',
            allowed_repositories=('owner/repository',),
            mode='live',
        )
        result = integration.github_reader('owner/repository')

    assert result['isError'] is True
    assert result['policy_code'] == 'GITHUB_REQUEST_FAILED'
    assert 'HTTP 404' in result['error']
    assert 'private-response-body' not in str(result)
    assert 'test-token' not in str(result)
