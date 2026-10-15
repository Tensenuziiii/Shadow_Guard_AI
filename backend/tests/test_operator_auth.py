from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import app.security.operator_auth as operator_auth


def test_approval_operator_authentication_fails_closed_when_unconfigured(monkeypatch):
    monkeypatch.setattr(operator_auth, 'APPROVAL_OPERATOR_TOKEN', '')
    app = FastAPI()

    @app.post('/protected', dependencies=[Depends(operator_auth.require_approval_operator)])
    def protected():
        return {'authorized': True}

    with TestClient(app) as client:
        response = client.post('/protected', headers={'Authorization': 'Bearer anything'})

    assert response.status_code == 503
    assert response.json()['detail'] == 'Approval operator authentication is not configured.'


def test_approval_operator_authentication_rejects_a_short_configured_token(monkeypatch):
    monkeypatch.setattr(operator_auth, 'APPROVAL_OPERATOR_TOKEN', 'too-short')
    app = FastAPI()

    @app.post('/protected', dependencies=[Depends(operator_auth.require_approval_operator)])
    def protected():
        return {'authorized': True}

    with TestClient(app) as client:
        response = client.post('/protected', headers={'Authorization': 'Bearer too-short'})

    assert response.status_code == 503
    assert 'at least 32 UTF-8 bytes' in response.json()['detail']


def test_approval_operator_authentication_rejects_missing_and_invalid_tokens(monkeypatch):
    monkeypatch.setattr(
        operator_auth,
        'APPROVAL_OPERATOR_TOKEN',
        'test-operator-token-with-at-least-32-bytes',
    )
    app = FastAPI()

    @app.post('/protected', dependencies=[Depends(operator_auth.require_approval_operator)])
    def protected():
        return {'authorized': True}

    with TestClient(app) as client:
        missing = client.post('/protected')
        invalid = client.post(
            '/protected',
            headers={'Authorization': 'Bearer wrong-token'},
        )
        wrong_scheme = client.post(
            '/protected',
            headers={'Authorization': 'Basic test-operator-token'},
        )

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert wrong_scheme.status_code == 401
    assert 'test-operator-token' not in missing.text + invalid.text + wrong_scheme.text


def test_approval_operator_authentication_accepts_matching_bearer_token(monkeypatch):
    token = 'test-operator-token-with-at-least-32-bytes'
    monkeypatch.setattr(operator_auth, 'APPROVAL_OPERATOR_TOKEN', token)
    app = FastAPI()

    @app.post('/protected', dependencies=[Depends(operator_auth.require_approval_operator)])
    def protected():
        return {'authorized': True}

    with TestClient(app) as client:
        response = client.post(
            '/protected',
            headers={'Authorization': f'Bearer {token}'},
        )

    assert response.status_code == 200
    assert response.json() == {'authorized': True}
