# ShadowGuard AI backend

## Windows PowerShell setup

From the project root, activate the existing virtual environment, install the
backend dependencies, and create a local environment file from the example:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r .\backend\requirements.txt
if (-not (Test-Path .\backend\.env)) { Copy-Item .\backend\.env.example .\backend\.env }
notepad .\backend\.env
```

In `backend\.env`, set `APPROVAL_OPERATOR_TOKEN` to a high-entropy secret. You
can generate one with
`python -c "import secrets; print(secrets.token_urlsafe(32))"` and paste it
into the local file. Approval and rejection decisions require this value as a
Bearer token with at least 32 UTF-8 bytes; missing or weak configuration fails
closed with HTTP 503. The
dashboard prompts for the token when confirming a decision and keeps it only
in memory for that dialog. Never commit or share the local `.env` file.

Replace `YOUR_API_KEY_HERE` with a valid OpenAI API key. Set `MODEL_NAME` to a
model available to that account, for example
`openai:gpt-4o-mini`. The `.env` file is ignored by Git; do not commit it or
share its contents. For an OpenRouter account, set `MODEL_NAME` to an available
OpenRouter model identifier such as `openrouter:openai/gpt-4o-mini`, and set
`OPENROUTER_API_KEY` (or use the existing `OPENAI_API_KEY` variable). Restart
the backend after changing either value.

The GitHub reader uses the GitHub Contents API. Configure
`GITHUB_REPOSITORY=owner/repository` and the comma-separated
`GITHUB_ALLOWED_REPOSITORIES` allowlist in `backend\.env`. A `GITHUB_TOKEN`
environment value is used for authenticated access (and is required for
private repositories); the token is never included in logs or tool results.
Weather requests use Open-Meteo and fetch current conditions from its live API.
Only geocoding results are cached (24-hour TTL, 128 entries); current weather
is fetched each time and includes the provider's observation time.

The default integration mode is `live`. Set
`SHADOWGUARD_INTEGRATION_MODE=fixture` only for explicitly offline demos and
tests. Fixture results are labelled as local fixtures and are not evidence that
the real integrations have been verified.

Start the API from the backend directory:

```powershell
Set-Location .\backend
python -m uvicorn app.main:app --reload
```

Check `http://127.0.0.1:8000/api/health`, then send a POST request to
`http://127.0.0.1:8000/api/chat` with JSON such as
`{"message":"Hello","user_id":"demo-user"}`. A successful response includes
`response`, `status`, `approval_id`, `session_id`, `state`, and `provenance`.
Protected operations remain subject to ShadowGuard policy and human approval.

The ML trust and intent signals use saved synthetic-demonstration models. See
[`docs/ml-security-models.md`](../docs/ml-security-models.md) for training,
evaluation metrics, configuration, and limitations.

See [`docs/edge-first-architecture.md`](../docs/edge-first-architecture.md)
for the current execution architecture, security flows, measured local
benchmarks, and remaining limitations.
