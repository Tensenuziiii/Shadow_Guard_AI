# ShadowGuard dashboard

## Run locally

From the repository root, install the backend dependencies and create a local
environment file:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Copy-Item backend\.env.example backend\.env
```

Set `MODEL_NAME` and the matching provider key in `backend\.env`. For OpenAI,
use `MODEL_NAME=openai:gpt-4o-mini` and `OPENAI_API_KEY`. For OpenRouter, use
an available model such as `MODEL_NAME=openrouter:openai/gpt-4o-mini` and set
`OPENROUTER_API_KEY` (or put the OpenRouter key in `OPENAI_API_KEY`). Do not
commit the local `.env` file. Also set `APPROVAL_OPERATOR_TOKEN` to a random
secret of at least 32 UTF-8 bytes; the dashboard asks for it when confirming
an approval or rejection and does not persist it. Generate a value with
`python -c "import secrets; print(secrets.token_urlsafe(32))"`. Without a
valid server token, approval decisions fail closed. Then start the backend:

Also set `GITHUB_REPOSITORY` and `GITHUB_ALLOWED_REPOSITORIES` to the GitHub
repositories the reader may access. `GITHUB_TOKEN` enables authenticated
access to private repositories. Weather uses live Open-Meteo data; only city
geocoding is cached. See
[`../backend/README.md`](../backend/README.md) for integration settings and
[`../docs/edge-first-architecture.md`](../docs/edge-first-architecture.md) for
architecture, measurements, and limitations.

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

In a second terminal, start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api` and `/ws` to the backend.
The current Vite configuration binds to `0.0.0.0`; use it only on a trusted
network, or change `server.host` to `127.0.0.1` for a local-only demo because
most backend API routes are unauthenticated.

For a production bundle, run `npm run build`; the generated files are written
to `frontend/dist/`.

## Dashboard features

- Agent chat with the current session trust state.
- Approval queue with SQL previews, taint-source review, and approve/reject actions.
- Integration trust-zone configuration.
- Recent and live security events.
- Demo scenario controls for an approval-gated SQL action and a tainted-session block.
