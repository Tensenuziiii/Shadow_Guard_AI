# ShadowGuard AI implementation plan

## Phase 1: inspect and plan
- Confirm the workspace is empty and establish the backend/frontend structure.
- Capture the runtime constraints and exact dependency versions used in the project.
- Create the architecture and implementation plan documents.

## Phase 2: database and security core
- Initialize the SQLite database and create durable tables for sessions, approval records, tool trust assignments, and audit events.
- Add the trust registry with the required three integrations and allow persisted configuration updates.
- Implement session creation, taint transitions, and sticky taint semantics.
- Implement the risk engine with SQL parsing, allowlists, destructive statement classification, and structured reasons.

## Phase 3: shadow state and approval lifecycle
- Create a shadow SQLite clone with a backup-based snapshot.
- Compute blast radius details before any live mutation.
- Stage pending approvals with a unique action ID and explicit action state transitions.
- Enforce duplicate, expired, stale, and unauthorized approval rejections.
- Commit approved SQL in a transaction only after snapshot revalidation.

## Phase 4: FastMCP and Pydantic AI integration
- Register the actual FastMCP tool layer with guarded adapters.
- Force the agent to use the guarded tool adapter rather than direct database access.
- Ensure unknown tools and failures fail closed.
- Use Pydantic AI with a local test model to keep the MVP self-contained.

## Phase 5: FastAPI and WebSockets
- Add API routes for health checks, chat requests, integrations, pending approvals, and decision endpoints.
- Add authenticated session handling and WebSocket event fan-out for the dashboard.
- Publish security events with typed payloads that can be consumed by the frontend.

## Phase 6: React dashboard
- Implement a chat panel, live event feed, trust-state indicators, blast-radius reporting, and action controls.
- Add integration configuration toggles backed by the backend.
- Connect the dashboard to the WebSocket stream and approval API.

## Phase 7: end-to-end validation
- Run the backend test suite.
- Run the frontend production build.
- Validate both demo scenarios and confirm nothing mutates the real database after a rejection or taint block.

## Phase 8: documentation and handoff
- Update README guidance, startup commands, environment variables, and troubleshooting notes.
- Document the live demo flows and limitations of the MVP.
- Record the final runbook for the team.
