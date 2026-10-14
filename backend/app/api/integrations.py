from fastapi import APIRouter, HTTPException, Request

from app.schemas import IntegrationSettingsRequest

router = APIRouter(prefix='/api')


@router.get('/integrations')
def list_integrations(request: Request):
    app_state = request.app.state.app_state
    return {'tools': app_state['trust_registry'].list_tools()}


@router.post('/integrations')
def set_integration(request: Request, settings: IntegrationSettingsRequest):
    app_state = request.app.state.app_state
    existing = app_state['trust_registry'].get_tool(settings.name)
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail=f"Integration '{settings.name}' is not registered in the gateway.",
        )

    zone = settings.trust_zone.upper()
    if zone not in {'HIGH', 'LOW', 'MEDIUM'}:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid trust zone '{settings.trust_zone}'. Allowed zones: HIGH, LOW, MEDIUM.",
        )

    try:
        tool = app_state['trust_registry'].set_trust_zone(settings.name, zone)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    request.app.state.audit_logger.log_event(
        'integration_policy_updated',
        'system',
        f"Integration '{settings.name}' trust zone updated to {zone}",
        {'tool_name': settings.name, 'trust_zone': zone, 'trust_score': tool.get('trust_score')},
        None,
        settings.name,
        'POLICY_UPDATE',
        severity='info',
    )
    app_state['event_hub'].publish(
        'integration_policy_updated',
        'system',
        f"Integration '{settings.name}' trust zone updated to {zone}.",
        {'tool_name': settings.name, 'trust_zone': zone},
        None,
        settings.name,
        'POLICY_UPDATE',
    )
    return {'tool': tool}
