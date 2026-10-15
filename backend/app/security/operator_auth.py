from __future__ import annotations

import hmac

from fastapi import Header, HTTPException

from app.config import APPROVAL_OPERATOR_TOKEN


def require_approval_operator(authorization: str | None = Header(default=None)) -> None:
    if not APPROVAL_OPERATOR_TOKEN:
        raise HTTPException(
            status_code=503,
            detail='Approval operator authentication is not configured.',
        )
    if len(APPROVAL_OPERATOR_TOKEN.encode('utf-8')) < 32:
        raise HTTPException(
            status_code=503,
            detail='Approval operator token must contain at least 32 UTF-8 bytes.',
        )

    scheme, separator, supplied_token = (authorization or '').partition(' ')
    if (
        scheme.casefold() != 'bearer'
        or not separator
        or not supplied_token.strip()
        or not hmac.compare_digest(
            supplied_token.strip().encode('utf-8'),
            APPROVAL_OPERATOR_TOKEN.encode('utf-8'),
        )
    ):
        raise HTTPException(
            status_code=401,
            detail='A valid approval operator token is required.',
            headers={'WWW-Authenticate': 'Bearer'},
        )
