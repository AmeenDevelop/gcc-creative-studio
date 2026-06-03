# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Microsoft Entra ID (Azure AD) token verification.

Verifies an ID token issued by Microsoft Entra against the tenant's JWKS
endpoint and enforces audience + issuer. Group-membership enforcement is
performed by the caller (``auth_guard``) using the decoded claims.
"""


import logging
from typing import Any

import jwt
from jwt import PyJWKClient

from src.config.config_service import config_service

logger = logging.getLogger(__name__)


# A single PyJWKClient instance keeps the JWKS in memory and refreshes it
# only when an unknown ``kid`` is seen, which is the recommended pattern.
_jwks_client: PyJWKClient | None = None


def _get_jwks_client() -> PyJWKClient:
    """Lazily build and cache the JWKS client for the configured tenant."""
    global _jwks_client  # noqa: PLW0603
    if _jwks_client is None:
        if not config_service.ENTRA_JWKS_URL:
            raise RuntimeError(
                "Entra is not configured; ENTRA_TENANT_ID is empty."
            )
        _jwks_client = PyJWKClient(
            config_service.ENTRA_JWKS_URL,
            cache_keys=True,
            lifespan=3600,
        )
    return _jwks_client


def is_entra_token(token: str) -> bool:
    """Cheap, signature-less check: does this look like a Microsoft token?

    We inspect the unverified ``iss`` claim. If it matches the configured
    Entra tenant issuer, we route to Microsoft verification. Otherwise we
    fall back to Firebase / Google verification.
    """
    if not config_service.ENTRA_ENABLED:
        return False
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return False

    issuer = unverified.get("iss", "")
    # v2.0 issuer is the configured one. v1.0 issuer uses {tenant}/ (no /v2.0)
    # and we accept both because Entra App Registrations can be configured
    # for either token version.
    tenant = config_service.ENTRA_TENANT_ID
    return (
        issuer == config_service.ENTRA_ISSUER
        or issuer == f"https://sts.windows.net/{tenant}/"
    )


def verify_entra_token(token: str) -> dict[str, Any]:
    """Verify a Microsoft Entra ID token and return its decoded claims.

    Raises ``jwt.InvalidTokenError`` (or subclasses) on any validation
    failure: bad signature, wrong audience, wrong issuer, expired, etc.
    """
    if not config_service.ENTRA_ENABLED:
        raise RuntimeError("Entra is not configured.")

    signing_key = _get_jwks_client().get_signing_key_from_jwt(token).key

    tenant = config_service.ENTRA_TENANT_ID
    accepted_issuers = {
        config_service.ENTRA_ISSUER,
        f"https://sts.windows.net/{tenant}/",
    }

    decoded = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256"],
        audience=config_service.ENTRA_CLIENT_ID,
        options={"require": ["exp", "iat", "iss", "aud"]},
    )

    if decoded.get("iss") not in accepted_issuers:
        raise jwt.InvalidIssuerError(
            f"Unexpected issuer: {decoded.get('iss')!r}"
        )

    return decoded


def extract_group_ids(claims: dict[str, Any]) -> list[str]:
    """Return the list of Entra group Object IDs in the token's claims.

    Returns an empty list if the ``groups`` claim is absent. Note that
    Entra omits ``groups`` entirely when a user is in too many groups
    (the "groups overage" scenario), in which case the token instead
    contains ``_claim_names`` / ``_claim_sources`` pointing at Microsoft
    Graph. We do not call Graph here; the App Registration should be
    configured (Token configuration -> groups claim -> "Groups assigned
    to the application") to keep the list bounded.
    """
    groups = claims.get("groups")
    if isinstance(groups, list):
        return [str(g) for g in groups]
    return []


def has_overage(claims: dict[str, Any]) -> bool:
    """True if the token signals a groups overage indirection via Graph."""
    names = claims.get("_claim_names") or {}
    return "groups" in names
