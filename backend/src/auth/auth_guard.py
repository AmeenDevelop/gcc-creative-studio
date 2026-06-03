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
"""Authentication guards and user retrieval."""


import asyncio
import logging

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from firebase_admin import auth

# --- Google Auth for Identity Platform ---
from google.auth.transport import requests as google_auth_requests
from google.oauth2 import id_token

from src.auth import entra_token_service
from src.config.config_service import config_service
from src.users.user_model import UserModel, UserRoleEnum
from src.users.user_service import UserService

# Initialize the service once to be used by dependencies.
# user_service = UserService()  <-- REMOVED

# This scheme will require the client to send a token in the Authorization
# header. It tells FastAPI how to find the token but doesn't validate it
# itself.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


logger = logging.getLogger(__name__)


def _enforce_entra_group_membership(claims: dict) -> None:
    """Reject the request unless the user is a member of an allowed group.

    Skipped (no-op) when ``ENTRA_ALLOWED_GROUP_IDS`` is empty so deployments
    can opt in to group-based restriction. When required, the token's
    ``groups`` claim must contain at least one of the configured group IDs.
    """
    allowed = config_service.ENTRA_ALLOWED_GROUP_IDS
    if not allowed:
        return

    if entra_token_service.has_overage(claims):
        # The user is in too many groups for Entra to inline them in the
        # token. Configure the App Registration's Token configuration
        # to emit "Groups assigned to the application" to keep the
        # list bounded.
        logger.error(
            "Entra token signals groups overage; cannot verify membership "
            "without a Graph API call. Configure the App Registration to "
            "emit only assigned groups."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Forbidden: token signalled too many groups. Ask the "
                "administrator to scope the 'groups' claim to assigned "
                "groups only."
            ),
        )

    token_groups = set(entra_token_service.extract_group_ids(claims))
    if not token_groups & allowed:
        logger.warning(
            "Entra user is not in any allowed security group. "
            "User groups=%s allowed=%s",
            sorted(token_groups),
            sorted(allowed),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Forbidden: user is not a member of an allowed security "
                "group."
            ),
        )


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    user_service: UserService = Depends(UserService),
) -> UserModel:
    """Dependency that handles the entire authentication and user
    provisioning flow.

    1. Verifies the Firebase ID token.
    2. Extracts user information (id, email).
    3. Checks if a user document exists in Firestore.
    4. If the user is new, creates their document ("Just-In-Time Provisioning").
    5. Returns a Pydantic model with the user's data.
    """
    try:
        decoded_token: dict = {}
        is_microsoft_token = entra_token_service.is_entra_token(token)

        if is_microsoft_token:
            # --- Microsoft Entra ID path ---
            # Verify the raw Microsoft-signed ID token (sent by the
            # frontend after Firebase signInWithPopup against the OIDC
            # provider). The Firebase ID token would NOT carry the
            # `groups` claim, so we must verify the original Entra
            # token to enforce security-group membership.
            try:
                decoded_token = await asyncio.to_thread(
                    entra_token_service.verify_entra_token, token
                )
            except jwt.InvalidTokenError as exc:
                logger.warning("Entra token verification failed: %s", exc)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid Microsoft ID token: {exc}",
                ) from exc

            _enforce_entra_group_membership(decoded_token)
        elif config_service.ENVIRONMENT == "local":
            # --- Local: Use Firebase Auth ---
            # Verifies the token using the standard Firebase Admin SDK method.
            logger.info("Verifying token using Firebase Admin SDK...")
            decoded_token = await asyncio.to_thread(auth.verify_id_token, token)
        else:
            # --- Development/Production: Use Google Identity Platform
            # (OIDC) ---
            # Verifies the Google-issued OIDC ID token. The audience must be the
            # OAuth 2.0 client ID of the Identity Platform-protected resource.
            google_token_audience = config_service.GOOGLE_TOKEN_AUDIENCE
            decoded_token = await asyncio.to_thread(
                id_token.verify_oauth2_token,
                token,
                google_auth_requests.Request(),
                audience=google_token_audience,
            )

        email = decoded_token.get("email") or decoded_token.get(
            "preferred_username"
        )
        name = decoded_token.get("name")
        picture = decoded_token.get("picture", "")
        token_info_hd = decoded_token.get("hd")
        # Entra tokens don't carry `hd`; derive the org from the email
        # domain so existing ALLOWED_ORGS checks still apply if desired.
        if not token_info_hd and email and "@" in email:
            token_info_hd = email.split("@", 1)[1]

        # Restrict by particular organizations if it's a closed environment
        if not email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Forbidden: User identity could not be confirmed from "
                    "token."
                ),
            )

        # If ALLOWED_ORGS is configured, check the user's organization.
        # For Microsoft sign-ins, the per-group check above is the primary
        # restriction; the org check still applies as defence-in-depth.
        if config_service.ALLOWED_ORGS:
            if (
                not token_info_hd
                or token_info_hd not in config_service.ALLOWED_ORGS
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=(
                        f"User from '{token_info_hd}' is not part of an "
                        "allowed organization."
                    ),
                )

        # Just-In-Time (JIT) User Provisioning:
        # Create a user profile in our database on their first API call.
        user_doc = await user_service.create_user_if_not_exists(
            email=email,
            name=name,
            picture=picture,
        )

        if not user_doc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not create or retrieve user profile.",
            )

        if not user_doc.picture and picture:
            logger.info("Updating picture for user: %s", email)
            user_doc.picture = picture
            if user_doc.id:
                await user_service.user_repo.update(
                    user_doc.id, {"picture": picture}
                )

        return user_doc

    except auth.ExpiredIdTokenError as exc:
        logger.error(
            "[get_current_user - auth.ExpiredIdTokenError] for %s", email
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired.",
        ) from exc
    except auth.InvalidIdTokenError as e:
        logger.error(
            "[get_current_user - auth.InvalidIdTokenError] for %s: %s",
            email,
            e,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {e}",
        ) from e
    except HTTPException as e:
        logger.error("[get_current_user - Exception]: %s", e)
        raise e
    except Exception as e:
        logger.error("[get_current_user - Exception]: %s", e)
        raise HTTPException(
            status_code=getattr(
                e,
                "status_code",
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            ),
            detail=f"An unexpected error occurred during authentication: {e}",
        ) from e


class RoleChecker:
    """Dependency that checks if the authenticated user has the required roles.
    It depends on `get_current_user` to ensure the user is authenticated first.
    """

    def __init__(self, allowed_roles: list[UserRoleEnum]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: UserModel = Depends(get_current_user)):
        """Checks the user's roles against the allowed roles."""
        is_authorized = any(role in self.allowed_roles for role in user.roles)

        if not is_authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "You do not have sufficient permissions to perform this "
                    "action."
                ),
            )
