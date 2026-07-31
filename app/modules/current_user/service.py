"""File: app/modules/current_user/service.py

Purpose:
Owns current-user profile reads, preference updates, and effective
role/permission projections.

Dependency flow:
CurrentUserServiceDep and authenticated user identifier
-> request-scoped SQLAlchemyUnitOfWork
-> CurrentUserRepository on the shared session
-> profile mutation or claim loading
-> unit-of-work commit/rollback
-> response contract
"""

from __future__ import annotations

import uuid

from app.auth.identity.presentation import public_user_data
from app.common.exceptions import AuthenticationError, NotFoundError
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.identity import UserProfiles
from app.modules.current_user.repositories import CurrentUserRepository
from app.modules.current_user.schemas import (
    CurrentAuthorizationResponse,
    UpdateCurrentUserRequest,
    UserPermissionsResponse,
    UserResponse,
    UserRolesResponse,
)
from app.utils.datetime_utils import utc_now

_PROFILE_FIELDS = {
    "first_name",
    "last_name",
    "preferred_name",
    "avatar_object_key",
}


class CurrentUserService:
    """Read and update the authenticated user's identity preferences."""

    def __init__(self, *, uow: SQLAlchemyUnitOfWork) -> None:
        self._uow = uow

    async def get(self, *, user_id: uuid.UUID) -> UserResponse:
        """Return the current identity and effective authorization claims."""
        async with self._uow:
            users = CurrentUserRepository(self._uow.session)
            user = await users.get_by_id(user_id)
            if user is None:
                raise NotFoundError("The user was not found.")
            profile = await users.get_active_profile(user.id)
            claims = await users.authorization_claims(user_id=user.id, now=utc_now())
            return UserResponse.model_validate(
                public_user_data(
                    user,
                    profile=profile,
                    roles=claims.roles,
                    permissions=claims.permissions,
                )
            )

    async def update(
        self,
        *,
        user_id: uuid.UUID,
        payload: UpdateCurrentUserRequest,
    ) -> UserResponse:
        """Update identity preferences and the owner's universal profile."""
        async with self._uow:
            users = CurrentUserRepository(self._uow.session)
            user = await users.get_by_id(user_id, for_update=True)
            if user is None:
                raise NotFoundError("The user was not found.")
            profile = await users.get_active_profile(user.id, for_update=True)
            account_updates = payload.model_dump(
                include={"preferred_locale", "timezone"},
                exclude_none=True,
            )
            if "preferred_locale" in account_updates:
                user.preferred_locale = str(account_updates["preferred_locale"])
            if "timezone" in account_updates:
                user.timezone = str(account_updates["timezone"])

            # exclude_unset distinguishes an omitted value from an explicit
            # null, allowing an owner to clear individual optional fields.
            profile_updates = payload.model_dump(
                include=_PROFILE_FIELDS,
                exclude_unset=True,
            )
            if profile is None and any(value is not None for value in profile_updates.values()):
                profile = UserProfiles(
                    user_id=user.id,
                    first_name=profile_updates.get("first_name"),
                    last_name=profile_updates.get("last_name"),
                    preferred_name=profile_updates.get("preferred_name"),
                    avatar_object_key=profile_updates.get("avatar_object_key"),
                    created_by=user.id,
                    updated_by=user.id,
                )
                users.add_profile(profile)
            elif profile is not None and profile_updates:
                for field_name, value in profile_updates.items():
                    setattr(profile, field_name, value)
                profile.updated_by = user.id

            claims = await users.authorization_claims(user_id=user.id, now=utc_now())
            return UserResponse.model_validate(
                public_user_data(
                    user,
                    profile=profile,
                    roles=claims.roles,
                    permissions=claims.permissions,
                )
            )

    async def roles(
        self,
        *,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> UserRolesResponse:
        """Compatibility projection of the consolidated authorization result."""
        authorization = await self.authorization(
            user_id=user_id,
            session_id=session_id,
        )
        return UserRolesResponse(roles=authorization.roles)

    async def permissions(
        self,
        *,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> UserPermissionsResponse:
        """Compatibility projection of the consolidated authorization result."""
        authorization = await self.authorization(
            user_id=user_id,
            session_id=session_id,
        )
        return UserPermissionsResponse(permissions=authorization.permissions)

    async def authorization(
        self,
        *,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> CurrentAuthorizationResponse:
        """Resolve current effective global authorization from the database."""
        async with self._uow:
            users = CurrentUserRepository(self._uow.session)
            if await users.get_by_id(user_id) is None:
                raise NotFoundError("The user was not found.")
            now = utc_now()
            if not await users.active_session_exists(
                user_id=user_id,
                session_id=session_id,
                now=now,
            ):
                raise AuthenticationError(
                    "The access session is expired or revoked."
                )
            claims = await users.authorization_claims(user_id=user_id, now=now)
            return CurrentAuthorizationResponse(
                roles=sorted(set(claims.roles)),
                permissions=sorted(set(claims.permissions)),
            )


__all__ = ["CurrentUserService"]
