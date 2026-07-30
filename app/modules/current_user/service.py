"""File: app/modules/current_user/service.py
Current-user application service."""

from __future__ import annotations

import uuid

from app.auth.identity.presentation import public_user_data
from app.common.exceptions import NotFoundError
from app.db.uow import SQLAlchemyUnitOfWork
from app.modules.current_user.repositories import CurrentUserRepository
from app.modules.current_user.schemas import (
    UpdateCurrentUserRequest,
    UserPermissionsResponse,
    UserResponse,
    UserRolesResponse,
)
from app.utils.datetime_utils import utc_now


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
            claims = await users.authorization_claims(user_id=user.id, now=utc_now())
            return UserResponse.model_validate(
                public_user_data(user, roles=claims.roles, permissions=claims.permissions)
            )

    async def update(
        self,
        *,
        user_id: uuid.UUID,
        payload: UpdateCurrentUserRequest,
    ) -> UserResponse:
        """Update only identity-owned locale and timezone preferences."""
        async with self._uow:
            users = CurrentUserRepository(self._uow.session)
            user = await users.get_by_id(user_id, for_update=True)
            if user is None:
                raise NotFoundError("The user was not found.")
            updates = payload.model_dump(exclude_none=True)
            if "preferred_locale" in updates:
                user.preferred_locale = str(updates["preferred_locale"])
            if "timezone" in updates:
                user.timezone = str(updates["timezone"])
            claims = await users.authorization_claims(user_id=user.id, now=utc_now())
            return UserResponse.model_validate(
                public_user_data(user, roles=claims.roles, permissions=claims.permissions)
            )

    async def roles(self, *, user_id: uuid.UUID) -> UserRolesResponse:
        """Return effective global role codes."""
        async with self._uow:
            users = CurrentUserRepository(self._uow.session)
            if await users.get_by_id(user_id) is None:
                raise NotFoundError("The user was not found.")
            claims = await users.authorization_claims(user_id=user_id, now=utc_now())
            return UserRolesResponse(roles=claims.roles)

    async def permissions(self, *, user_id: uuid.UUID) -> UserPermissionsResponse:
        """Return effective global permission codes."""
        async with self._uow:
            users = CurrentUserRepository(self._uow.session)
            if await users.get_by_id(user_id) is None:
                raise NotFoundError("The user was not found.")
            claims = await users.authorization_claims(user_id=user_id, now=utc_now())
            return UserPermissionsResponse(permissions=claims.permissions)


__all__ = ["CurrentUserService"]
