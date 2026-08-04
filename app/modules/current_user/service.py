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

from app.auth.identity.presentation import authenticated_user_data
from app.common.exceptions import NotFoundError
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.identity import UserProfiles
from app.modules.current_user.repositories import CurrentUserRepository
from app.modules.current_user.schemas import (
    AuthenticatedUserResponse,
    UpdateCurrentUserRequest,
)

_PROFILE_FIELDS = {
    "first_name",
    "last_name",
    "preferred_name",
    "avatar_file_id",
}


class CurrentUserService:
    """Read and update the authenticated user's identity preferences."""

    def __init__(self, *, uow: SQLAlchemyUnitOfWork) -> None:
        self._uow = uow

    async def get(self, *, user_id: uuid.UUID) -> AuthenticatedUserResponse:
        """Return the current authenticated identity profile."""
        async with self._uow:
            users = CurrentUserRepository(self._uow.session)
            user = await users.get_by_id(user_id)
            if user is None:
                raise NotFoundError("The user was not found.")
            profile = await users.get_active_profile(user.id)
            return AuthenticatedUserResponse.model_validate(
                authenticated_user_data(user, profile=profile)
            )

    async def update(
        self,
        *,
        user_id: uuid.UUID,
        payload: UpdateCurrentUserRequest,
    ) -> AuthenticatedUserResponse:
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
                    avatar_file_id=profile_updates.get("avatar_file_id"),
                    created_by=user.id,
                    updated_by=user.id,
                )
                users.add_profile(profile)
            elif profile is not None and profile_updates:
                for field_name, value in profile_updates.items():
                    setattr(profile, field_name, value)
                profile.updated_by = user.id

            return AuthenticatedUserResponse.model_validate(
                authenticated_user_data(user, profile=profile)
            )


__all__ = ["CurrentUserService"]
