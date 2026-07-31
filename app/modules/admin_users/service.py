"""File: app/modules/admin_users/service.py

Purpose:
Owns administrative user listing, detail projection, status transitions, and
global session-revocation use cases.

Dependency flow:
AdminUsersServiceDep
-> request-scoped SQLAlchemyUnitOfWork
-> AdminUserRepository on the shared session
-> invariant checks and ORM mutations
-> unit-of-work commit/rollback
-> response contract
"""

from __future__ import annotations

import uuid

from app.auth.identity.presentation import admin_user_data
from app.common.exceptions import ConflictError, NotFoundError
from app.common.response import PaginationMeta
from app.core.logging import get_logger
from app.core.pagination import PaginationParams, PaginationResult
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.enums import UserStatus
from app.models.identity import Users
from app.modules.admin_users.repositories import AdminUserRepository
from app.modules.admin_users.schemas import (
    AdminLogoutAllRequest,
    AdminUserListResponse,
    AdminUserResponse,
    MessageResponse,
    UpdateUserStatusRequest,
)
from app.utils.datetime_utils import utc_now

logger = get_logger(__name__)


class AdminUsersService:
    """Manage user status and sessions through permission-protected workflows."""

    def __init__(self, *, uow: SQLAlchemyUnitOfWork) -> None:
        self._uow = uow

    async def list_users(
        self,
        *,
        pagination: PaginationParams,
        search: str | None,
        status: UserStatus | None,
    ) -> tuple[AdminUserListResponse, PaginationMeta]:
        """Return a page of users with effective authorization claims."""
        async with self._uow:
            repository = AdminUserRepository(self._uow.session)
            page: PaginationResult[Users] = await repository.list(
                pagination=pagination,
                search=search,
                status=status,
            )
            profiles = await repository.active_profiles_by_user_ids(
                [user.id for user in page.items]
            )
            now = utc_now()
            items: list[AdminUserResponse] = []
            for user in page.items:
                claims = await repository.authorization_claims(
                    user_id=user.id,
                    now=now,
                )
                items.append(
                    AdminUserResponse.model_validate(
                        admin_user_data(
                            user,
                            profile=profiles.get(user.id),
                            roles=claims.roles,
                            permissions=claims.permissions,
                        )
                    )
                )
            return AdminUserListResponse(users=items), page.pagination

    async def get_user(self, *, user_id: uuid.UUID) -> AdminUserResponse:
        """Return one user and effective authorization claims."""
        async with self._uow:
            repository = AdminUserRepository(self._uow.session)
            user = await repository.get_by_id(user_id)
            if user is None:
                raise NotFoundError("The user was not found.")
            profile = await repository.get_active_profile(user.id)
            claims = await repository.authorization_claims(
                user_id=user.id,
                now=utc_now(),
            )
            return AdminUserResponse.model_validate(
                admin_user_data(
                    user,
                    profile=profile,
                    roles=claims.roles,
                    permissions=claims.permissions,
                )
            )

    async def update_status(
        self,
        *,
        user_id: uuid.UUID,
        payload: UpdateUserStatusRequest,
        actor_user_id: uuid.UUID,
    ) -> AdminUserResponse:
        """Apply a validated status transition and optionally revoke sessions."""
        if user_id == actor_user_id and payload.status != UserStatus.ACTIVE:
            raise ConflictError("Administrators cannot disable their own account here.")
        async with self._uow:
            repository = AdminUserRepository(self._uow.session)
            user = await repository.get_by_id(user_id, for_update=True)
            if user is None:
                raise NotFoundError("The user was not found.")
            user.status = payload.status
            if payload.status == UserStatus.ACTIVE:
                user.locked_until = None
                user.failed_login_count = 0
            if payload.status == UserStatus.CLOSED:
                user.account_closed_at = user.account_closed_at or utc_now()
            elif user.account_closed_at is not None:
                user.account_closed_at = None
            if payload.revoke_sessions and payload.status != UserStatus.ACTIVE:
                await repository.revoke_user_sessions(
                    user_id=user.id,
                    revoked_at=utc_now(),
                    reason=f"admin_status_{payload.status.value}",
                )
            profile = await repository.get_active_profile(user.id)
            claims = await repository.authorization_claims(
                user_id=user.id,
                now=utc_now(),
            )
            response = AdminUserResponse.model_validate(
                admin_user_data(
                    user,
                    profile=profile,
                    roles=claims.roles,
                    permissions=claims.permissions,
                )
            )
        logger.info(
            "Security audit event",
            extra={
                "event": "admin_user_status_changed",
                "actor_user_id": str(actor_user_id),
                "target_user_id": str(user_id),
                "new_status": payload.status.value,
                "reason": payload.reason,
            },
        )
        return response

    async def logout_all(
        self,
        *,
        user_id: uuid.UUID,
        payload: AdminLogoutAllRequest,
        actor_user_id: uuid.UUID,
    ) -> MessageResponse:
        """Revoke every active session for a target user."""
        async with self._uow:
            repository = AdminUserRepository(self._uow.session)
            if await repository.get_by_id(user_id) is None:
                raise NotFoundError("The user was not found.")
            await repository.revoke_user_sessions(
                user_id=user_id,
                revoked_at=utc_now(),
                reason=payload.reason,
            )
        logger.info(
            "Security audit event",
            extra={
                "event": "admin_user_logout_all",
                "actor_user_id": str(actor_user_id),
                "target_user_id": str(user_id),
                "reason": payload.reason,
            },
        )
        return MessageResponse(message="All user sessions have been revoked.")


__all__ = ["AdminUsersService"]
