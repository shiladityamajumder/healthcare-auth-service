"""File: app/modules/admin_roles/service.py

Purpose:
Owns active-role CRUD use cases, uniqueness checks, and system-role mutation
invariants.

Dependency flow:
AdminRolesServiceDep
-> request-scoped SQLAlchemyUnitOfWork
-> RoleRepository on the shared session
-> invariant checks and staged ORM changes
-> unit-of-work commit/rollback
-> role response contract
"""

from __future__ import annotations

import uuid

from app.common.exceptions import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.identity import Roles
from app.modules.admin_roles.repositories import RoleRepository
from app.modules.admin_roles.schemas import (
    CreateRoleRequest,
    MessageResponse,
    RoleListResponse,
    RoleResponse,
    UpdateRoleRequest,
)
from app.utils.datetime_utils import utc_now

logger = get_logger(__name__)


def role_response(role: Roles) -> RoleResponse:
    """Map an ORM role to the public administrative contract."""
    return RoleResponse(
        id=role.id,
        code=role.code,
        name=role.name,
        description=role.description,
        is_system=role.is_system,
        created_at=role.created_at,
        updated_at=role.updated_at,
    )


class AdminRolesService:
    """Create, read, update, and soft-delete RBAC roles."""

    def __init__(self, *, uow: SQLAlchemyUnitOfWork) -> None:
        self._uow = uow

    async def list_roles(self) -> RoleListResponse:
        """Return all active roles."""
        async with self._uow:
            roles = await RoleRepository(self._uow.session).list_active()
            return RoleListResponse(roles=[role_response(item) for item in roles])

    async def create(
        self,
        *,
        payload: CreateRoleRequest,
        actor_user_id: uuid.UUID,
    ) -> RoleResponse:
        """Create a custom role with an immutable initial audit actor."""
        async with self._uow:
            repository = RoleRepository(self._uow.session)
            if await repository.code_exists(payload.code):
                raise ConflictError("An active role with this code already exists.")
            role = Roles(
                code=payload.code,
                name=payload.name,
                description=payload.description,
                is_system=False,
                created_by=actor_user_id,
                updated_by=actor_user_id,
            )
            repository.add(role)
            # Flush assigns database-generated state for the response while the
            # unit of work retains commit control.
            await self._uow.flush()
            response = role_response(role)
        logger.info(
            "Security audit event",
            extra={
                "event": "role_created",
                "actor_user_id": str(actor_user_id),
                "role_id": str(response.id),
                "role_code": response.code,
            },
        )
        return response

    async def get(self, *, role_id: uuid.UUID) -> RoleResponse:
        """Return one active role."""
        async with self._uow:
            role = await RoleRepository(self._uow.session).get_active(role_id)
            if role is None:
                raise NotFoundError("The role was not found.")
            return role_response(role)

    async def update(
        self,
        *,
        role_id: uuid.UUID,
        payload: UpdateRoleRequest,
        actor_user_id: uuid.UUID,
    ) -> RoleResponse:
        """Update an active role while protecting system role codes."""
        async with self._uow:
            repository = RoleRepository(self._uow.session)
            role = await repository.get_active(role_id, for_update=True)
            if role is None:
                raise NotFoundError("The role was not found.")
            updates = payload.model_dump(exclude_unset=True)
            if role.is_system and "code" in updates and updates["code"] != role.code:
                raise ConflictError("System role codes cannot be changed.")
            new_code = updates.get("code")
            if new_code and await repository.code_exists(
                str(new_code),
                exclude_role_id=role.id,
            ):
                raise ConflictError("An active role with this code already exists.")
            for field, value in updates.items():
                setattr(role, field, value)
            role.updated_by = actor_user_id
            response = role_response(role)
        logger.info(
            "Security audit event",
            extra={
                "event": "role_updated",
                "actor_user_id": str(actor_user_id),
                "role_id": str(role_id),
            },
        )
        return response

    async def delete(
        self,
        *,
        role_id: uuid.UUID,
        actor_user_id: uuid.UUID,
    ) -> MessageResponse:
        """Soft-delete a custom role."""
        async with self._uow:
            role = await RoleRepository(self._uow.session).get_active(
                role_id,
                for_update=True,
            )
            if role is None:
                raise NotFoundError("The role was not found.")
            if role.is_system:
                raise ConflictError("System roles cannot be deleted.")
            now = utc_now()
            role.is_deleted = True
            role.deleted_at = now
            role.deleted_by = actor_user_id
            role.updated_by = actor_user_id
        logger.info(
            "Security audit event",
            extra={
                "event": "role_deleted",
                "actor_user_id": str(actor_user_id),
                "role_id": str(role_id),
            },
        )
        return MessageResponse(message="The role has been deleted.")


__all__ = ["AdminRolesService", "role_response"]
