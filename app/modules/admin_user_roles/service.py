"""File: app/modules/admin_user_roles/service.py
User-role assignment application service."""

from __future__ import annotations

import uuid

from app.common.exceptions import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.identity import Roles, UserRoles
from app.modules.admin_user_roles.repositories import UserRoleRepository
from app.modules.admin_user_roles.schemas import (
    AssignUserRoleRequest,
    MessageResponse,
    UpdateUserRoleRequest,
    UserRoleListResponse,
    UserRoleResponse,
)

logger = get_logger(__name__)


def assignment_response(
    assignment: UserRoles,
    role: Roles,
) -> UserRoleResponse:
    """Map assignment and role records to the public contract."""
    return UserRoleResponse(
        id=assignment.id,
        user_id=assignment.user_id,
        role_id=assignment.role_id,
        role_code=role.code,
        role_name=role.name,
        scope_type=assignment.scope_type,
        scope_id=assignment.scope_id,
        valid_from=assignment.valid_from,
        valid_until=assignment.valid_until,
        is_active=assignment.is_active,
        created_at=assignment.created_at,
        updated_at=assignment.updated_at,
    )


class AdminUserRolesService:
    """Manage global and scoped role assignments for users."""

    def __init__(self, *, uow: SQLAlchemyUnitOfWork) -> None:
        self._uow = uow

    async def list_assignments(
        self,
        *,
        user_id: uuid.UUID,
    ) -> UserRoleListResponse:
        """Return all assignments for a user."""
        async with self._uow:
            repository = UserRoleRepository(self._uow.session)
            if not await repository.user_exists(user_id):
                raise NotFoundError("The user was not found.")
            records = await repository.list_for_user(user_id)
            return UserRoleListResponse(
                assignments=[assignment_response(assignment, role) for assignment, role in records]
            )

    async def assign(
        self,
        *,
        user_id: uuid.UUID,
        payload: AssignUserRoleRequest,
        actor_user_id: uuid.UUID,
    ) -> UserRoleResponse:
        """Create one role assignment."""
        async with self._uow:
            repository = UserRoleRepository(self._uow.session)
            if not await repository.user_exists(user_id):
                raise NotFoundError("The user was not found.")
            role = await repository.get_active_role(payload.role_id)
            if role is None:
                raise NotFoundError("The role was not found.")
            assignment = UserRoles(
                user_id=user_id,
                role_id=role.id,
                scope_type=payload.scope_type,
                scope_id=payload.scope_id,
                valid_from=payload.valid_from,
                valid_until=payload.valid_until,
                is_active=payload.is_active,
                created_by=actor_user_id,
                updated_by=actor_user_id,
            )
            repository.add(assignment)
            await self._uow.flush()
            response = assignment_response(assignment, role)
        logger.info(
            "Security audit event",
            extra={
                "event": "user_role_assigned",
                "actor_user_id": str(actor_user_id),
                "target_user_id": str(user_id),
                "assignment_id": str(response.id),
                "role_id": str(response.role_id),
            },
        )
        return response

    async def update(
        self,
        *,
        user_id: uuid.UUID,
        assignment_id: uuid.UUID,
        payload: UpdateUserRoleRequest,
        actor_user_id: uuid.UUID,
    ) -> UserRoleResponse:
        """Update assignment scope, validity, or active state."""
        async with self._uow:
            repository = UserRoleRepository(self._uow.session)
            record = await repository.get_assignment(
                user_id=user_id,
                assignment_id=assignment_id,
                for_update=True,
            )
            if record is None:
                raise NotFoundError("The user-role assignment was not found.")
            assignment, role = record
            updates = payload.model_dump(exclude_unset=True)
            next_valid_from = updates.get("valid_from", assignment.valid_from)
            next_valid_until = updates.get("valid_until", assignment.valid_until)
            if (
                next_valid_from is not None
                and next_valid_until is not None
                and next_valid_until <= next_valid_from
            ):
                raise ValidationError("valid_until must be later than valid_from")
            for field, value in updates.items():
                setattr(assignment, field, value)
            assignment.updated_by = actor_user_id
            response = assignment_response(assignment, role)
        logger.info(
            "Security audit event",
            extra={
                "event": "user_role_updated",
                "actor_user_id": str(actor_user_id),
                "target_user_id": str(user_id),
                "assignment_id": str(assignment_id),
            },
        )
        return response

    async def remove(
        self,
        *,
        user_id: uuid.UUID,
        assignment_id: uuid.UUID,
        actor_user_id: uuid.UUID,
    ) -> MessageResponse:
        """Delete one explicit user-role assignment."""
        async with self._uow:
            repository = UserRoleRepository(self._uow.session)
            record = await repository.get_assignment(
                user_id=user_id,
                assignment_id=assignment_id,
                for_update=True,
            )
            if record is None:
                raise NotFoundError("The user-role assignment was not found.")
            assignment, _ = record
            await repository.delete(assignment)
        logger.info(
            "Security audit event",
            extra={
                "event": "user_role_removed",
                "actor_user_id": str(actor_user_id),
                "target_user_id": str(user_id),
                "assignment_id": str(assignment_id),
            },
        )
        return MessageResponse(message="The user-role assignment has been removed.")


__all__ = ["AdminUserRolesService", "assignment_response"]
