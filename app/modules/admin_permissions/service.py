"""Permission and role-policy application service."""

from __future__ import annotations

import uuid

from app.common.exceptions import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.identity import Permissions
from app.modules.admin_permissions.repositories import PermissionRepository
from app.modules.admin_permissions.schemas import (
    PermissionListResponse,
    PermissionResponse,
    ReplaceRolePermissionsRequest,
    RolePermissionsResponse,
)

logger = get_logger(__name__)


def permission_response(permission: Permissions) -> PermissionResponse:
    """Map an ORM permission to the public administrative contract."""
    return PermissionResponse(
        id=permission.id,
        code=permission.code,
        resource=permission.resource,
        action=permission.action,
        description=permission.description,
        created_at=permission.created_at,
        updated_at=permission.updated_at,
    )


class AdminPermissionsService:
    """Read permissions and atomically replace role permission sets."""

    def __init__(self, *, uow: SQLAlchemyUnitOfWork) -> None:
        self._uow = uow

    async def list_permissions(self) -> PermissionListResponse:
        """Return all active permissions."""
        async with self._uow:
            records = await PermissionRepository(self._uow.session).list_active()
            return PermissionListResponse(
                permissions=[permission_response(item) for item in records]
            )

    async def role_permissions(
        self,
        *,
        role_id: uuid.UUID,
    ) -> RolePermissionsResponse:
        """Return the complete active permission set for a role."""
        async with self._uow:
            repository = PermissionRepository(self._uow.session)
            if await repository.get_role(role_id) is None:
                raise NotFoundError("The role was not found.")
            records = await repository.list_for_role(role_id)
            return RolePermissionsResponse(
                role_id=role_id,
                permissions=[permission_response(item) for item in records],
            )

    async def replace_role_permissions(
        self,
        *,
        role_id: uuid.UUID,
        payload: ReplaceRolePermissionsRequest,
        actor_user_id: uuid.UUID,
    ) -> RolePermissionsResponse:
        """Validate and atomically replace a role's permission mappings."""
        async with self._uow:
            repository = PermissionRepository(self._uow.session)
            if await repository.get_role(role_id, for_update=True) is None:
                raise NotFoundError("The role was not found.")
            permissions = await repository.get_active_by_ids(payload.permission_ids)
            found_ids = {item.id for item in permissions}
            missing_ids = [
                str(item) for item in payload.permission_ids if item not in found_ids
            ]
            if missing_ids:
                raise ValidationError(
                    "One or more permissions do not exist or are deleted.",
                    details={"missing_permission_ids": missing_ids},
                )
            await repository.replace_role_permissions(
                role_id=role_id,
                permission_ids=payload.permission_ids,
                actor_user_id=actor_user_id,
            )
            ordered = sorted(permissions, key=lambda item: item.code)
            response = RolePermissionsResponse(
                role_id=role_id,
                permissions=[permission_response(item) for item in ordered],
            )
        logger.info(
            "Security audit event",
            extra={
                "event": "role_permissions_replaced",
                "actor_user_id": str(actor_user_id),
                "role_id": str(role_id),
                "permission_count": len(payload.permission_ids),
            },
        )
        return response


__all__ = ["AdminPermissionsService", "permission_response"]
