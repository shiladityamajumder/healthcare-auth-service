"""File: app/modules/admin_permissions/service.py
Permission and role-policy application service."""

from __future__ import annotations

import uuid

from sqlalchemy.exc import IntegrityError

from app.common.exceptions import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.identity import Permissions
from app.modules.admin_permissions.repositories import PermissionRepository
from app.modules.admin_permissions.schemas import (
    CreatePermissionRequest,
    MessageResponse,
    PermissionListResponse,
    PermissionResponse,
    ReplaceRolePermissionsRequest,
    RolePermissionsResponse,
    UpdatePermissionRequest,
)
from app.utils.datetime_utils import utc_now

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
    """Manage permission masters and atomically replace role policy sets."""

    def __init__(self, *, uow: SQLAlchemyUnitOfWork) -> None:
        self._uow = uow

    async def list_permissions(self) -> PermissionListResponse:
        """Return all active permissions."""
        async with self._uow:
            records = await PermissionRepository(self._uow.session).list_active()
            return PermissionListResponse(
                permissions=[permission_response(item) for item in records]
            )

    async def create(
        self,
        *,
        payload: CreatePermissionRequest,
        actor_user_id: uuid.UUID,
    ) -> PermissionResponse:
        """Create one active permission with complete audit ownership."""
        try:
            async with self._uow:
                repository = PermissionRepository(self._uow.session)
                if await repository.code_exists(payload.code):
                    raise _permission_code_conflict(payload.code)
                permission = Permissions(
                    code=payload.code,
                    resource=payload.resource,
                    action=payload.action,
                    description=payload.description,
                    created_by=actor_user_id,
                    updated_by=actor_user_id,
                )
                repository.add(permission)
                await self._uow.flush()
                response = permission_response(permission)
        except IntegrityError as exc:
            # The partial unique index remains authoritative when two create
            # requests race after both pass the friendly existence check.
            raise _permission_code_conflict(payload.code) from exc
        logger.info(
            "Security audit event",
            extra={
                "event": "permission_created",
                "actor_user_id": str(actor_user_id),
                "permission_id": str(response.id),
                "permission_code": response.code,
            },
        )
        return response

    async def get(self, *, permission_id: uuid.UUID) -> PermissionResponse:
        """Return one active permission master record."""
        async with self._uow:
            permission = await PermissionRepository(self._uow.session).get_active(permission_id)
            if permission is None:
                raise NotFoundError("The permission was not found.")
            return permission_response(permission)

    async def update(
        self,
        *,
        permission_id: uuid.UUID,
        payload: UpdatePermissionRequest,
        actor_user_id: uuid.UUID,
    ) -> PermissionResponse:
        """Apply supplied fields while preserving active-code uniqueness."""
        try:
            async with self._uow:
                repository = PermissionRepository(self._uow.session)
                permission = await repository.get_active(
                    permission_id,
                    for_update=True,
                )
                if permission is None:
                    raise NotFoundError("The permission was not found.")
                updates = payload.model_dump(exclude_unset=True)
                new_code = updates.get("code")
                if new_code and await repository.code_exists(
                    str(new_code),
                    exclude_permission_id=permission.id,
                ):
                    raise _permission_code_conflict(str(new_code))
                for field, value in updates.items():
                    setattr(permission, field, value)
                permission.updated_by = actor_user_id
                await self._uow.flush()
                response = permission_response(permission)
        except IntegrityError as exc:
            code = payload.code or "requested"
            raise _permission_code_conflict(code) from exc
        logger.info(
            "Security audit event",
            extra={
                "event": "permission_updated",
                "actor_user_id": str(actor_user_id),
                "permission_id": str(permission_id),
                "permission_code": response.code,
            },
        )
        return response

    async def delete(
        self,
        *,
        permission_id: uuid.UUID,
        actor_user_id: uuid.UUID,
    ) -> MessageResponse:
        """Soft-delete a permission while retaining its audit history."""
        async with self._uow:
            permission = await PermissionRepository(self._uow.session).get_active(
                permission_id,
                for_update=True,
            )
            if permission is None:
                raise NotFoundError("The permission was not found.")
            now = utc_now()
            permission.is_deleted = True
            permission.deleted_at = now
            permission.deleted_by = actor_user_id
            permission.updated_by = actor_user_id
        logger.info(
            "Security audit event",
            extra={
                "event": "permission_deleted",
                "actor_user_id": str(actor_user_id),
                "permission_id": str(permission_id),
                "permission_code": permission.code,
            },
        )
        return MessageResponse(message="The permission has been deleted.")

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
            missing_ids = [str(item) for item in payload.permission_ids if item not in found_ids]
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


def _permission_code_conflict(code: str) -> ConflictError:
    """Build one consistent, client-safe duplicate-code error."""
    return ConflictError(
        "An active permission with this code already exists.",
        details={"code": code},
        code="PERMISSION_CODE_ALREADY_EXISTS",
    )


__all__ = ["AdminPermissionsService", "permission_response"]
