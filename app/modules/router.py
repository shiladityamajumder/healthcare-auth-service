"""File: app/modules/router.py
Version-independent registry of vertical identity modules."""

from __future__ import annotations

from fastapi import APIRouter

from app.modules.admin_permissions.routes import (
    permissions_router,
    role_permissions_router,
)
from app.modules.admin_roles.routes import router as admin_roles_router
from app.modules.admin_user_roles.routes import router as admin_user_roles_router
from app.modules.admin_users.routes import router as admin_users_router
from app.modules.current_user.routes import router as current_user_router
from app.modules.email_verification.routes import router as email_verification_router
from app.modules.login.routes import router as login_router
from app.modules.password_management.routes import router as password_router
from app.modules.registration.routes import router as registration_router
from app.modules.session_management.routes import router as session_router
from app.modules.token_management.routes import router as token_router

router = APIRouter()

for child_router in (
    registration_router,
    email_verification_router,
    login_router,
    token_router,
    session_router,
    password_router,
    current_user_router,
    admin_users_router,
    admin_roles_router,
    permissions_router,
    role_permissions_router,
    admin_user_roles_router,
):
    router.include_router(child_router)


__all__ = ["router"]
