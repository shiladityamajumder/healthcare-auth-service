"""API version-one router registry."""

from __future__ import annotations

from fastapi import APIRouter

from app.modules.router import router as modules_router

router = APIRouter()
router.include_router(modules_router)

__all__ = ["router"]
