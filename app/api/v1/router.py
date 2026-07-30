"""File: app/api/v1/router.py

Purpose:
Registers all vertical module routers beneath the version-one API router.

Dependency flow:
Application composition
-> version-one APIRouter
-> modules router registry
-> module route trees
"""

from __future__ import annotations

from fastapi import APIRouter

from app.modules.router import router as modules_router

router = APIRouter()
router.include_router(modules_router)

__all__ = ["router"]
