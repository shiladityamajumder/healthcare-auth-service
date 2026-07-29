"""Shared authentication infrastructure used by vertical identity modules."""

from app.auth.context import AuthRequestContext
from app.auth.principals import UserPrincipal
from app.auth.runtime import AuthRuntime

__all__ = ["AuthRequestContext", "AuthRuntime", "UserPrincipal"]
