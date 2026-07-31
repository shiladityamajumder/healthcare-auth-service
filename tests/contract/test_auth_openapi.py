"""File: tests/contract/test_auth_openapi.py

Purpose:
Protects authentication OpenAPI, header exposure, route-method, and declarative
security-policy contracts.

Dependency flow:
create_app(test settings)
-> generated OpenAPI or recursive APIRoute tree
-> dependency/security metadata inspection
-> architectural assertions
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from app.auth.request_context.dependencies import get_current_user_principal
from app.auth.route_security import route_security_policy
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.main import create_app
from app.modules.router import router as modules_router
from fastapi.routing import APIRoute

EXPECTED_IDENTITY_PATHS = {
    "/api/v1/auth/register/email",
    "/api/v1/auth/register/phone/request-otp",
    "/api/v1/auth/register/phone/verify-otp",
    "/api/v1/auth/email-verification/request",
    "/api/v1/auth/email-verification/verify",
    "/api/v1/auth/login/password",
    "/api/v1/auth/login/phone/request-otp",
    "/api/v1/auth/login/phone/verify-otp",
    "/api/v1/auth/token/refresh",
    "/api/v1/auth/logout",
    "/api/v1/auth/logout/others",
    "/api/v1/auth/logout/all",
    "/api/v1/auth/sessions",
    "/api/v1/auth/sessions/{session_id}",
    "/api/v1/auth/password/forgot",
    "/api/v1/auth/password/reset/verify-otp",
    "/api/v1/auth/password/reset",
    "/api/v1/auth/password",
    "/api/v1/users/me",
    "/api/v1/users/me/roles",
    "/api/v1/users/me/permissions",
    "/api/v1/admin/users",
    "/api/v1/admin/users/{user_id}",
    "/api/v1/admin/users/{user_id}/status",
    "/api/v1/admin/users/{user_id}/logout-all",
    "/api/v1/admin/roles",
    "/api/v1/admin/roles/{role_id}",
    "/api/v1/admin/permissions",
    "/api/v1/admin/permissions/{permission_id}",
    "/api/v1/admin/roles/{role_id}/permissions",
    "/api/v1/admin/users/{user_id}/roles",
    "/api/v1/admin/users/{user_id}/roles/{user_role_id}",
}


def test_vertical_identity_routes_and_security_contract_are_exposed() -> None:
    """Protect the public route inventory and Swagger bearer scheme."""
    schema = create_app().openapi()
    paths = set(schema["paths"])

    assert EXPECTED_IDENTITY_PATHS.issubset(paths)
    assert not any("/mfa" in path for path in paths)

    security_schemes = schema["components"]["securitySchemes"]
    assert security_schemes["BearerAuth"]["type"] == "http"
    assert security_schemes["BearerAuth"]["scheme"] == "bearer"


def test_auth_metadata_headers_are_narrow_and_non_authoritative() -> None:
    """Keep header profiles minimal and prevent metadata from acting as auth."""
    schema = create_app().openapi()
    rate_limited = schema["paths"]["/api/v1/auth/login/phone/request-otp"]["post"]
    login = schema["paths"]["/api/v1/auth/login/password"]["post"]
    protected = schema["paths"]["/api/v1/auth/sessions"]["get"]

    def headers(operation: dict[str, object]) -> dict[str, dict[str, Any]]:
        parameters = operation.get("parameters", [])
        assert isinstance(parameters, list)
        return {
            item["name"]: item
            for item in parameters
            if isinstance(item, dict) and item.get("in") == "header"
        }

    rate_headers = headers(rate_limited)
    login_headers = headers(login)
    protected_headers = headers(protected)

    assert set(rate_headers) == {"X-Client-ID", "X-Device-ID"}
    assert set(login_headers) == {
        "X-Client-ID",
        "X-Platform",
        "X-Device-ID",
        "X-Device-Type",
    }
    assert set(protected_headers) == {"X-Device-ID", "X-User-ID", "X-Session-ID"}

    for operation_headers in (rate_headers, login_headers, protected_headers):
        assert all(item["required"] is False for item in operation_headers.values())

    assert "consistency assertion" in protected_headers["X-User-ID"]["description"].lower()
    assert "consistency assertion" in protected_headers["X-Session-ID"]["description"].lower()
    assert "body" not in login_headers["X-Device-ID"]["description"].lower()
    assert "body" not in login_headers["X-Device-Type"]["description"].lower()

    # Swagger obtains Authorization through its BearerAuth Authorize dialog,
    # not through a duplicated free-text header parameter.
    assert protected["security"] == [{"BearerAuth": []}]
    assert "security" not in login


def test_session_device_metadata_is_header_only() -> None:
    """Keep session device metadata out of authentication request bodies."""
    schema = create_app().openapi()
    components = schema["components"]["schemas"]
    device_fields = {
        "device_id",
        "device_type",
        "device_name",
        "device_fingerprint",
    }
    request_schemas = (
        "EmailPasswordRegistrationRequest",
        "PhoneOtpRegistrationVerifyRequest",
        "PasswordLoginRequest",
        "PhoneOtpLoginVerifyRequest",
        "EmailVerificationConfirmRequest",
        "ResetPasswordWithTokenRequest",
        "ChangePasswordRequest",
        "SetPasswordRequest",
        "RefreshTokenRequest",
    )

    for schema_name in request_schemas:
        properties = components[schema_name].get("properties", {})
        assert device_fields.isdisjoint(properties), schema_name


def test_auth_operations_publish_unified_error_responses() -> None:
    """Require documented error envelopes for authentication operations."""
    schema = create_app().openapi()
    operation = schema["paths"]["/api/v1/auth/login/password"]["post"]
    for status_code in (
        "400",
        "401",
        "403",
        "404",
        "409",
        "422",
        "429",
        "500",
        "503",
        "504",
    ):
        assert status_code in operation["responses"]


def test_password_and_role_paths_publish_expected_methods() -> None:
    """Protect the intended HTTP methods on password and RBAC resources."""
    schema = create_app().openapi()
    paths = schema["paths"]

    assert {"put", "post"}.issubset(paths["/api/v1/auth/password"])
    assert {"get", "post"}.issubset(paths["/api/v1/admin/roles"])
    assert {"get", "patch", "delete"}.issubset(paths["/api/v1/admin/roles/{role_id}"])
    assert {"get", "put"}.issubset(paths["/api/v1/admin/roles/{role_id}/permissions"])
    assert {"get", "post"}.issubset(paths["/api/v1/admin/permissions"])
    assert {"get", "patch", "delete"}.issubset(paths["/api/v1/admin/permissions/{permission_id}"])


def test_every_bearer_protected_module_route_has_declarative_security() -> None:
    """Prevent protected endpoints from bypassing composed route policy.

    FastAPI's included routers are lazy in this version, so the recursive
    dependency tree is inspected for both the bearer resolver and policy marker.
    """
    protected_route_names: list[str] = []

    for route in _iter_api_routes(modules_router.routes):
        calls = tuple(_dependency_calls(route.dependant))
        if get_current_user_principal not in calls:
            continue

        protected_route_names.append(route.name)
        assert any(route_security_policy(call) is not None for call in calls), route.name

    assert protected_route_names


def test_route_security_uses_risk_based_rate_limit_profiles() -> None:
    """Protect representative read/write route assignments to risk tiers."""
    policies: dict[str, RouteSecurityPolicy] = {}

    for route in _iter_api_routes(modules_router.routes):
        for call in _dependency_calls(route.dependant):
            policy = route_security_policy(call)
            if policy is not None:
                policies[route.name] = policy

    assert policies["list_users"].rate_limit is RateLimitPolicy.ADMIN_READ
    assert policies["update_user_status"].rate_limit is RateLimitPolicy.ADMIN_WRITE
    assert policies["get_current_user"].rate_limit is RateLimitPolicy.STANDARD
    assert policies["update_current_user"].rate_limit is RateLimitPolicy.SENSITIVE
    assert policies["list_sessions"].rate_limit is RateLimitPolicy.STANDARD
    assert policies["revoke_session"].rate_limit is RateLimitPolicy.SENSITIVE
    assert policies["logout_all"].rate_limit is RateLimitPolicy.SENSITIVE


def _iter_api_routes(routes: Iterable[object]) -> Iterator[APIRoute]:
    """Traverse FastAPI's lazy included-router structure."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
            continue
        original_router = getattr(route, "original_router", None)
        nested_routes = getattr(original_router, "routes", None)
        if isinstance(nested_routes, list):
            yield from _iter_api_routes(nested_routes)


def _dependency_calls(dependant: object) -> Iterator[object]:
    """Yield every callable in one FastAPI dependency tree."""
    call = getattr(dependant, "call", None)
    if call is not None:
        yield call
    dependencies = getattr(dependant, "dependencies", ())
    for child in dependencies:
        yield from _dependency_calls(child)
