"""File: tests/contract/test_auth_openapi.py"""

from __future__ import annotations

from app.main import create_app

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
    schema = create_app().openapi()
    paths = set(schema["paths"])

    assert EXPECTED_IDENTITY_PATHS.issubset(paths)
    assert not any("/mfa" in path for path in paths)

    security_schemes = schema["components"]["securitySchemes"]
    assert security_schemes["BearerAuth"]["type"] == "http"
    assert security_schemes["BearerAuth"]["scheme"] == "bearer"


def test_auth_metadata_headers_are_narrow_and_non_authoritative() -> None:
    schema = create_app().openapi()
    rate_limited = schema["paths"]["/api/v1/auth/login/phone/request-otp"]["post"]
    login = schema["paths"]["/api/v1/auth/login/password"]["post"]
    protected = schema["paths"]["/api/v1/auth/sessions"]["get"]

    def headers(operation: dict[str, object]) -> dict[str, dict[str, object]]:
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

    # Swagger obtains Authorization through its BearerAuth Authorize dialog,
    # not through a duplicated free-text header parameter.
    assert protected["security"] == [{"BearerAuth": []}]
    assert "security" not in login


def test_auth_operations_publish_unified_error_responses() -> None:
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
    schema = create_app().openapi()
    paths = schema["paths"]

    assert {"put", "post"}.issubset(paths["/api/v1/auth/password"])
    assert {"get", "post"}.issubset(paths["/api/v1/admin/roles"])
    assert {"get", "patch", "delete"}.issubset(paths["/api/v1/admin/roles/{role_id}"])
    assert {"get", "put"}.issubset(paths["/api/v1/admin/roles/{role_id}/permissions"])
    assert {"get", "post"}.issubset(paths["/api/v1/admin/permissions"])
    assert {"get", "patch", "delete"}.issubset(paths["/api/v1/admin/permissions/{permission_id}"])
