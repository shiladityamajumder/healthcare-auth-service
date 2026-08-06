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
from fastapi.testclient import TestClient
from tests.conftest import build_test_settings

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
    "/api/v1/auth/capabilities",
    "/api/v1/auth/.well-known/jwks.json",
    "/api/v1/auth/logout",
    "/api/v1/auth/logout/others",
    "/api/v1/auth/logout/all",
    "/api/v1/auth/users/me/authorization",
    "/api/v1/auth/sessions",
    "/api/v1/auth/sessions/{sessionId}",
    "/api/v1/auth/password/forgot",
    "/api/v1/auth/password/reset/verify-otp",
    "/api/v1/auth/password/reset",
    "/api/v1/auth/password",
    "/api/v1/users/me",
    "/api/v1/admin/users",
    "/api/v1/admin/users/{userId}",
    "/api/v1/admin/users/{userId}/status",
    "/api/v1/admin/users/{userId}/logout-all",
    "/api/v1/admin/roles",
    "/api/v1/admin/roles/{roleId}",
    "/api/v1/admin/permissions",
    "/api/v1/admin/permissions/{permissionId}",
    "/api/v1/admin/roles/{roleId}/permissions",
    "/api/v1/admin/users/{userId}/roles",
    "/api/v1/admin/users/{userId}/roles/{userRoleId}",
}


def test_vertical_identity_routes_and_security_contract_are_exposed() -> None:
    """Protect the public route inventory and Swagger bearer scheme."""
    schema = create_app().openapi()
    paths = set(schema["paths"])

    assert {path for path in paths if path.startswith("/api/v1/")} == EXPECTED_IDENTITY_PATHS
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
    refresh = schema["paths"]["/api/v1/auth/token/refresh"]["post"]

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
    refresh_headers = headers(refresh)

    assert set(rate_headers) == {"X-Client-ID", "X-Device-ID"}
    assert set(login_headers) == {
        "X-Client-ID",
        "X-Platform",
        "X-Device-ID",
        "X-Device-Type",
    }
    assert protected_headers == {}
    assert set(refresh_headers) == {"X-Client-ID", "X-Device-ID"}

    for operation_headers in (rate_headers, login_headers, refresh_headers):
        assert all(item["required"] is False for item in operation_headers.values())

    assert "body" not in login_headers["X-Device-ID"]["description"].lower()
    assert "body" not in login_headers["X-Device-Type"]["description"].lower()

    # Swagger obtains Authorization through its BearerAuth Authorize dialog,
    # not through a duplicated free-text header parameter.
    assert protected["security"] == [{"BearerAuth": []}]
    assert "security" not in login


def test_role_and_permission_headers_are_never_authorization_inputs() -> None:
    """Prevent Swagger or routes from accepting client-supplied RBAC headers."""
    schema = create_app().openapi()
    forbidden = {
        "x-role",
        "x-roles",
        "x-permission",
        "x-permissions",
        "x-user-id",
        "x-session-id",
        "x-client-version",
        "x-device-name",
        "idempotency-key",
    }

    for path_item in schema["paths"].values():
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            parameters = operation.get("parameters", [])
            header_names = {
                str(parameter.get("name", "")).casefold()
                for parameter in parameters
                if isinstance(parameter, dict) and parameter.get("in") == "header"
            }
            assert forbidden.isdisjoint(header_names)


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


def test_public_registration_contract_does_not_expose_role_assignment() -> None:
    """Keep arbitrary role assignment out of both anonymous request schemas."""
    schema = create_app().openapi()
    components = schema["components"]["schemas"]

    for schema_name in (
        "EmailPasswordRegistrationRequest",
        "PhoneOtpRegistrationVerifyRequest",
    ):
        properties = components[schema_name].get("properties", {})
        assert "roles" not in properties, schema_name


def test_authorization_contract_is_single_and_redundant_routes_are_removed() -> None:
    """Publish one protected authorization DTO and no duplicate projections."""
    schema = create_app().openapi()
    paths = schema["paths"]
    authorization = paths["/api/v1/auth/users/me/authorization"]["get"]

    assert authorization["security"] == [{"BearerAuth": []}]
    assert authorization.get("deprecated") is not True
    assert "/api/v1/users/me/roles" not in paths
    assert "/api/v1/users/me/permissions" not in paths

    properties = schema["components"]["schemas"]["CurrentAuthorizationResponse"]["properties"]
    assert set(properties) == {"roles", "permissions"}


def test_every_token_response_uses_one_minimal_profile_contract() -> None:
    """Expose one token pair and one authorization-free user schema."""
    schemas = create_app().openapi()["components"]["schemas"]
    user = schemas["AuthenticatedUserResponse"]["properties"]

    assert "roles" not in user
    assert "permissions" not in user
    assert "TokenPairResponse" in schemas
    assert not any("V1" in name or "V2" in name for name in schemas)
    assert schemas["TokenPairResponse"]["properties"]["user"]["$ref"].endswith(
        "/AuthenticatedUserResponse"
    )
    assert schemas["RegistrationResponse"]["properties"]["user"]["$ref"].endswith(
        "/AuthenticatedUserResponse"
    )
    profile = schemas["UserProfileResponse"]["properties"]
    avatar = profile["avatar"]["anyOf"][0]
    public_file = schemas["PublicFileResponse"]["properties"]

    assert avatar["$ref"].endswith("/PublicFileResponse")
    assert set(public_file) == {"id", "url"}
    assert "avatar_file_id" not in profile
    assert {"object_key", "bucket", "encryption_key_ref"}.isdisjoint(public_file)


def test_all_token_producing_surfaces_share_the_token_pair_contract() -> None:
    """Require every token-producing route to publish the same response model."""
    schema = create_app().openapi()
    paths = schema["paths"]

    assert (
        paths["/api/v1/auth/email-verification/verify"]["post"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        == "#/components/schemas/APIResponseModel_TokenPairResponse_"
    )
    assert (
        paths["/api/v1/auth/register/phone/verify-otp"]["post"]["responses"]["201"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        == "#/components/schemas/APIResponseModel_TokenPairResponse_"
    )
    assert (
        paths["/api/v1/auth/password/reset"]["post"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        == "#/components/schemas/APIResponseModel_TokenPairResponse_"
    )
    assert (
        paths["/api/v1/users/me"]["get"]["responses"]["200"]["content"]["application/json"][
            "schema"
        ]["$ref"]
        == "#/components/schemas/APIResponseModel_AuthenticatedUserResponse_"
    )


def test_public_capabilities_are_anonymous_and_do_not_publish_authorization() -> None:
    schema = create_app().openapi()
    operation = schema["paths"]["/api/v1/auth/capabilities"]["get"]
    properties = schema["components"]["schemas"]["AuthCapabilitiesResponse"]["properties"]

    assert "security" not in operation
    assert {"roles", "permissions"}.isdisjoint(properties)
    assert {"schema", "registration", "login", "verification", "passwordPolicy"} <= set(properties)


def test_public_capabilities_work_and_removed_authorization_routes_are_404() -> None:
    app = create_app(build_test_settings())
    with TestClient(app) as client:
        assert client.get("/api/v1/auth/capabilities").status_code == 200
        assert client.get("/api/v1/users/me/roles").status_code == 404
        assert client.get("/api/v1/users/me/permissions").status_code == 404


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
    assert {"get", "patch", "delete"}.issubset(paths["/api/v1/admin/roles/{roleId}"])
    assert {"get", "put"}.issubset(paths["/api/v1/admin/roles/{roleId}/permissions"])
    assert {"get", "post"}.issubset(paths["/api/v1/admin/permissions"])
    assert {"get", "patch", "delete"}.issubset(paths["/api/v1/admin/permissions/{permissionId}"])


def test_external_contract_names_are_camel_case() -> None:
    """Prevent snake_case Python names from leaking into the public OpenAPI contract."""
    schema = create_app().openapi()

    for component in schema.get("components", {}).get("schemas", {}).values():
        assert all("_" not in name for name in component.get("properties", {}))

    for path, path_item in schema["paths"].items():
        assert "_" not in path
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            assert all("_" not in item["name"] for item in operation.get("parameters", []))


def test_no_anonymous_role_or_permission_catalog_is_exposed() -> None:
    """Require authentication for every role/permission catalog operation."""
    schema = create_app().openapi()

    for path, path_item in schema["paths"].items():
        if "/roles" not in path and "/permissions" not in path:
            continue
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            assert operation["security"] == [{"BearerAuth": []}], (path, method)


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
