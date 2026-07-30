"""File: tests/unit/test_identity_master_seed.py

Purpose:
Protects the healthcare-commerce RBAC seed manifest and its least-privilege
separation between customer, clinical, operational, and security roles.

Dependency flow:
Static seed manifest
-> manifest validation
-> role/permission contract assertions
"""

from __future__ import annotations

from scripts.seed_identity_master_data import (
    ALL_PERMISSION_CODES,
    ROLE_SEEDS,
    validate_seed_manifest,
)


def _role_permissions(role_code: str) -> frozenset[str]:
    return next(seed.permission_codes for seed in ROLE_SEEDS if seed.code == role_code)


def test_identity_master_seed_manifest_is_valid() -> None:
    validate_seed_manifest()


def test_every_mutating_grant_includes_the_matching_read_grant() -> None:
    for role in ROLE_SEEDS:
        for permission_code in role.permission_codes:
            resource, _, action = permission_code.rpartition(".")
            if action != "read" and f"{resource}.read" in ALL_PERMISSION_CODES:
                assert f"{resource}.read" in role.permission_codes


def test_seed_contains_permissions_required_by_current_admin_routes() -> None:
    required = {
        "identity.users.read",
        "identity.users.manage",
        "identity.roles.read",
        "identity.roles.manage",
        "identity.permissions.read",
        "identity.permissions.manage",
        "identity.user_roles.read",
        "identity.user_roles.manage",
    }

    assert required <= ALL_PERMISSION_CODES


def test_clinical_duties_are_separated() -> None:
    doctor = _role_permissions("doctor")
    pharmacist = _role_permissions("pharmacist")
    lab_technician = _role_permissions("lab_technician")
    lab_manager = _role_permissions("lab_manager")

    assert "prescriptions.prescriptions.issue" in doctor
    assert "prescriptions.prescriptions.verify" not in doctor
    assert "prescriptions.prescriptions.verify" in pharmacist
    assert "prescriptions.prescriptions.issue" not in pharmacist
    assert "labs.results.record" in lab_technician
    assert "labs.results.verify" not in lab_technician
    assert "labs.results.verify" in lab_manager


def test_customer_and_delivery_roles_have_no_administrative_permissions() -> None:
    prohibited_prefixes = ("identity.", "audit.", "reports.")

    for role_code in ("customer", "delivery_agent"):
        permissions = _role_permissions(role_code)
        assert not any(code.startswith(prohibited_prefixes) for code in permissions)


def test_permission_definition_management_is_security_admin_only() -> None:
    assert "identity.permissions.manage" in _role_permissions("identity_admin")
    platform_admin = _role_permissions("platform_admin")
    assert "identity.permissions.manage" not in platform_admin
    assert "prescriptions.prescriptions.verify" not in platform_admin
    assert "pharmacy.dispensing.approve" not in platform_admin
    assert "labs.results.verify" not in platform_admin


def test_super_admin_contains_every_managed_permission() -> None:
    assert _role_permissions("super_admin") == ALL_PERMISSION_CODES
