"""File: tests/unit/test_identity_model_contract.py

Purpose:
Protects identity/profile ORM schema placement, ownership, active-row
uniqueness, and phone-identity database constraints.

Dependency flow:
SQLAlchemy identity mapping metadata
-> table/constraint inspection
-> external schema contract assertions
"""

from __future__ import annotations

from app.models.identity import ApiClients, Sessions, UserProfiles, Users


def test_identity_models_use_external_identity_schema() -> None:
    assert Users.__table__.schema == "identity"
    assert UserProfiles.__table__.schema == "identity"
    assert Sessions.__table__.schema == "identity"
    assert ApiClients.__table__.schema == "identity"


def test_phone_uniqueness_is_partial_not_nulls_not_distinct() -> None:
    indexes = {index.name: index for index in Users.__table__.indexes}
    phone_index = indexes["uq_identity_users_phone_present"]
    assert phone_index.unique is True
    where = str(phone_index.dialect_options["postgresql"]["where"])
    assert "phone_country_code IS NOT NULL" in where
    assert "phone_number IS NOT NULL" in where


def test_phone_identity_requires_both_fields() -> None:
    constraints = {constraint.name for constraint in Users.__table__.constraints}
    assert "ck_identity_users_phone_pair_complete" in constraints


def test_user_profile_belongs_to_identity_user() -> None:
    foreign_keys = {
        foreign_key.target_fullname for foreign_key in UserProfiles.__table__.foreign_keys
    }
    assert "identity.users.id" in foreign_keys


def test_user_profile_has_one_active_row_per_user() -> None:
    indexes = {index.name: index for index in UserProfiles.__table__.indexes}
    active_index = indexes["uq_identity_user_profiles_user_active"]
    assert active_index.unique is True
    where = str(active_index.dialect_options["postgresql"]["where"])
    assert "is_deleted = false" in where
