"""Contract tests that prevent authentication layers from collapsing again."""

from __future__ import annotations

import ast
from pathlib import Path

from app.auth.security.tokens import TokenType
from app.core.config import AppSettings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = PROJECT_ROOT / "app"
MODULES_ROOT = APP_ROOT / "modules"

VERTICAL_MODULES = {
    "registration",
    "email_verification",
    "login",
    "token_management",
    "session_management",
    "password_management",
    "current_user",
    "admin_users",
    "admin_roles",
    "admin_permissions",
    "admin_user_roles",
}

REQUIRED_FILES = {
    "routes.py",
    "schemas.py",
    "service.py",
    "repositories.py",
    "openapi.py",
}


def _imports(path: Path) -> set[str]:
    """Return absolute import module names found in a Python source file."""
    tree = ast.parse(path.read_text(), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def _defined_classes(path: Path) -> set[str]:
    """Return top-level classes defined directly in a Python source file."""
    tree = ast.parse(path.read_text(), filename=str(path))
    return {node.name for node in tree.body if isinstance(node, ast.ClassDef)}


def test_every_vertical_module_owns_all_five_layers() -> None:
    """Require concrete local schemas, services, and repositories per API family."""
    for module_name in VERTICAL_MODULES:
        module_path = MODULES_ROOT / module_name
        assert module_path.is_dir()
        assert REQUIRED_FILES.issubset({item.name for item in module_path.iterdir()})

        service_classes = _defined_classes(module_path / "service.py")
        repository_classes = _defined_classes(module_path / "repositories.py")
        schema_classes = _defined_classes(module_path / "schemas.py")

        assert any(name.endswith("Service") for name in service_classes)
        assert any(name.endswith("Repository") for name in repository_classes)
        assert schema_classes


def test_removed_auth_business_layers_cannot_return() -> None:
    """Keep business implementations out of the shared authentication kernel."""
    forbidden_paths = {
        APP_ROOT / "modules" / "auth",
        APP_ROOT / "auth" / "services",
        APP_ROOT / "auth" / "repositories",
        APP_ROOT / "auth" / "schemas",
    }
    assert all(not path.exists() for path in forbidden_paths)

    for path in (APP_ROOT / "auth").rglob("*.py"):
        assert not any(name.startswith("app.modules") for name in _imports(path))

    forbidden_imports = {
        "app.auth.services",
        "app.auth.repositories",
        "app.auth.schemas",
    }
    for path in APP_ROOT.rglob("*.py"):
        assert all(
            not any(name == prefix or name.startswith(f"{prefix}.") for prefix in forbidden_imports)
            for name in _imports(path)
        )


def test_current_release_has_no_mfa_or_api_client_runtime_configuration() -> None:
    """Keep unapproved MFA and machine-client features outside this release."""
    settings_fields = AppSettings.model_fields
    assert "MFA_ENABLED" not in settings_fields
    assert "MFA_ENCRYPTION_KEY" not in settings_fields
    assert "CLIENT_ACCESS_TOKEN_TTL_MINUTES" not in settings_fields
    assert {token_type.value for token_type in TokenType} == {
        "access",
        "refresh",
        "password_reset",
    }
