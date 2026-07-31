"""Seed healthcare-platform identity roles and permissions.

Run from the auth-service repository root after the externally managed
``identity`` schema has been migrated::

    python -m scripts.seed_identity_master_data

Validate the static manifest without connecting to PostgreSQL::

    python -m scripts.seed_identity_master_data --check-only

The operation is idempotent and transactionally safe. It creates or updates
active managed roles and permissions, then makes each managed role's
role-permission mappings exactly match this manifest.

The script intentionally does not:

* create users or user profiles;
* assign roles to users;
* create organization memberships or facility scopes;
* create API clients or credentials;
* delete roles or permissions outside this manifest.

Permissions represent capability only. Every domain service must still enforce
record ownership, practitioner assignment, organization/facility scope,
purpose-of-use, consent, and other domain invariants before returning or
changing regulated or personally identifiable data.
"""

from __future__ import annotations

import argparse
import asyncio
import re
from dataclasses import dataclass

from app.core.config import AppSettings
from app.db.postgres import PostgreSQLDatabase
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.identity import (
    Permissions,
    RolePermissions,
    Roles,
)
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class PermissionSeed:
    """One stable permission definition managed by this seed script."""

    resource: str
    action: str
    description: str

    @property
    def code(self) -> str:
        """Return the canonical ``resource.action`` permission code."""
        return f"{self.resource}.{self.action}"


@dataclass(frozen=True, slots=True)
class RoleSeed:
    """One managed system role and its complete permission set."""

    code: str
    name: str
    description: str
    permission_codes: frozenset[str]


@dataclass(frozen=True, slots=True)
class SeedSummary:
    """Counts of database changes made by one successful seed run."""

    permissions_created: int
    permissions_updated: int
    roles_created: int
    roles_updated: int
    mappings_created: int
    mappings_removed: int


def _permission(resource: str, action: str, description: str) -> PermissionSeed:
    """Build a permission whose code follows ``resource.action``."""
    return PermissionSeed(
        resource=resource,
        action=action,
        description=description,
    )


def _codes(*permissions: PermissionSeed) -> frozenset[str]:
    """Return permission codes for the supplied permission definitions."""
    return frozenset(permission.code for permission in permissions)


# ---------------------------------------------------------------------------
# Identity and access administration
# ---------------------------------------------------------------------------
IDENTITY_USERS_READ = _permission(
    "identity.users",
    "read",
    "View user accounts, contact identifiers, verification state, and status.",
)
IDENTITY_USERS_MANAGE = _permission(
    "identity.users",
    "manage",
    "Change account status, lock state, and administrative account lifecycle data.",
)
IDENTITY_PROFILES_READ = _permission(
    "identity.profiles",
    "read",
    "View universal user profile names and presentation data.",
)
IDENTITY_PROFILES_MANAGE = _permission(
    "identity.profiles",
    "manage",
    "Create and maintain universal user profile names and presentation data.",
)
IDENTITY_ROLES_READ = _permission(
    "identity.roles",
    "read",
    "View role master definitions.",
)
IDENTITY_ROLES_MANAGE = _permission(
    "identity.roles",
    "manage",
    "Create and maintain role master definitions.",
)
IDENTITY_PERMISSIONS_READ = _permission(
    "identity.permissions",
    "read",
    "View permission master definitions.",
)
IDENTITY_PERMISSIONS_MANAGE = _permission(
    "identity.permissions",
    "manage",
    "Create permissions and maintain role-permission policies.",
)
IDENTITY_USER_ROLES_READ = _permission(
    "identity.user_roles",
    "read",
    "View user-role assignments and their scopes.",
)
IDENTITY_USER_ROLES_MANAGE = _permission(
    "identity.user_roles",
    "manage",
    "Assign, activate, expire, or revoke user roles.",
)
IDENTITY_SESSIONS_READ = _permission(
    "identity.sessions",
    "read",
    "View active and revoked authentication sessions.",
)
IDENTITY_SESSIONS_REVOKE = _permission(
    "identity.sessions",
    "revoke",
    "Revoke authentication sessions for permitted users.",
)
IDENTITY_API_CLIENTS_READ = _permission(
    "identity.api_clients",
    "read",
    "View machine-to-machine API client definitions.",
)
IDENTITY_API_CLIENTS_MANAGE = _permission(
    "identity.api_clients",
    "manage",
    "Create, rotate, suspend, and maintain API client credentials.",
)

# ---------------------------------------------------------------------------
# Organization, facilities, and workforce membership
# ---------------------------------------------------------------------------
ORGANIZATIONS_READ = _permission(
    "organization.organizations",
    "read",
    "View organizations and provider entities.",
)
ORGANIZATIONS_MANAGE = _permission(
    "organization.organizations",
    "manage",
    "Create and maintain organizations and provider entities.",
)
ORGANIZATION_LOCATIONS_READ = _permission(
    "organization.locations",
    "read",
    "View pharmacies, labs, clinics, warehouses, and service locations.",
)
ORGANIZATION_LOCATIONS_MANAGE = _permission(
    "organization.locations",
    "manage",
    "Create and maintain pharmacies, labs, clinics, warehouses, and locations.",
)
ORGANIZATION_DEPARTMENTS_READ = _permission(
    "organization.departments",
    "read",
    "View organization departments and reporting structures.",
)
ORGANIZATION_DEPARTMENTS_MANAGE = _permission(
    "organization.departments",
    "manage",
    "Maintain organization departments and reporting structures.",
)
ORGANIZATION_MEMBERSHIPS_READ = _permission(
    "organization.memberships",
    "read",
    "View workforce memberships, designations, and facility assignments.",
)
ORGANIZATION_MEMBERSHIPS_MANAGE = _permission(
    "organization.memberships",
    "manage",
    "Create and maintain workforce memberships and facility assignments.",
)
ORGANIZATION_LICENSES_READ = _permission(
    "organization.licenses",
    "read",
    "View organization, facility, and professional license records.",
)
ORGANIZATION_LICENSES_MANAGE = _permission(
    "organization.licenses",
    "manage",
    "Create, verify, suspend, and maintain license records.",
)

# ---------------------------------------------------------------------------
# Customer and patient-facing account data
# ---------------------------------------------------------------------------
CUSTOMER_PROFILES_READ = _permission(
    "customer.profiles",
    "read",
    "View permitted customer profile information.",
)
CUSTOMER_PROFILES_MANAGE = _permission(
    "customer.profiles",
    "manage",
    "Maintain permitted customer profile information.",
)
CUSTOMER_ADDRESSES_READ = _permission(
    "customer.addresses",
    "read",
    "View permitted customer addresses.",
)
CUSTOMER_ADDRESSES_MANAGE = _permission(
    "customer.addresses",
    "manage",
    "Create and maintain permitted customer addresses.",
)
CUSTOMER_FAMILY_READ = _permission(
    "customer.family_members",
    "read",
    "View permitted family-member profiles.",
)
CUSTOMER_FAMILY_MANAGE = _permission(
    "customer.family_members",
    "manage",
    "Create and maintain permitted family-member profiles.",
)
CUSTOMER_PREFERENCES_MANAGE = _permission(
    "customer.preferences",
    "manage",
    "Maintain permitted customer preferences and communication choices.",
)

# ---------------------------------------------------------------------------
# Catalogue, product governance, pricing, and promotions
# ---------------------------------------------------------------------------
CATALOG_PRODUCTS_READ = _permission(
    "catalog.products",
    "read",
    "View medicines, diagnostics, devices, wellness items, and services.",
)
CATALOG_PRODUCTS_MANAGE = _permission(
    "catalog.products",
    "manage",
    "Create and maintain product and service master records.",
)
CATALOG_CATEGORIES_READ = _permission(
    "catalog.categories",
    "read",
    "View product categories and hierarchy.",
)
CATALOG_CATEGORIES_MANAGE = _permission(
    "catalog.categories",
    "manage",
    "Maintain product categories and hierarchy.",
)
CATALOG_BRANDS_READ = _permission(
    "catalog.brands",
    "read",
    "View product brands.",
)
CATALOG_BRANDS_MANAGE = _permission(
    "catalog.brands",
    "manage",
    "Maintain product brands.",
)
CATALOG_MANUFACTURERS_READ = _permission(
    "catalog.manufacturers",
    "read",
    "View manufacturers.",
)
CATALOG_MANUFACTURERS_MANAGE = _permission(
    "catalog.manufacturers",
    "manage",
    "Maintain manufacturers.",
)
CATALOG_REGULATORY_READ = _permission(
    "catalog.regulatory",
    "read",
    "View product regulatory, recall, and compliance information.",
)
CATALOG_REGULATORY_MANAGE = _permission(
    "catalog.regulatory",
    "manage",
    "Maintain product regulatory, recall, and compliance information.",
)
PRICING_PRICES_READ = _permission(
    "pricing.prices",
    "read",
    "View product prices, price books, taxes, and pricing evaluations.",
)
PRICING_PRICES_MANAGE = _permission(
    "pricing.prices",
    "manage",
    "Maintain price books, product prices, and tax rules.",
)
PRICING_PROMOTIONS_READ = _permission(
    "pricing.promotions",
    "read",
    "View promotions, coupon codes, and redemption rules.",
)
PRICING_PROMOTIONS_MANAGE = _permission(
    "pricing.promotions",
    "manage",
    "Create and maintain promotions, coupons, and redemption rules.",
)

# ---------------------------------------------------------------------------
# Commerce orders, returns, and cancellations
# ---------------------------------------------------------------------------
COMMERCE_CARTS_READ = _permission(
    "commerce.carts",
    "read",
    "View permitted carts and checkout state.",
)
COMMERCE_CARTS_MANAGE = _permission(
    "commerce.carts",
    "manage",
    "Create and maintain permitted carts and checkout state.",
)
COMMERCE_ORDERS_READ = _permission(
    "commerce.orders",
    "read",
    "View permitted orders, items, charges, discounts, and status history.",
)
COMMERCE_ORDERS_CREATE = _permission(
    "commerce.orders",
    "create",
    "Create an order for a permitted customer or patient.",
)
COMMERCE_ORDERS_MANAGE = _permission(
    "commerce.orders",
    "manage",
    "Manage order lifecycle, allocation exceptions, and operational corrections.",
)
COMMERCE_ORDERS_CANCEL = _permission(
    "commerce.orders",
    "cancel",
    "Cancel an eligible permitted order.",
)
COMMERCE_RETURNS_READ = _permission(
    "commerce.returns",
    "read",
    "View permitted return and cancellation records.",
)
COMMERCE_RETURNS_MANAGE = _permission(
    "commerce.returns",
    "manage",
    "Create, approve, reject, and process eligible returns and cancellations.",
)

# ---------------------------------------------------------------------------
# Payments, refunds, settlement, and finance
# ---------------------------------------------------------------------------
PAYMENTS_READ = _permission(
    "payment.transactions",
    "read",
    "View permitted payment intents, attempts, and transactions.",
)
PAYMENTS_MANAGE = _permission(
    "payment.transactions",
    "manage",
    "Manage payment intents, transactions, and payment exceptions.",
)
PAYMENTS_REFUND = _permission(
    "payment.refunds",
    "refund",
    "Initiate or approve eligible refunds.",
)
PAYMENTS_CHARGEBACKS_MANAGE = _permission(
    "payment.chargebacks",
    "manage",
    "Review and manage payment chargebacks.",
)
FINANCE_INVOICES_READ = _permission(
    "finance.invoices",
    "read",
    "View invoices, credit notes, and accounting documents.",
)
FINANCE_INVOICES_MANAGE = _permission(
    "finance.invoices",
    "manage",
    "Create and maintain invoices and credit notes.",
)
FINANCE_RECONCILIATION_READ = _permission(
    "finance.reconciliation",
    "read",
    "View settlement and reconciliation runs.",
)
FINANCE_RECONCILIATION_MANAGE = _permission(
    "finance.reconciliation",
    "manage",
    "Run and resolve payment, COD, supplier, and seller reconciliation.",
)
FINANCE_LEDGER_READ = _permission(
    "finance.ledger",
    "read",
    "View permitted journal entries and ledger records.",
)
FINANCE_LEDGER_MANAGE = _permission(
    "finance.ledger",
    "manage",
    "Create and post permitted journal entries.",
)

# ---------------------------------------------------------------------------
# Clinical care, prescriptions, and appointments
# ---------------------------------------------------------------------------
CLINICAL_PATIENTS_READ = _permission(
    "clinical.patients",
    "read",
    "View permitted patient clinical profiles, conditions, allergies, and medications.",
)
CLINICAL_PATIENTS_MANAGE = _permission(
    "clinical.patients",
    "manage",
    "Maintain permitted patient clinical profiles and structured history.",
)
CLINICAL_PRESCRIPTIONS_READ = _permission(
    "clinical.prescriptions",
    "read",
    "View permitted prescriptions and prescription documents.",
)
CLINICAL_PRESCRIPTIONS_UPLOAD = _permission(
    "clinical.prescriptions",
    "upload",
    "Upload a prescription for a permitted patient or order.",
)
CLINICAL_PRESCRIPTIONS_ISSUE = _permission(
    "clinical.prescriptions",
    "issue",
    "Issue a clinical prescription within practitioner scope.",
)
CLINICAL_PRESCRIPTIONS_VERIFY = _permission(
    "clinical.prescriptions",
    "verify",
    "Verify a prescription for dispensing.",
)
CLINICAL_PRESCRIPTIONS_REJECT = _permission(
    "clinical.prescriptions",
    "reject",
    "Reject a prescription that fails clinical or regulatory checks.",
)
CLINICAL_CONSULTATIONS_READ = _permission(
    "clinical.consultations",
    "read",
    "View permitted consultations, diagnoses, observations, and care episodes.",
)
CLINICAL_CONSULTATIONS_MANAGE = _permission(
    "clinical.consultations",
    "manage",
    "Create and maintain assigned consultation clinical records.",
)
CLINICAL_DISPENSING_READ = _permission(
    "clinical.dispensing",
    "read",
    "View permitted medicine-dispensing records.",
)
CLINICAL_DISPENSING_MANAGE = _permission(
    "clinical.dispensing",
    "manage",
    "Record medicine dispensing against approved prescriptions and orders.",
)
CLINICAL_DISPENSING_APPROVE = _permission(
    "clinical.dispensing",
    "approve",
    "Approve controlled or exceptional dispensing actions.",
)
APPOINTMENTS_READ = _permission(
    "appointment.appointments",
    "read",
    "View permitted appointments, slots, and waiting-room events.",
)
APPOINTMENTS_CREATE = _permission(
    "appointment.appointments",
    "create",
    "Book an appointment for a permitted patient.",
)
APPOINTMENTS_MANAGE = _permission(
    "appointment.appointments",
    "manage",
    "Confirm, reschedule, check in, and manage assigned appointments.",
)
APPOINTMENTS_CANCEL = _permission(
    "appointment.appointments",
    "cancel",
    "Cancel an eligible permitted appointment.",
)
APPOINTMENT_AVAILABILITY_MANAGE = _permission(
    "appointment.availability",
    "manage",
    "Maintain practitioner availability rules, slots, and exceptions.",
)

# ---------------------------------------------------------------------------
# Diagnostic labs
# ---------------------------------------------------------------------------
DIAGNOSTICS_CATALOG_READ = _permission(
    "diagnostics.catalog",
    "read",
    "View diagnostic tests, packages, providers, and lab offerings.",
)
DIAGNOSTICS_CATALOG_MANAGE = _permission(
    "diagnostics.catalog",
    "manage",
    "Maintain diagnostic tests, packages, providers, and lab offerings.",
)
DIAGNOSTICS_ORDERS_READ = _permission(
    "diagnostics.orders",
    "read",
    "View permitted diagnostic orders and items.",
)
DIAGNOSTICS_ORDERS_CREATE = _permission(
    "diagnostics.orders",
    "create",
    "Create a diagnostic order for a permitted patient.",
)
DIAGNOSTICS_ORDERS_MANAGE = _permission(
    "diagnostics.orders",
    "manage",
    "Manage diagnostic-order lifecycle and exceptions.",
)
DIAGNOSTICS_SAMPLES_READ = _permission(
    "diagnostics.samples",
    "read",
    "View permitted sample collection, custody, and processing records.",
)
DIAGNOSTICS_SAMPLES_COLLECT = _permission(
    "diagnostics.samples",
    "collect",
    "Record sample collection and chain of custody.",
)
DIAGNOSTICS_SAMPLES_PROCESS = _permission(
    "diagnostics.samples",
    "process",
    "Receive, accept, reject, process, and dispose diagnostic samples.",
)
DIAGNOSTICS_RESULTS_READ = _permission(
    "diagnostics.results",
    "read",
    "View permitted diagnostic observations, result values, and reports.",
)
DIAGNOSTICS_RESULTS_RECORD = _permission(
    "diagnostics.results",
    "record",
    "Record diagnostic observations and result values.",
)
DIAGNOSTICS_RESULTS_VERIFY = _permission(
    "diagnostics.results",
    "verify",
    "Clinically verify and release diagnostic reports.",
)

# ---------------------------------------------------------------------------
# Warehouse, fulfillment, logistics, and delivery
# ---------------------------------------------------------------------------
WAREHOUSE_INVENTORY_READ = _permission(
    "warehouse.inventory",
    "read",
    "View stock balances, reservations, holds, ledger entries, lots, and expiry.",
)
WAREHOUSE_INVENTORY_ADJUST = _permission(
    "warehouse.inventory",
    "adjust",
    "Record controlled inventory adjustments and quality dispositions.",
)
WAREHOUSE_RECEIVING_READ = _permission(
    "warehouse.receiving",
    "read",
    "View goods receipts and receiving quality checks.",
)
WAREHOUSE_RECEIVING_MANAGE = _permission(
    "warehouse.receiving",
    "manage",
    "Receive goods and complete receiving quality checks.",
)
WAREHOUSE_TRANSFERS_READ = _permission(
    "warehouse.transfers",
    "read",
    "View stock transfers and replenishment activity.",
)
WAREHOUSE_TRANSFERS_MANAGE = _permission(
    "warehouse.transfers",
    "manage",
    "Create and complete stock transfers and replenishment activity.",
)
WAREHOUSE_COUNTS_READ = _permission(
    "warehouse.counts",
    "read",
    "View cycle counts and count variances.",
)
WAREHOUSE_COUNTS_MANAGE = _permission(
    "warehouse.counts",
    "manage",
    "Create, count, approve, and close cycle counts.",
)
WAREHOUSE_LAYOUT_READ = _permission(
    "warehouse.layout",
    "read",
    "View warehouses, zones, aisles, racks, and bins.",
)
WAREHOUSE_LAYOUT_MANAGE = _permission(
    "warehouse.layout",
    "manage",
    "Maintain warehouses, zones, aisles, racks, bins, and replenishment rules.",
)
FULFILLMENT_ORDERS_READ = _permission(
    "fulfillment.orders",
    "read",
    "View permitted fulfillment orders, allocations, and events.",
)
FULFILLMENT_ORDERS_MANAGE = _permission(
    "fulfillment.orders",
    "manage",
    "Create, allocate, and manage fulfillment orders.",
)
FULFILLMENT_PICK = _permission(
    "fulfillment.picking",
    "execute",
    "Execute assigned picking waves and pick tasks.",
)
FULFILLMENT_PACK = _permission(
    "fulfillment.packing",
    "execute",
    "Execute assigned packing tasks and package creation.",
)
LOGISTICS_SHIPMENTS_READ = _permission(
    "logistics.shipments",
    "read",
    "View permitted shipments, packages, routes, assignments, and events.",
)
LOGISTICS_SHIPMENTS_MANAGE = _permission(
    "logistics.shipments",
    "manage",
    "Create and manage shipment lifecycle, carrier booking, and exceptions.",
)
LOGISTICS_ASSIGN = _permission(
    "logistics.shipments",
    "assign",
    "Assign shipments and delivery routes to delivery personnel.",
)
LOGISTICS_DELIVER = _permission(
    "logistics.shipments",
    "deliver",
    "Record assigned delivery attempts, COD collection, and completion.",
)

# ---------------------------------------------------------------------------
# Procurement and supplier operations
# ---------------------------------------------------------------------------
PROCUREMENT_SUPPLIERS_READ = _permission(
    "procurement.suppliers",
    "read",
    "View suppliers, supplier products, licenses, and commercial terms.",
)
PROCUREMENT_SUPPLIERS_MANAGE = _permission(
    "procurement.suppliers",
    "manage",
    "Create, verify, suspend, and maintain suppliers and supplier products.",
)
PROCUREMENT_REQUISITIONS_READ = _permission(
    "procurement.requisitions",
    "read",
    "View purchase requisitions and items.",
)
PROCUREMENT_REQUISITIONS_MANAGE = _permission(
    "procurement.requisitions",
    "manage",
    "Create, approve, reject, and maintain purchase requisitions.",
)
PROCUREMENT_ORDERS_READ = _permission(
    "procurement.purchase_orders",
    "read",
    "View purchase orders and supplier commitments.",
)
PROCUREMENT_ORDERS_MANAGE = _permission(
    "procurement.purchase_orders",
    "manage",
    "Create, approve, issue, amend, and close purchase orders.",
)
PROCUREMENT_RETURNS_READ = _permission(
    "procurement.returns",
    "read",
    "View supplier returns and return items.",
)
PROCUREMENT_RETURNS_MANAGE = _permission(
    "procurement.returns",
    "manage",
    "Create, approve, and process supplier returns.",
)
PROCUREMENT_INVOICES_READ = _permission(
    "procurement.invoices",
    "read",
    "View supplier invoices and three-way matching information.",
)
PROCUREMENT_INVOICES_MANAGE = _permission(
    "procurement.invoices",
    "manage",
    "Validate, match, dispute, and approve supplier invoices.",
)

# ---------------------------------------------------------------------------
# Marketplace seller operations
# ---------------------------------------------------------------------------
MARKETPLACE_SELLERS_READ = _permission(
    "marketplace.sellers",
    "read",
    "View sellers, locations, service levels, ratings, and commission plans.",
)
MARKETPLACE_SELLERS_MANAGE = _permission(
    "marketplace.sellers",
    "manage",
    "Onboard, verify, suspend, and maintain sellers and seller locations.",
)
MARKETPLACE_LISTINGS_READ = _permission(
    "marketplace.listings",
    "read",
    "View seller product listings and availability.",
)
MARKETPLACE_LISTINGS_MANAGE = _permission(
    "marketplace.listings",
    "manage",
    "Create, approve, reject, and maintain seller product listings.",
)
MARKETPLACE_COMMISSIONS_READ = _permission(
    "marketplace.commissions",
    "read",
    "View seller commission plans and assignments.",
)
MARKETPLACE_COMMISSIONS_MANAGE = _permission(
    "marketplace.commissions",
    "manage",
    "Create and assign seller commission plans.",
)

# ---------------------------------------------------------------------------
# Insurance, membership, and loyalty
# ---------------------------------------------------------------------------
INSURANCE_PLANS_READ = _permission(
    "insurance.plans",
    "read",
    "View insurers, TPAs, plans, and plan benefits.",
)
INSURANCE_PLANS_MANAGE = _permission(
    "insurance.plans",
    "manage",
    "Maintain insurers, TPAs, plans, and benefits.",
)
INSURANCE_POLICIES_READ = _permission(
    "insurance.policies",
    "read",
    "View permitted policies, members, and eligibility checks.",
)
INSURANCE_POLICIES_MANAGE = _permission(
    "insurance.policies",
    "manage",
    "Create and maintain policies, members, and eligibility decisions.",
)
INSURANCE_CLAIMS_READ = _permission(
    "insurance.claims",
    "read",
    "View permitted claims, documents, and status history.",
)
INSURANCE_CLAIMS_MANAGE = _permission(
    "insurance.claims",
    "manage",
    "Submit, assess, approve, reject, and settle permitted claims.",
)
MEMBERSHIP_LOYALTY_READ = _permission(
    "membership.loyalty",
    "read",
    "View permitted loyalty accounts, subscriptions, and benefit usage.",
)
MEMBERSHIP_LOYALTY_MANAGE = _permission(
    "membership.loyalty",
    "manage",
    "Maintain loyalty accounts, subscriptions, benefits, and ledger adjustments.",
)

# ---------------------------------------------------------------------------
# Support and notifications
# ---------------------------------------------------------------------------
SUPPORT_TICKETS_READ = _permission(
    "support.tickets",
    "read",
    "View permitted support cases, tickets, messages, and actions.",
)
SUPPORT_TICKETS_CREATE = _permission(
    "support.tickets",
    "create",
    "Create a support case or ticket.",
)
SUPPORT_TICKETS_MANAGE = _permission(
    "support.tickets",
    "manage",
    "Assign, communicate on, escalate, resolve, and close support tickets.",
)
NOTIFICATIONS_MESSAGES_READ = _permission(
    "notification.messages",
    "read",
    "View permitted notification messages and delivery attempts.",
)
NOTIFICATIONS_MESSAGES_SEND = _permission(
    "notification.messages",
    "send",
    "Queue and send transactional notifications.",
)
NOTIFICATIONS_TEMPLATES_MANAGE = _permission(
    "notification.templates",
    "manage",
    "Create and maintain notification templates and channel policies.",
)

# ---------------------------------------------------------------------------
# Compliance, privacy, risk, and audit
# ---------------------------------------------------------------------------
COMPLIANCE_AUDIT_READ = _permission(
    "compliance.audit",
    "read",
    "View security, access, prescription, consent, and compliance audit evidence.",
)
COMPLIANCE_CONSENTS_READ = _permission(
    "compliance.consents",
    "read",
    "View permitted consent records and consent events.",
)
COMPLIANCE_CONSENTS_MANAGE = _permission(
    "compliance.consents",
    "manage",
    "Create, revoke, expire, and maintain permitted consent records.",
)
COMPLIANCE_PRIVACY_READ = _permission(
    "compliance.privacy",
    "read",
    "View privacy requests, legal holds, and retention policies.",
)
COMPLIANCE_PRIVACY_MANAGE = _permission(
    "compliance.privacy",
    "manage",
    "Process privacy requests and maintain legal holds and retention policies.",
)
COMPLIANCE_ADVERSE_EVENTS_READ = _permission(
    "compliance.adverse_events",
    "read",
    "View adverse-event and product-safety reports.",
)
COMPLIANCE_ADVERSE_EVENTS_MANAGE = _permission(
    "compliance.adverse_events",
    "manage",
    "Record, assess, escalate, and report adverse events.",
)
RISK_SIGNALS_READ = _permission(
    "risk.signals",
    "read",
    "View fraud, abuse, payment, account, and operational risk signals.",
)
RISK_SIGNALS_MANAGE = _permission(
    "risk.signals",
    "manage",
    "Review and resolve risk signals and assessments.",
)
RISK_RULES_READ = _permission(
    "risk.rules",
    "read",
    "View risk rules, blocklists, and decision policies.",
)
RISK_RULES_MANAGE = _permission(
    "risk.rules",
    "manage",
    "Create and maintain risk rules, blocklists, and decision policies.",
)

# ---------------------------------------------------------------------------
# Platform operations, files, search, and reporting
# ---------------------------------------------------------------------------
PLATFORM_SETTINGS_READ = _permission(
    "platform.settings",
    "read",
    "View application settings, service types, and feature flags.",
)
PLATFORM_SETTINGS_MANAGE = _permission(
    "platform.settings",
    "manage",
    "Maintain application settings, service types, and feature flags.",
)
PLATFORM_FILES_READ = _permission(
    "platform.files",
    "read",
    "View permitted file objects, scan events, and access grants.",
)
PLATFORM_FILES_MANAGE = _permission(
    "platform.files",
    "manage",
    "Maintain file objects, access grants, and scan dispositions.",
)
PLATFORM_JOBS_READ = _permission(
    "platform.jobs",
    "read",
    "View scheduled jobs, outbox events, and webhook delivery state.",
)
PLATFORM_JOBS_MANAGE = _permission(
    "platform.jobs",
    "manage",
    "Operate scheduled jobs, event delivery, and webhook endpoints.",
)
SEARCH_CONFIGURATION_READ = _permission(
    "search.configuration",
    "read",
    "View indexing jobs, synonyms, redirects, and search configuration.",
)
SEARCH_CONFIGURATION_MANAGE = _permission(
    "search.configuration",
    "manage",
    "Maintain indexing jobs, synonyms, redirects, and search configuration.",
)
REPORTS_OPERATIONS_READ = _permission(
    "reports.operations",
    "read",
    "View operational reports and dashboards.",
)
REPORTS_FINANCE_READ = _permission(
    "reports.finance",
    "read",
    "View financial reports and dashboards.",
)
REPORTS_CLINICAL_READ = _permission(
    "reports.clinical",
    "read",
    "View permitted clinical and diagnostic reports.",
)


PERMISSION_SEEDS: tuple[PermissionSeed, ...] = (
    IDENTITY_USERS_READ,
    IDENTITY_USERS_MANAGE,
    IDENTITY_PROFILES_READ,
    IDENTITY_PROFILES_MANAGE,
    IDENTITY_ROLES_READ,
    IDENTITY_ROLES_MANAGE,
    IDENTITY_PERMISSIONS_READ,
    IDENTITY_PERMISSIONS_MANAGE,
    IDENTITY_USER_ROLES_READ,
    IDENTITY_USER_ROLES_MANAGE,
    IDENTITY_SESSIONS_READ,
    IDENTITY_SESSIONS_REVOKE,
    IDENTITY_API_CLIENTS_READ,
    IDENTITY_API_CLIENTS_MANAGE,
    ORGANIZATIONS_READ,
    ORGANIZATIONS_MANAGE,
    ORGANIZATION_LOCATIONS_READ,
    ORGANIZATION_LOCATIONS_MANAGE,
    ORGANIZATION_DEPARTMENTS_READ,
    ORGANIZATION_DEPARTMENTS_MANAGE,
    ORGANIZATION_MEMBERSHIPS_READ,
    ORGANIZATION_MEMBERSHIPS_MANAGE,
    ORGANIZATION_LICENSES_READ,
    ORGANIZATION_LICENSES_MANAGE,
    CUSTOMER_PROFILES_READ,
    CUSTOMER_PROFILES_MANAGE,
    CUSTOMER_ADDRESSES_READ,
    CUSTOMER_ADDRESSES_MANAGE,
    CUSTOMER_FAMILY_READ,
    CUSTOMER_FAMILY_MANAGE,
    CUSTOMER_PREFERENCES_MANAGE,
    CATALOG_PRODUCTS_READ,
    CATALOG_PRODUCTS_MANAGE,
    CATALOG_CATEGORIES_READ,
    CATALOG_CATEGORIES_MANAGE,
    CATALOG_BRANDS_READ,
    CATALOG_BRANDS_MANAGE,
    CATALOG_MANUFACTURERS_READ,
    CATALOG_MANUFACTURERS_MANAGE,
    CATALOG_REGULATORY_READ,
    CATALOG_REGULATORY_MANAGE,
    PRICING_PRICES_READ,
    PRICING_PRICES_MANAGE,
    PRICING_PROMOTIONS_READ,
    PRICING_PROMOTIONS_MANAGE,
    COMMERCE_CARTS_READ,
    COMMERCE_CARTS_MANAGE,
    COMMERCE_ORDERS_READ,
    COMMERCE_ORDERS_CREATE,
    COMMERCE_ORDERS_MANAGE,
    COMMERCE_ORDERS_CANCEL,
    COMMERCE_RETURNS_READ,
    COMMERCE_RETURNS_MANAGE,
    PAYMENTS_READ,
    PAYMENTS_MANAGE,
    PAYMENTS_REFUND,
    PAYMENTS_CHARGEBACKS_MANAGE,
    FINANCE_INVOICES_READ,
    FINANCE_INVOICES_MANAGE,
    FINANCE_RECONCILIATION_READ,
    FINANCE_RECONCILIATION_MANAGE,
    FINANCE_LEDGER_READ,
    FINANCE_LEDGER_MANAGE,
    CLINICAL_PATIENTS_READ,
    CLINICAL_PATIENTS_MANAGE,
    CLINICAL_PRESCRIPTIONS_READ,
    CLINICAL_PRESCRIPTIONS_UPLOAD,
    CLINICAL_PRESCRIPTIONS_ISSUE,
    CLINICAL_PRESCRIPTIONS_VERIFY,
    CLINICAL_PRESCRIPTIONS_REJECT,
    CLINICAL_CONSULTATIONS_READ,
    CLINICAL_CONSULTATIONS_MANAGE,
    CLINICAL_DISPENSING_READ,
    CLINICAL_DISPENSING_MANAGE,
    CLINICAL_DISPENSING_APPROVE,
    APPOINTMENTS_READ,
    APPOINTMENTS_CREATE,
    APPOINTMENTS_MANAGE,
    APPOINTMENTS_CANCEL,
    APPOINTMENT_AVAILABILITY_MANAGE,
    DIAGNOSTICS_CATALOG_READ,
    DIAGNOSTICS_CATALOG_MANAGE,
    DIAGNOSTICS_ORDERS_READ,
    DIAGNOSTICS_ORDERS_CREATE,
    DIAGNOSTICS_ORDERS_MANAGE,
    DIAGNOSTICS_SAMPLES_READ,
    DIAGNOSTICS_SAMPLES_COLLECT,
    DIAGNOSTICS_SAMPLES_PROCESS,
    DIAGNOSTICS_RESULTS_READ,
    DIAGNOSTICS_RESULTS_RECORD,
    DIAGNOSTICS_RESULTS_VERIFY,
    WAREHOUSE_INVENTORY_READ,
    WAREHOUSE_INVENTORY_ADJUST,
    WAREHOUSE_RECEIVING_READ,
    WAREHOUSE_RECEIVING_MANAGE,
    WAREHOUSE_TRANSFERS_READ,
    WAREHOUSE_TRANSFERS_MANAGE,
    WAREHOUSE_COUNTS_READ,
    WAREHOUSE_COUNTS_MANAGE,
    WAREHOUSE_LAYOUT_READ,
    WAREHOUSE_LAYOUT_MANAGE,
    FULFILLMENT_ORDERS_READ,
    FULFILLMENT_ORDERS_MANAGE,
    FULFILLMENT_PICK,
    FULFILLMENT_PACK,
    LOGISTICS_SHIPMENTS_READ,
    LOGISTICS_SHIPMENTS_MANAGE,
    LOGISTICS_ASSIGN,
    LOGISTICS_DELIVER,
    PROCUREMENT_SUPPLIERS_READ,
    PROCUREMENT_SUPPLIERS_MANAGE,
    PROCUREMENT_REQUISITIONS_READ,
    PROCUREMENT_REQUISITIONS_MANAGE,
    PROCUREMENT_ORDERS_READ,
    PROCUREMENT_ORDERS_MANAGE,
    PROCUREMENT_RETURNS_READ,
    PROCUREMENT_RETURNS_MANAGE,
    PROCUREMENT_INVOICES_READ,
    PROCUREMENT_INVOICES_MANAGE,
    MARKETPLACE_SELLERS_READ,
    MARKETPLACE_SELLERS_MANAGE,
    MARKETPLACE_LISTINGS_READ,
    MARKETPLACE_LISTINGS_MANAGE,
    MARKETPLACE_COMMISSIONS_READ,
    MARKETPLACE_COMMISSIONS_MANAGE,
    INSURANCE_PLANS_READ,
    INSURANCE_PLANS_MANAGE,
    INSURANCE_POLICIES_READ,
    INSURANCE_POLICIES_MANAGE,
    INSURANCE_CLAIMS_READ,
    INSURANCE_CLAIMS_MANAGE,
    MEMBERSHIP_LOYALTY_READ,
    MEMBERSHIP_LOYALTY_MANAGE,
    SUPPORT_TICKETS_READ,
    SUPPORT_TICKETS_CREATE,
    SUPPORT_TICKETS_MANAGE,
    NOTIFICATIONS_MESSAGES_READ,
    NOTIFICATIONS_MESSAGES_SEND,
    NOTIFICATIONS_TEMPLATES_MANAGE,
    COMPLIANCE_AUDIT_READ,
    COMPLIANCE_CONSENTS_READ,
    COMPLIANCE_CONSENTS_MANAGE,
    COMPLIANCE_PRIVACY_READ,
    COMPLIANCE_PRIVACY_MANAGE,
    COMPLIANCE_ADVERSE_EVENTS_READ,
    COMPLIANCE_ADVERSE_EVENTS_MANAGE,
    RISK_SIGNALS_READ,
    RISK_SIGNALS_MANAGE,
    RISK_RULES_READ,
    RISK_RULES_MANAGE,
    PLATFORM_SETTINGS_READ,
    PLATFORM_SETTINGS_MANAGE,
    PLATFORM_FILES_READ,
    PLATFORM_FILES_MANAGE,
    PLATFORM_JOBS_READ,
    PLATFORM_JOBS_MANAGE,
    SEARCH_CONFIGURATION_READ,
    SEARCH_CONFIGURATION_MANAGE,
    REPORTS_OPERATIONS_READ,
    REPORTS_FINANCE_READ,
    REPORTS_CLINICAL_READ,
)

ALL_PERMISSION_CODES = frozenset(seed.code for seed in PERMISSION_SEEDS)

# Reusable capability groups keep role definitions readable and auditable.
IDENTITY_READ = _codes(
    IDENTITY_USERS_READ,
    IDENTITY_PROFILES_READ,
    IDENTITY_ROLES_READ,
    IDENTITY_PERMISSIONS_READ,
    IDENTITY_USER_ROLES_READ,
    IDENTITY_SESSIONS_READ,
)
IDENTITY_ADMIN = IDENTITY_READ | _codes(
    IDENTITY_USERS_MANAGE,
    IDENTITY_PROFILES_MANAGE,
    IDENTITY_ROLES_MANAGE,
    IDENTITY_PERMISSIONS_MANAGE,
    IDENTITY_USER_ROLES_MANAGE,
    IDENTITY_SESSIONS_REVOKE,
    IDENTITY_API_CLIENTS_READ,
    IDENTITY_API_CLIENTS_MANAGE,
)
ORGANIZATION_READ = _codes(
    ORGANIZATIONS_READ,
    ORGANIZATION_LOCATIONS_READ,
    ORGANIZATION_DEPARTMENTS_READ,
    ORGANIZATION_MEMBERSHIPS_READ,
    ORGANIZATION_LICENSES_READ,
)
CATALOG_READ = _codes(
    CATALOG_PRODUCTS_READ,
    CATALOG_CATEGORIES_READ,
    CATALOG_BRANDS_READ,
    CATALOG_MANUFACTURERS_READ,
    CATALOG_REGULATORY_READ,
    PRICING_PRICES_READ,
    PRICING_PROMOTIONS_READ,
)
CATALOG_MANAGE = CATALOG_READ | _codes(
    CATALOG_PRODUCTS_MANAGE,
    CATALOG_CATEGORIES_MANAGE,
    CATALOG_BRANDS_MANAGE,
    CATALOG_MANUFACTURERS_MANAGE,
    CATALOG_REGULATORY_MANAGE,
)
WAREHOUSE_READ = _codes(
    WAREHOUSE_INVENTORY_READ,
    WAREHOUSE_RECEIVING_READ,
    WAREHOUSE_TRANSFERS_READ,
    WAREHOUSE_COUNTS_READ,
    WAREHOUSE_LAYOUT_READ,
)
PROCUREMENT_READ = _codes(
    PROCUREMENT_SUPPLIERS_READ,
    PROCUREMENT_REQUISITIONS_READ,
    PROCUREMENT_ORDERS_READ,
    PROCUREMENT_RETURNS_READ,
    PROCUREMENT_INVOICES_READ,
)

CUSTOMER_PERMISSIONS = _codes(
    CUSTOMER_PROFILES_READ,
    CUSTOMER_PROFILES_MANAGE,
    CUSTOMER_ADDRESSES_READ,
    CUSTOMER_ADDRESSES_MANAGE,
    CUSTOMER_FAMILY_READ,
    CUSTOMER_FAMILY_MANAGE,
    CUSTOMER_PREFERENCES_MANAGE,
    CATALOG_PRODUCTS_READ,
    CATALOG_CATEGORIES_READ,
    CATALOG_BRANDS_READ,
    CATALOG_MANUFACTURERS_READ,
    PRICING_PRICES_READ,
    PRICING_PROMOTIONS_READ,
    COMMERCE_CARTS_READ,
    COMMERCE_CARTS_MANAGE,
    COMMERCE_ORDERS_READ,
    COMMERCE_ORDERS_CREATE,
    COMMERCE_ORDERS_CANCEL,
    COMMERCE_RETURNS_READ,
    CLINICAL_PATIENTS_READ,
    CLINICAL_PATIENTS_MANAGE,
    CLINICAL_PRESCRIPTIONS_READ,
    CLINICAL_PRESCRIPTIONS_UPLOAD,
    APPOINTMENTS_READ,
    APPOINTMENTS_CREATE,
    APPOINTMENTS_CANCEL,
    DIAGNOSTICS_CATALOG_READ,
    DIAGNOSTICS_ORDERS_READ,
    DIAGNOSTICS_ORDERS_CREATE,
    DIAGNOSTICS_RESULTS_READ,
    PAYMENTS_READ,
    PAYMENTS_REFUND,
    LOGISTICS_SHIPMENTS_READ,
    INSURANCE_PLANS_READ,
    INSURANCE_POLICIES_READ,
    INSURANCE_CLAIMS_READ,
    MEMBERSHIP_LOYALTY_READ,
    SUPPORT_TICKETS_READ,
    SUPPORT_TICKETS_CREATE,
    COMPLIANCE_CONSENTS_READ,
    COMPLIANCE_CONSENTS_MANAGE,
)

CAREGIVER_PERMISSIONS = CUSTOMER_PERMISSIONS

DOCTOR_PERMISSIONS = ORGANIZATION_READ | _codes(
    CATALOG_PRODUCTS_READ,
    CLINICAL_PATIENTS_READ,
    CLINICAL_PATIENTS_MANAGE,
    CLINICAL_PRESCRIPTIONS_READ,
    CLINICAL_PRESCRIPTIONS_ISSUE,
    CLINICAL_CONSULTATIONS_READ,
    CLINICAL_CONSULTATIONS_MANAGE,
    APPOINTMENTS_READ,
    APPOINTMENTS_MANAGE,
    APPOINTMENT_AVAILABILITY_MANAGE,
    DIAGNOSTICS_CATALOG_READ,
    DIAGNOSTICS_ORDERS_READ,
    DIAGNOSTICS_ORDERS_CREATE,
    DIAGNOSTICS_RESULTS_READ,
    REPORTS_CLINICAL_READ,
)

PHARMACIST_PERMISSIONS = (
    ORGANIZATION_READ
    | CATALOG_READ
    | _codes(
        COMMERCE_ORDERS_READ,
        CLINICAL_PATIENTS_READ,
        CLINICAL_PRESCRIPTIONS_READ,
        CLINICAL_PRESCRIPTIONS_VERIFY,
        CLINICAL_PRESCRIPTIONS_REJECT,
        CLINICAL_DISPENSING_READ,
        CLINICAL_DISPENSING_MANAGE,
        WAREHOUSE_INVENTORY_READ,
        FULFILLMENT_ORDERS_READ,
    )
)
PHARMACY_MANAGER_PERMISSIONS = PHARMACIST_PERMISSIONS | _codes(
    CLINICAL_DISPENSING_APPROVE,
    WAREHOUSE_INVENTORY_ADJUST,
    WAREHOUSE_RECEIVING_READ,
    WAREHOUSE_TRANSFERS_READ,
    COMMERCE_ORDERS_MANAGE,
    FULFILLMENT_ORDERS_MANAGE,
    REPORTS_OPERATIONS_READ,
)

LAB_TECHNICIAN_PERMISSIONS = ORGANIZATION_READ | _codes(
    DIAGNOSTICS_CATALOG_READ,
    DIAGNOSTICS_ORDERS_READ,
    DIAGNOSTICS_SAMPLES_READ,
    DIAGNOSTICS_SAMPLES_COLLECT,
    DIAGNOSTICS_SAMPLES_PROCESS,
    DIAGNOSTICS_RESULTS_READ,
    DIAGNOSTICS_RESULTS_RECORD,
)
PATHOLOGIST_PERMISSIONS = LAB_TECHNICIAN_PERMISSIONS | _codes(
    CLINICAL_PATIENTS_READ,
    DIAGNOSTICS_RESULTS_VERIFY,
    REPORTS_CLINICAL_READ,
)
LAB_MANAGER_PERMISSIONS = PATHOLOGIST_PERMISSIONS | _codes(
    DIAGNOSTICS_CATALOG_MANAGE,
    DIAGNOSTICS_ORDERS_CREATE,
    DIAGNOSTICS_ORDERS_MANAGE,
    REPORTS_OPERATIONS_READ,
)

WAREHOUSE_RECEIVER_PERMISSIONS = (
    ORGANIZATION_READ
    | CATALOG_READ
    | _codes(
        WAREHOUSE_INVENTORY_READ,
        WAREHOUSE_RECEIVING_READ,
        WAREHOUSE_RECEIVING_MANAGE,
        WAREHOUSE_LAYOUT_READ,
    )
)
WAREHOUSE_PICKER_PERMISSIONS = (
    ORGANIZATION_READ
    | CATALOG_READ
    | _codes(
        WAREHOUSE_INVENTORY_READ,
        WAREHOUSE_LAYOUT_READ,
        FULFILLMENT_ORDERS_READ,
        FULFILLMENT_PICK,
    )
)
WAREHOUSE_PACKER_PERMISSIONS = (
    ORGANIZATION_READ
    | CATALOG_READ
    | _codes(
        FULFILLMENT_ORDERS_READ,
        FULFILLMENT_PACK,
        LOGISTICS_SHIPMENTS_READ,
    )
)
WAREHOUSE_OPERATOR_PERMISSIONS = (
    WAREHOUSE_RECEIVER_PERMISSIONS
    | WAREHOUSE_PICKER_PERMISSIONS
    | WAREHOUSE_PACKER_PERMISSIONS
    | _codes(WAREHOUSE_TRANSFERS_READ, WAREHOUSE_COUNTS_READ)
)
WAREHOUSE_MANAGER_PERMISSIONS = WAREHOUSE_OPERATOR_PERMISSIONS | _codes(
    WAREHOUSE_INVENTORY_ADJUST,
    WAREHOUSE_TRANSFERS_MANAGE,
    WAREHOUSE_COUNTS_MANAGE,
    WAREHOUSE_LAYOUT_MANAGE,
    FULFILLMENT_ORDERS_MANAGE,
    LOGISTICS_SHIPMENTS_MANAGE,
    LOGISTICS_ASSIGN,
    REPORTS_OPERATIONS_READ,
)

DELIVERY_AGENT_PERMISSIONS = _codes(
    LOGISTICS_SHIPMENTS_READ,
    LOGISTICS_DELIVER,
)
DELIVERY_DISPATCHER_PERMISSIONS = ORGANIZATION_READ | _codes(
    LOGISTICS_SHIPMENTS_READ,
    LOGISTICS_SHIPMENTS_MANAGE,
    LOGISTICS_ASSIGN,
    REPORTS_OPERATIONS_READ,
)
LOGISTICS_MANAGER_PERMISSIONS = DELIVERY_DISPATCHER_PERMISSIONS | _codes(
    COMMERCE_ORDERS_READ,
    COMMERCE_RETURNS_READ,
    FULFILLMENT_ORDERS_READ,
    FULFILLMENT_ORDERS_MANAGE,
)

PROCUREMENT_OFFICER_PERMISSIONS = (
    ORGANIZATION_READ
    | CATALOG_READ
    | PROCUREMENT_READ
    | _codes(
        PROCUREMENT_SUPPLIERS_MANAGE,
        PROCUREMENT_REQUISITIONS_MANAGE,
        PROCUREMENT_ORDERS_MANAGE,
        PROCUREMENT_RETURNS_MANAGE,
        PROCUREMENT_INVOICES_MANAGE,
        WAREHOUSE_INVENTORY_READ,
        WAREHOUSE_RECEIVING_READ,
    )
)
PROCUREMENT_MANAGER_PERMISSIONS = PROCUREMENT_OFFICER_PERMISSIONS | _codes(
    REPORTS_OPERATIONS_READ,
    REPORTS_FINANCE_READ,
    FINANCE_INVOICES_READ,
    FINANCE_RECONCILIATION_READ,
)

SELLER_ADMIN_PERMISSIONS = (
    ORGANIZATION_READ
    | CATALOG_READ
    | _codes(
        MARKETPLACE_SELLERS_READ,
        MARKETPLACE_LISTINGS_READ,
        MARKETPLACE_LISTINGS_MANAGE,
        MARKETPLACE_COMMISSIONS_READ,
        COMMERCE_ORDERS_READ,
        FULFILLMENT_ORDERS_READ,
        LOGISTICS_SHIPMENTS_READ,
        FINANCE_RECONCILIATION_READ,
        REPORTS_OPERATIONS_READ,
    )
)
MARKETPLACE_MANAGER_PERMISSIONS = SELLER_ADMIN_PERMISSIONS | _codes(
    MARKETPLACE_SELLERS_MANAGE,
    MARKETPLACE_COMMISSIONS_MANAGE,
    CATALOG_PRODUCTS_MANAGE,
    PRICING_PRICES_MANAGE,
    REPORTS_FINANCE_READ,
)

CATALOG_MANAGER_PERMISSIONS = CATALOG_MANAGE | _codes(
    PRICING_PROMOTIONS_MANAGE,
    SEARCH_CONFIGURATION_READ,
    SEARCH_CONFIGURATION_MANAGE,
    REPORTS_OPERATIONS_READ,
)
PRICING_MANAGER_PERMISSIONS = CATALOG_READ | _codes(
    PRICING_PRICES_MANAGE,
    PRICING_PROMOTIONS_MANAGE,
    REPORTS_OPERATIONS_READ,
    REPORTS_FINANCE_READ,
)

SUPPORT_AGENT_PERMISSIONS = _codes(
    IDENTITY_USERS_READ,
    IDENTITY_PROFILES_READ,
    CUSTOMER_PROFILES_READ,
    CUSTOMER_ADDRESSES_READ,
    CUSTOMER_FAMILY_READ,
    CATALOG_PRODUCTS_READ,
    PRICING_PRICES_READ,
    COMMERCE_ORDERS_READ,
    COMMERCE_RETURNS_READ,
    PAYMENTS_READ,
    LOGISTICS_SHIPMENTS_READ,
    SUPPORT_TICKETS_READ,
    SUPPORT_TICKETS_CREATE,
    SUPPORT_TICKETS_MANAGE,
    NOTIFICATIONS_MESSAGES_READ,
)
SUPPORT_MANAGER_PERMISSIONS = SUPPORT_AGENT_PERMISSIONS | _codes(
    COMMERCE_ORDERS_MANAGE,
    COMMERCE_ORDERS_CANCEL,
    COMMERCE_RETURNS_MANAGE,
    PAYMENTS_REFUND,
    NOTIFICATIONS_MESSAGES_SEND,
    REPORTS_OPERATIONS_READ,
)

FINANCE_ANALYST_PERMISSIONS = _codes(
    COMMERCE_ORDERS_READ,
    COMMERCE_RETURNS_READ,
    PAYMENTS_READ,
    FINANCE_INVOICES_READ,
    FINANCE_RECONCILIATION_READ,
    FINANCE_LEDGER_READ,
    PROCUREMENT_INVOICES_READ,
    MARKETPLACE_COMMISSIONS_READ,
    REPORTS_FINANCE_READ,
)
FINANCE_MANAGER_PERMISSIONS = FINANCE_ANALYST_PERMISSIONS | _codes(
    PAYMENTS_MANAGE,
    PAYMENTS_REFUND,
    PAYMENTS_CHARGEBACKS_MANAGE,
    FINANCE_INVOICES_MANAGE,
    FINANCE_RECONCILIATION_MANAGE,
    FINANCE_LEDGER_MANAGE,
)

INSURANCE_COORDINATOR_PERMISSIONS = ORGANIZATION_READ | _codes(
    CLINICAL_PATIENTS_READ,
    DIAGNOSTICS_ORDERS_READ,
    INSURANCE_PLANS_READ,
    INSURANCE_POLICIES_READ,
    INSURANCE_POLICIES_MANAGE,
    INSURANCE_CLAIMS_READ,
    INSURANCE_CLAIMS_MANAGE,
)
INSURANCE_MANAGER_PERMISSIONS = INSURANCE_COORDINATOR_PERMISSIONS | _codes(
    INSURANCE_PLANS_MANAGE,
    REPORTS_FINANCE_READ,
    COMPLIANCE_AUDIT_READ,
)

COMPLIANCE_AUDITOR_PERMISSIONS = (
    IDENTITY_READ
    | ORGANIZATION_READ
    | _codes(
        CATALOG_REGULATORY_READ,
        COMMERCE_ORDERS_READ,
        COMMERCE_RETURNS_READ,
        PAYMENTS_READ,
        FINANCE_INVOICES_READ,
        FINANCE_RECONCILIATION_READ,
        CLINICAL_PATIENTS_READ,
        CLINICAL_PRESCRIPTIONS_READ,
        CLINICAL_CONSULTATIONS_READ,
        CLINICAL_DISPENSING_READ,
        DIAGNOSTICS_ORDERS_READ,
        DIAGNOSTICS_SAMPLES_READ,
        DIAGNOSTICS_RESULTS_READ,
        PROCUREMENT_SUPPLIERS_READ,
        MARKETPLACE_SELLERS_READ,
        INSURANCE_CLAIMS_READ,
        COMPLIANCE_AUDIT_READ,
        COMPLIANCE_CONSENTS_READ,
        COMPLIANCE_PRIVACY_READ,
        COMPLIANCE_ADVERSE_EVENTS_READ,
        RISK_SIGNALS_READ,
        RISK_RULES_READ,
        REPORTS_OPERATIONS_READ,
        REPORTS_FINANCE_READ,
        REPORTS_CLINICAL_READ,
    )
)
COMPLIANCE_OFFICER_PERMISSIONS = COMPLIANCE_AUDITOR_PERMISSIONS | _codes(
    ORGANIZATION_LICENSES_MANAGE,
    CATALOG_REGULATORY_MANAGE,
    COMPLIANCE_CONSENTS_MANAGE,
    COMPLIANCE_PRIVACY_MANAGE,
    COMPLIANCE_ADVERSE_EVENTS_MANAGE,
)

RISK_ANALYST_PERMISSIONS = _codes(
    IDENTITY_USERS_READ,
    COMMERCE_ORDERS_READ,
    PAYMENTS_READ,
    PAYMENTS_CHARGEBACKS_MANAGE,
    SUPPORT_TICKETS_READ,
    RISK_SIGNALS_READ,
    RISK_SIGNALS_MANAGE,
    RISK_RULES_READ,
    COMPLIANCE_AUDIT_READ,
)
RISK_MANAGER_PERMISSIONS = RISK_ANALYST_PERMISSIONS | _codes(
    RISK_RULES_MANAGE,
    REPORTS_OPERATIONS_READ,
    REPORTS_FINANCE_READ,
)

ORGANIZATION_ADMIN_PERMISSIONS = (
    IDENTITY_READ
    | ORGANIZATION_READ
    | _codes(
        IDENTITY_PROFILES_MANAGE,
        IDENTITY_USER_ROLES_MANAGE,
        ORGANIZATIONS_MANAGE,
        ORGANIZATION_LOCATIONS_MANAGE,
        ORGANIZATION_DEPARTMENTS_MANAGE,
        ORGANIZATION_MEMBERSHIPS_MANAGE,
        ORGANIZATION_LICENSES_MANAGE,
    )
)
IDENTITY_ADMIN_PERMISSIONS = IDENTITY_ADMIN | _codes(COMPLIANCE_AUDIT_READ)

OPERATIONS_MANAGER_PERMISSIONS = (
    ORGANIZATION_READ
    | CATALOG_READ
    | WAREHOUSE_READ
    | _codes(
        COMMERCE_ORDERS_READ,
        COMMERCE_ORDERS_MANAGE,
        COMMERCE_ORDERS_CANCEL,
        COMMERCE_RETURNS_READ,
        COMMERCE_RETURNS_MANAGE,
        FULFILLMENT_ORDERS_READ,
        FULFILLMENT_ORDERS_MANAGE,
        LOGISTICS_SHIPMENTS_READ,
        LOGISTICS_SHIPMENTS_MANAGE,
        LOGISTICS_ASSIGN,
        SUPPORT_TICKETS_READ,
        SUPPORT_TICKETS_MANAGE,
        REPORTS_OPERATIONS_READ,
    )
)

PLATFORM_ADMIN_PERMISSIONS = (
    ORGANIZATION_ADMIN_PERMISSIONS
    | CATALOG_MANAGER_PERMISSIONS
    | PRICING_MANAGER_PERMISSIONS
    | WAREHOUSE_MANAGER_PERMISSIONS
    | LOGISTICS_MANAGER_PERMISSIONS
    | PROCUREMENT_MANAGER_PERMISSIONS
    | MARKETPLACE_MANAGER_PERMISSIONS
    | SUPPORT_MANAGER_PERMISSIONS
    | FINANCE_MANAGER_PERMISSIONS
    | INSURANCE_MANAGER_PERMISSIONS
    | RISK_MANAGER_PERMISSIONS
    | _codes(
        PLATFORM_SETTINGS_READ,
        PLATFORM_SETTINGS_MANAGE,
        PLATFORM_FILES_READ,
        PLATFORM_FILES_MANAGE,
        PLATFORM_JOBS_READ,
        PLATFORM_JOBS_MANAGE,
        NOTIFICATIONS_MESSAGES_READ,
        NOTIFICATIONS_MESSAGES_SEND,
        NOTIFICATIONS_TEMPLATES_MANAGE,
        SEARCH_CONFIGURATION_READ,
        SEARCH_CONFIGURATION_MANAGE,
        COMPLIANCE_AUDIT_READ,
    )
) - _codes(
    IDENTITY_PERMISSIONS_MANAGE,
    CLINICAL_PRESCRIPTIONS_ISSUE,
    CLINICAL_PRESCRIPTIONS_VERIFY,
    CLINICAL_DISPENSING_APPROVE,
    DIAGNOSTICS_RESULTS_VERIFY,
)


ROLE_SEEDS: tuple[RoleSeed, ...] = (
    RoleSeed(
        code="customer",
        name="Customer",
        description=(
            "Healthcare-commerce customer. Domain services must enforce ownership "
            "and family-member authorization for every record."
        ),
        permission_codes=CUSTOMER_PERMISSIONS,
    ),
    RoleSeed(
        code="caregiver",
        name="Caregiver",
        description=(
            "Authorized caregiver acting for permitted family members or patients; "
            "consent and relationship checks remain mandatory."
        ),
        permission_codes=CAREGIVER_PERMISSIONS,
    ),
    RoleSeed(
        code="doctor",
        name="Doctor",
        description=(
            "Practitioner managing assigned appointments, consultations, and prescriptions."
        ),
        permission_codes=DOCTOR_PERMISSIONS,
    ),
    RoleSeed(
        code="pharmacist",
        name="Pharmacist",
        description="Pharmacist verifying prescriptions and recording medicine dispensing.",
        permission_codes=PHARMACIST_PERMISSIONS,
    ),
    RoleSeed(
        code="pharmacy_manager",
        name="Pharmacy Manager",
        description="Pharmacy supervisor responsible for stock, orders, and dispensing approvals.",
        permission_codes=PHARMACY_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="lab_technician",
        name="Lab Technician",
        description=(
            "Diagnostic technician collecting and processing samples and recording results."
        ),
        permission_codes=LAB_TECHNICIAN_PERMISSIONS,
    ),
    RoleSeed(
        code="pathologist",
        name="Pathologist",
        description="Authorized clinical reviewer verifying and releasing diagnostic reports.",
        permission_codes=PATHOLOGIST_PERMISSIONS,
    ),
    RoleSeed(
        code="lab_manager",
        name="Lab Manager",
        description="Diagnostic-lab supervisor maintaining offerings and operational workflows.",
        permission_codes=LAB_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="warehouse_receiver",
        name="Warehouse Receiver",
        description="Warehouse staff receiving goods and completing receiving quality checks.",
        permission_codes=WAREHOUSE_RECEIVER_PERMISSIONS,
    ),
    RoleSeed(
        code="warehouse_picker",
        name="Warehouse Picker",
        description="Warehouse staff executing assigned picking work.",
        permission_codes=WAREHOUSE_PICKER_PERMISSIONS,
    ),
    RoleSeed(
        code="warehouse_packer",
        name="Warehouse Packer",
        description="Warehouse staff executing assigned packing and package creation work.",
        permission_codes=WAREHOUSE_PACKER_PERMISSIONS,
    ),
    RoleSeed(
        code="warehouse_operator",
        name="Warehouse Operator",
        description="Cross-functional warehouse operator handling receiving, picking, and packing.",
        permission_codes=WAREHOUSE_OPERATOR_PERMISSIONS,
    ),
    RoleSeed(
        code="warehouse_manager",
        name="Warehouse Manager",
        description="Warehouse supervisor controlling inventory, layout, counts, and fulfillment.",
        permission_codes=WAREHOUSE_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="delivery_agent",
        name="Delivery Agent",
        description="Delivery staff updating only assigned shipment and COD progress.",
        permission_codes=DELIVERY_AGENT_PERMISSIONS,
    ),
    RoleSeed(
        code="delivery_dispatcher",
        name="Delivery Dispatcher",
        description="Dispatcher assigning shipments and coordinating delivery routes.",
        permission_codes=DELIVERY_DISPATCHER_PERMISSIONS,
    ),
    RoleSeed(
        code="logistics_manager",
        name="Logistics Manager",
        description="Logistics supervisor managing carriers, shipments, routes, and exceptions.",
        permission_codes=LOGISTICS_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="procurement_officer",
        name="Procurement Officer",
        description=(
            "Procurement staff managing suppliers, requisitions, orders, returns, and invoices."
        ),
        permission_codes=PROCUREMENT_OFFICER_PERMISSIONS,
    ),
    RoleSeed(
        code="procurement_manager",
        name="Procurement Manager",
        description="Procurement supervisor approving sourcing and supplier financial workflows.",
        permission_codes=PROCUREMENT_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="seller_admin",
        name="Seller Administrator",
        description=(
            "Seller-side administrator maintaining own listings and operational visibility."
        ),
        permission_codes=SELLER_ADMIN_PERMISSIONS,
    ),
    RoleSeed(
        code="marketplace_manager",
        name="Marketplace Manager",
        description="Platform staff onboarding sellers and managing listings and commissions.",
        permission_codes=MARKETPLACE_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="catalog_manager",
        name="Catalog Manager",
        description=(
            "Merchandising staff maintaining products, categories, content, and search metadata."
        ),
        permission_codes=CATALOG_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="pricing_manager",
        name="Pricing Manager",
        description="Commercial staff maintaining prices, promotions, coupons, and tax rules.",
        permission_codes=PRICING_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="support_agent",
        name="Support Agent",
        description=(
            "Customer-support staff handling permitted account, order, "
            "payment, and delivery queries."
        ),
        permission_codes=SUPPORT_AGENT_PERMISSIONS,
    ),
    RoleSeed(
        code="support_manager",
        name="Support Manager",
        description=(
            "Support supervisor handling escalations, returns, cancellations, and eligible refunds."
        ),
        permission_codes=SUPPORT_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="finance_analyst",
        name="Finance Analyst",
        description=(
            "Read-focused finance staff reviewing payments, invoices, settlements, and ledgers."
        ),
        permission_codes=FINANCE_ANALYST_PERMISSIONS,
    ),
    RoleSeed(
        code="finance_manager",
        name="Finance Manager",
        description=(
            "Finance supervisor responsible for refunds, chargebacks, "
            "reconciliation, and ledger posting."
        ),
        permission_codes=FINANCE_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="insurance_coordinator",
        name="Insurance Coordinator",
        description="Insurance operations staff managing eligibility, policies, and claims.",
        permission_codes=INSURANCE_COORDINATOR_PERMISSIONS,
    ),
    RoleSeed(
        code="insurance_manager",
        name="Insurance Manager",
        description="Insurance supervisor maintaining plans and overseeing claims operations.",
        permission_codes=INSURANCE_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="compliance_auditor",
        name="Compliance Auditor",
        description="Read-only compliance access to regulated records and audit evidence.",
        permission_codes=COMPLIANCE_AUDITOR_PERMISSIONS,
    ),
    RoleSeed(
        code="compliance_officer",
        name="Compliance Officer",
        description=(
            "Compliance staff managing consent, privacy, regulatory, and adverse-event workflows."
        ),
        permission_codes=COMPLIANCE_OFFICER_PERMISSIONS,
    ),
    RoleSeed(
        code="risk_analyst",
        name="Risk Analyst",
        description="Risk staff reviewing fraud, abuse, account, payment, and operational signals.",
        permission_codes=RISK_ANALYST_PERMISSIONS,
    ),
    RoleSeed(
        code="risk_manager",
        name="Risk Manager",
        description="Risk supervisor managing decision rules, blocklists, and escalations.",
        permission_codes=RISK_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="organization_admin",
        name="Organization Administrator",
        description=(
            "Tenant or provider administrator managing workforce, facilities, "
            "and scoped role assignments."
        ),
        permission_codes=ORGANIZATION_ADMIN_PERMISSIONS,
    ),
    RoleSeed(
        code="operations_manager",
        name="Operations Manager",
        description=(
            "Operations staff coordinating orders, fulfillment, warehouse, support, and delivery."
        ),
        permission_codes=OPERATIONS_MANAGER_PERMISSIONS,
    ),
    RoleSeed(
        code="identity_admin",
        name="Identity Administrator",
        description=(
            "Security administrator managing accounts, profiles, sessions, "
            "roles, permissions, and API clients."
        ),
        permission_codes=IDENTITY_ADMIN_PERMISSIONS,
    ),
    RoleSeed(
        code="platform_admin",
        name="Platform Administrator",
        description=(
            "Broad non-clinical platform administrator. Clinical authoring, clinical "
            "verification, and permission-definition changes remain separated."
        ),
        permission_codes=PLATFORM_ADMIN_PERMISSIONS,
    ),
    RoleSeed(
        code="super_admin",
        name="Super Administrator",
        description="Emergency platform owner with every permission managed by this manifest.",
        permission_codes=ALL_PERMISSION_CODES,
    ),
)

_ROLE_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_RESOURCE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_ACTION_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")


def validate_seed_manifest() -> None:
    """Fail before database access when the static RBAC manifest is invalid."""
    permission_codes = [seed.code for seed in PERMISSION_SEEDS]
    if len(permission_codes) != len(set(permission_codes)):
        raise ValueError("Permission seed codes must be unique.")

    for permission_seed in PERMISSION_SEEDS:
        if not _RESOURCE_PATTERN.fullmatch(permission_seed.resource):
            raise ValueError(f"Invalid permission resource: {permission_seed.resource}")
        if not _ACTION_PATTERN.fullmatch(permission_seed.action):
            raise ValueError(f"Invalid permission action: {permission_seed.action}")
        if len(permission_seed.code) > 128:
            raise ValueError(f"Permission code is too long: {permission_seed.code}")
        if not permission_seed.description.strip():
            raise ValueError(f"Permission '{permission_seed.code}' requires a description.")

    role_codes = [seed.code for seed in ROLE_SEEDS]
    if len(role_codes) != len(set(role_codes)):
        raise ValueError("Role seed codes must be unique.")

    for role_seed in ROLE_SEEDS:
        if not _ROLE_CODE_PATTERN.fullmatch(role_seed.code):
            raise ValueError(f"Invalid role code: {role_seed.code}")
        if not role_seed.name.strip() or not role_seed.description.strip():
            raise ValueError(f"Role '{role_seed.code}' requires a name and description.")
        if not role_seed.permission_codes:
            raise ValueError(f"Role '{role_seed.code}' must contain at least one permission.")

        missing = role_seed.permission_codes - ALL_PERMISSION_CODES
        if missing:
            raise ValueError(
                f"Role '{role_seed.code}' references unknown permissions: {sorted(missing)}"
            )

        # Mutation permissions should normally include the corresponding read
        # permission so the actor can inspect the resource before changing it.
        for permission_code in role_seed.permission_codes:
            resource, _, action = permission_code.rpartition(".")
            read_code = f"{resource}.read"
            if (
                action != "read"
                and read_code in ALL_PERMISSION_CODES
                and read_code not in role_seed.permission_codes
            ):
                raise ValueError(
                    f"Role '{role_seed.code}' can '{action}' '{resource}' without read access."
                )

    super_admin = next(seed for seed in ROLE_SEEDS if seed.code == "super_admin")
    if super_admin.permission_codes != ALL_PERMISSION_CODES:
        raise ValueError("The super_admin role must contain every managed permission.")


async def seed_identity_master_data(settings: AppSettings) -> SeedSummary:
    """Persist the managed RBAC manifest in one PostgreSQL transaction."""
    validate_seed_manifest()
    database = PostgreSQLDatabase(settings)

    try:
        async with database.session() as session, SQLAlchemyUnitOfWork(session):
            # Serialize concurrent deployments running this deterministic seed.
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": "identity-master-data-seed-v2"},
            )

            permissions, permission_counts = await _upsert_permissions(session)
            roles, role_counts = await _upsert_roles(session)
            await session.flush()

            await _ensure_default_role(
                session,
                settings.DEFAULT_ROLE_CODE,
            )
            mapping_counts = await _synchronize_role_permissions(
                session,
                roles=roles,
                permissions=permissions,
            )

            return SeedSummary(
                permissions_created=permission_counts[0],
                permissions_updated=permission_counts[1],
                roles_created=role_counts[0],
                roles_updated=role_counts[1],
                mappings_created=mapping_counts[0],
                mappings_removed=mapping_counts[1],
            )
    finally:
        await database.close()


async def _upsert_permissions(
    session: AsyncSession,
) -> tuple[dict[str, Permissions], tuple[int, int]]:
    """Create missing active permissions and refresh managed definitions."""
    result = await session.scalars(
        select(Permissions)
        .where(
            Permissions.code.in_(ALL_PERMISSION_CODES),
            Permissions.is_deleted.is_(False),
        )
        .with_for_update()
    )
    by_code = {record.code: record for record in result}
    created = 0
    updated = 0

    for seed in PERMISSION_SEEDS:
        record = by_code.get(seed.code)
        if record is None:
            record = Permissions(
                code=seed.code,
                resource=seed.resource,
                action=seed.action,
                description=seed.description,
            )
            session.add(record)
            by_code[seed.code] = record
            created += 1
            continue

        changed = (
            record.resource != seed.resource
            or record.action != seed.action
            or record.description != seed.description
        )
        if changed:
            record.resource = seed.resource
            record.action = seed.action
            record.description = seed.description
            record.updated_by = None
            updated += 1

    return by_code, (created, updated)


async def _upsert_roles(
    session: AsyncSession,
) -> tuple[dict[str, Roles], tuple[int, int]]:
    """Create or refresh managed roles and protect them as system roles."""
    managed_codes = frozenset(seed.code for seed in ROLE_SEEDS)
    result = await session.scalars(
        select(Roles)
        .where(
            Roles.code.in_(managed_codes),
            Roles.is_deleted.is_(False),
        )
        .with_for_update()
    )
    by_code = {record.code: record for record in result}
    created = 0
    updated = 0

    for seed in ROLE_SEEDS:
        record = by_code.get(seed.code)
        if record is None:
            record = Roles(
                code=seed.code,
                name=seed.name,
                description=seed.description,
                is_system=True,
            )
            session.add(record)
            by_code[seed.code] = record
            created += 1
            continue

        changed = (
            record.name != seed.name
            or record.description != seed.description
            or not record.is_system
        )
        if changed:
            record.name = seed.name
            record.description = seed.description
            record.is_system = True
            record.updated_by = None
            updated += 1

    return by_code, (created, updated)


async def _ensure_default_role(
    session: AsyncSession,
    default_role_code: str,
) -> None:
    """Ensure registration can resolve the configured default role."""
    role_id = await session.scalar(
        select(Roles.id).where(
            Roles.code == default_role_code,
            Roles.is_deleted.is_(False),
        )
    )
    if role_id is None:
        raise RuntimeError(
            f"DEFAULT_ROLE_CODE '{default_role_code}' does not identify an active role."
        )


async def _synchronize_role_permissions(
    session: AsyncSession,
    *,
    roles: dict[str, Roles],
    permissions: dict[str, Permissions],
) -> tuple[int, int]:
    """Make mappings exact only for roles owned by this seed manifest."""
    role_ids = {record.id for record in roles.values()}
    current_records = list(
        (
            await session.scalars(
                select(RolePermissions)
                .where(RolePermissions.role_id.in_(role_ids))
                .with_for_update()
            )
        ).all()
    )
    current_by_pair = {(record.role_id, record.permission_id): record for record in current_records}
    target_pairs = {
        (roles[role.code].id, permissions[permission_code].id)
        for role in ROLE_SEEDS
        for permission_code in role.permission_codes
    }

    stale_pairs = current_by_pair.keys() - target_pairs
    for pair in stale_pairs:
        await session.delete(current_by_pair[pair])

    missing_pairs = target_pairs - current_by_pair.keys()
    session.add_all(
        [
            RolePermissions(
                role_id=role_id,
                permission_id=permission_id,
            )
            for role_id, permission_id in sorted(
                missing_pairs,
                key=lambda pair: (str(pair[0]), str(pair[1])),
            )
        ]
    )

    return len(missing_pairs), len(stale_pairs)


def _parser() -> argparse.ArgumentParser:
    """Build the command-line parser without accepting database secrets."""
    parser = argparse.ArgumentParser(
        description=("Seed healthcare-platform identity roles and permissions."),
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate the static manifest without connecting to PostgreSQL.",
    )
    return parser


def main() -> int:
    """Validate the manifest and seed it using environment configuration."""
    args = _parser().parse_args()
    validate_seed_manifest()

    if args.check_only:
        print(f"Manifest valid: {len(ROLE_SEEDS)} roles, {len(PERMISSION_SEEDS)} permissions.")
        return 0

    summary = asyncio.run(seed_identity_master_data(AppSettings()))
    print(
        "Identity master data seeded: "
        f"permissions(created={summary.permissions_created}, "
        f"updated={summary.permissions_updated}), "
        f"roles(created={summary.roles_created}, "
        f"updated={summary.roles_updated}), "
        f"mappings(created={summary.mappings_created}, "
        f"removed={summary.mappings_removed})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
