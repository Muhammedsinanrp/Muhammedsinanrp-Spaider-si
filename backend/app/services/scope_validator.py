"""
SPAIDER Scope Validation Service
Ensures scans ONLY execute against authorized targets and prevents out-of-scope testing.
"""

import ipaddress
import urllib.parse
from datetime import datetime
from typing import Tuple, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.models import Scope, Target


def extract_host(target_str: str) -> str:
    """Extract clean hostname or IP from target string or URL."""
    target_clean = target_str.strip()
    if "://" in target_clean:
        parsed = urllib.parse.urlparse(target_clean)
        return parsed.hostname or target_clean
    # Strip port if present (e.g., 192.168.1.50:3000)
    if ":" in target_clean and not target_clean.count(":") > 1:  # not IPv6
        return target_clean.split(":")[0]
    return target_clean


def is_ip_in_network(ip_str: str, net_str: str) -> bool:
    """Check if IP is within CIDR network or matches exactly."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if "/" in net_str:
            net = ipaddress.ip_network(net_str, strict=False)
            return ip in net
        return ip == ipaddress.ip_address(net_str)
    except ValueError:
        return False


def matches_scope_pattern(target_host: str, pattern: str) -> bool:
    """Check if host matches scope rule (domain, wildcard, IP, CIDR)."""
    pattern_clean = pattern.strip()
    pattern_host = extract_host(pattern_clean)

    # Exact host match
    if target_host.lower() == pattern_host.lower():
        return True

    # Wildcard domain match (*.example.com)
    if pattern_host.startswith("*."):
        suffix = pattern_host[1:].lower()
        if target_host.lower().endswith(suffix):
            return True

    # Subdomain match if pattern is a root domain
    if target_host.lower().endswith("." + pattern_host.lower()):
        return True

    # IP / CIDR check
    if is_ip_in_network(target_host, pattern_clean):
        return True

    return False


class ScopeValidator:
    """Validator utility class for scope authorization."""

    @staticmethod
    def extract_host(target_str: str) -> str:
        return extract_host(target_str)

    @staticmethod
    def matches_pattern(target_host: str, pattern: str) -> bool:
        return matches_scope_pattern(target_host, pattern)

    @staticmethod
    def validate_target(scope: Scope, target_input: str) -> Tuple[bool, str]:
        """Synchronously validate target against a single Scope model."""
        target_host = extract_host(target_input)
        now = datetime.utcnow()

        if scope.authorization_status != "AUTHORIZED":
            return False, f"Scope '{scope.name}' is not AUTHORIZED (status: {scope.authorization_status})"

        if scope.valid_until and scope.valid_until < now:
            return False, f"Scope '{scope.name}' has expired on {scope.valid_until}"

        if scope.expires_at and scope.expires_at < now:
            return False, f"Scope '{scope.name}' has expired"

        # Check excluded
        for excl in scope.excluded_targets or []:
            if matches_scope_pattern(target_host, str(excl)):
                return False, f"Target '{target_input}' is explicitly excluded in scope '{scope.name}'"

        # Check allowed targets
        matched = False
        for allowed in scope.targets or []:
            if matches_scope_pattern(target_host, str(allowed)):
                matched = True
                break

        if not matched and scope.value:
            if matches_scope_pattern(target_host, scope.value):
                matched = True

        if not matched:
            return False, f"Target '{target_input}' (host: {target_host}) not found in authorized targets of scope '{scope.name}'"

        if not scope.active_testing:
            return False, f"Active testing is disabled for scope '{scope.name}'"

        return True, f"Target '{target_input}' is authorized"


async def validate_target_scope(
    target_input: str,
    db: AsyncSession,
    scope_id: Optional[str] = None,
) -> Tuple[bool, str, Optional[Scope]]:
    """
    Validate whether a target is permitted for active scanning.
    Returns: (is_authorized, reason, matching_scope)
    """
    target_host = extract_host(target_input)

    # Fetch active scopes
    stmt = select(Scope).where(Scope.authorization_status == "AUTHORIZED")
    if scope_id:
        stmt = stmt.where(Scope.id == scope_id)

    result = await db.execute(stmt)
    scopes = result.scalars().all()

    now = datetime.utcnow()
    matching_scope: Optional[Scope] = None

    for scope in scopes:
        # Check validity window
        if scope.valid_until and scope.valid_until < now:
            continue
        if scope.expires_at and scope.expires_at < now:
            continue

        # Check excluded targets first
        is_excluded = False
        for excl in scope.excluded_targets or []:
            if matches_scope_pattern(target_host, str(excl)):
                is_excluded = True
                break
        if is_excluded:
            continue

        # Check scope targets list
        for allowed in scope.targets or []:
            if matches_scope_pattern(target_host, str(allowed)):
                matching_scope = scope
                break

        # Check scope single value field
        if not matching_scope and scope.value:
            if matches_scope_pattern(target_host, scope.value):
                matching_scope = scope

        if matching_scope:
            break

    if not matching_scope:
        return (
            False,
            f"Target '{target_input}' (host: {target_host}) is NOT in any AUTHORIZED testing scope. Scanning rejected.",
            None,
        )

    if not matching_scope.active_testing:
        return (
            False,
            f"Scope '{matching_scope.name}' has active_testing=False. Active scanning is disabled for this scope.",
            matching_scope,
        )

    return (
        True,
        f"Target '{target_input}' authorized under scope '{matching_scope.name}' (Authorized by: {matching_scope.authorized_by or 'SecOps'}).",
        matching_scope,
    )
