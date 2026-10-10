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
    """Match a target URL/host against a scope entry.

    URL-shaped scope entries constrain scheme and explicit port as well as host.
    Plain domain and CIDR entries retain their host/subdomain/network semantics.
    A URL path in the scope acts as a path prefix.
    """
    target_raw = str(target_host).strip()
    pattern_clean = str(pattern).strip()
    if not target_raw or not pattern_clean:
        return False

    target_has_scheme = "://" in target_raw
    pattern_has_scheme = "://" in pattern_clean
    try:
        target_parsed = urllib.parse.urlsplit(target_raw if target_has_scheme else f"//{target_raw}")
        pattern_parsed = urllib.parse.urlsplit(pattern_clean if pattern_has_scheme else f"//{pattern_clean}")
        target_port = target_parsed.port
        pattern_port = pattern_parsed.port
    except ValueError:
        return False

    target_name = (target_parsed.hostname or extract_host(target_raw)).lower().rstrip(".")
    pattern_name = (pattern_parsed.hostname or extract_host(pattern_clean)).lower().rstrip(".")

    # An URL scope represents one origin. Do not allow changing http<->https
    # or scanning a different port because the hostname happens to match.
    if pattern_has_scheme:
        # URL/origin scopes authorize HTTP(S) testing only, not a bare-host port
        # scan. Network scanners need a separate domain, IP, or CIDR scope.
        if not target_has_scheme:
            return False
        if target_parsed.scheme.lower() != pattern_parsed.scheme.lower():
            return False
        default_port = 443 if target_parsed.scheme.lower() == "https" else 80
        scope_default_port = 443 if pattern_parsed.scheme.lower() == "https" else 80
        actual_port = target_port or default_port
        allowed_port = pattern_port or scope_default_port
        if actual_port != allowed_port:
            return False
    elif pattern_port is not None and target_port != pattern_port:
        return False

    # If the scope entry includes a non-root path, limit the target to it.
    scope_path = pattern_parsed.path.rstrip("/")
    if pattern_has_scheme and scope_path:
        target_path = (target_parsed.path or "/").rstrip("/")
        if target_path != scope_path and not target_path.startswith(scope_path + "/"):
            return False

    # Exact host match.
    if target_name == pattern_name:
        return True

    # Wildcard domains (*.example.com).
    if pattern_name.startswith("*."):
        suffix = pattern_name[1:]
        return target_name.endswith(suffix) and target_name != pattern_name[2:]

    # A bare root domain permits its subdomains.
    if target_name.endswith("." + pattern_name):
        return True

    # IP address and CIDR scopes.
    if is_ip_in_network(target_name, pattern_clean):
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

        if scope.valid_from and scope.valid_from > now:
            return False, f"Scope '{scope.name}' is not valid until {scope.valid_from}"

        if scope.valid_until and scope.valid_until < now:
            return False, f"Scope '{scope.name}' has expired on {scope.valid_until}"

        if scope.expires_at and scope.expires_at < now:
            return False, f"Scope '{scope.name}' has expired"

        if not str(scope.authorized_by or "").strip():
            return False, f"Scope '{scope.name}' is missing the authorizing person."

        if not str(scope.authorization_document or "").strip():
            return False, f"Scope '{scope.name}' is missing an authorization document reference."

        # Check excluded
        for excl in scope.excluded_targets or []:
            if matches_scope_pattern(target_input, str(excl)):
                return False, f"Target '{target_input}' is explicitly excluded in scope '{scope.name}'"

        # Check allowed targets
        matched = False
        for allowed in scope.targets or []:
            if matches_scope_pattern(target_input, str(allowed)):
                matched = True
                break

        if not matched and scope.value:
            if matches_scope_pattern(target_input, scope.value):
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
    Validate an active scan target against an explicit authorization scope.

    Continue evaluating candidate scopes when one matches but is expired,
    disabled, excluded, or missing authorization evidence; an older unusable
    record must not shadow a newer valid scope for the same authorized target.
    """
    target_host = extract_host(target_input)
    stmt = select(Scope).where(Scope.authorization_status == "AUTHORIZED")
    if scope_id:
        stmt = stmt.where(Scope.id == scope_id)

    result = await db.execute(stmt)
    scopes = result.scalars().all()
    now = datetime.utcnow()
    missing_document_scope: Optional[Scope] = None
    inactive_scope: Optional[Scope] = None
    future_scope: Optional[Scope] = None

    for scope in scopes:
        if scope.valid_from and scope.valid_from > now:
            future_scope = future_scope or scope
            continue
        if scope.valid_until and scope.valid_until < now:
            continue
        if scope.expires_at and scope.expires_at < now:
            continue

        # Exclusions apply within the scope that declares them.
        if any(matches_scope_pattern(target_input, str(excl)) for excl in scope.excluded_targets or []):
            continue

        allowed = any(matches_scope_pattern(target_input, str(pattern)) for pattern in scope.targets or [])
        if not allowed and scope.value:
            allowed = matches_scope_pattern(target_input, scope.value)
        if not allowed:
            continue

        if not str(scope.authorized_by or "").strip() or not str(scope.authorization_document or "").strip():
            missing_document_scope = missing_document_scope or scope
            continue
        if not scope.active_testing:
            inactive_scope = inactive_scope or scope
            continue

        return (
            True,
            f"Target '{target_input}' authorized under scope '{scope.name}' "
            f"(Authorized by: {scope.authorized_by}).",
            scope,
        )

    if inactive_scope:
        return (
            False,
            f"Matching scope '{inactive_scope.name}' has active_testing=False. Active scanning is disabled.",
            inactive_scope,
        )
    if missing_document_scope:
        if not str(missing_document_scope.authorized_by or "").strip():
            detail = "no authorizing person is recorded"
        else:
            detail = "no authorization document reference is recorded"
        return (
            False,
            f"Matching scope '{missing_document_scope.name}' has {detail}. Scanning rejected.",
            missing_document_scope,
        )
    if future_scope:
        return (
            False,
            f"A matching scope is not valid until {future_scope.valid_from}. Scanning rejected.",
            future_scope,
        )

    return (
        False,
        f"Target '{target_input}' (host: {target_host}) is NOT in any active, unexpired AUTHORIZED testing scope. Scanning rejected.",
        None,
    )
