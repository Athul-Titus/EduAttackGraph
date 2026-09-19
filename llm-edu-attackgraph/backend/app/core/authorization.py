"""
Authorization Manager — Safety-critical component.

Only allowlisted targets may be scanned.
Implements SSRF protection and input validation.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import List, Optional

from app.config import settings, AuthorizedTargetMode


# Private/reserved IP ranges that should never be accessed in strict mode
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]

LOOPBACK_ADDRESSES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class AuthorizationError(Exception):
    """Raised when a target is not authorized for scanning."""
    pass


class AuthorizationManager:
    """
    Enforces target authorization.

    In ALLOWLIST mode: only explicitly listed targets are allowed.
    In LAB mode: private IP ranges are also allowed (for lab environments).

    This is a safety-critical component — never bypass it.
    """

    def __init__(
        self,
        mode: AuthorizedTargetMode = AuthorizedTargetMode.ALLOWLIST,
        allowlist: Optional[List[str]] = None,
    ):
        self.mode = mode
        self.allowlist = allowlist or settings.allowed_targets

    def validate_target(self, target: str, is_admin: bool = False) -> str:
        """
        Validate a target hostname or IP.

        Returns the validated target string.
        Raises AuthorizationError if not authorized.
        """
        target = target.strip().lower()

        # Basic validation
        if not target:
            raise AuthorizationError("Empty target is not allowed.")

        # Check for obviously malicious input
        self._check_for_injection(target)

        # Authenticated admin has authorization privilege to add and authorize targets
        if is_admin:
            return target

        # Resolve to IP for SSRF check
        resolved_ip = self._resolve_target(target)

        if self.mode == AuthorizedTargetMode.ALLOWLIST:
            self._check_allowlist(target, resolved_ip)
        elif self.mode == AuthorizedTargetMode.LAB:
            self._check_lab_mode(target, resolved_ip)
        elif self.mode == AuthorizedTargetMode.LOCALHOST_ONLY:
            self._check_localhost(target, resolved_ip)

        return target

    def _check_localhost(self, target: str, resolved_ip: Optional[str]) -> None:
        """LOCALHOST_ONLY mode: only loopback addresses permitted."""
        base = target.split(":")[0].strip("[]")
        if base in LOOPBACK_ADDRESSES or (resolved_ip and resolved_ip in LOOPBACK_ADDRESSES):
            return
        raise AuthorizationError(
            f"Target '{target}' is not authorized. "
            "In LOCALHOST_ONLY mode, only 127.0.0.1, localhost, and ::1 are permitted."
        )

    def _check_for_injection(self, target: str) -> None:
        """Check for obvious injection attempts."""
        # Only allow alphanumeric, dots, hyphens, colons (IPv6), brackets
        if not re.match(r'^[a-zA-Z0-9.\-:\[\]_]+$', target):
            raise AuthorizationError(
                f"Target '{target}' contains invalid characters. "
                "Only hostname/IP format is accepted."
            )

        # Reject obviously shell-injection-like patterns
        dangerous_patterns = [";", "|", "&", "`", "$", "(", ")", "<", ">", "\n", "\r"]
        for p in dangerous_patterns:
            if p in target:
                raise AuthorizationError(f"Target contains illegal character: {p!r}")

    def _resolve_target(self, target: str) -> Optional[str]:
        """
        Resolve hostname to IP for SSRF protection.
        Returns None if resolution fails (still may be checked against allowlist by hostname).
        """
        try:
            # Strip port if present
            hostname = target.split(":")[0].strip("[]")
            resolved = socket.gethostbyname(hostname)
            return resolved
        except socket.gaierror:
            return None

    def _check_allowlist(self, target: str, resolved_ip: Optional[str]) -> None:
        """ALLOWLIST mode: target must be explicitly listed."""
        # Check hostname directly
        if target in self.allowlist:
            return
        # Check resolved IP
        if resolved_ip and resolved_ip in self.allowlist:
            return
        # Check without port
        base = target.split(":")[0].strip("[]")
        if base in self.allowlist:
            return

        raise AuthorizationError(
            f"Target '{target}' is not in the authorized allowlist. "
            f"Allowlist: {self.allowlist}. "
            "Add the target to TARGET_ALLOWLIST in your .env file to scan it."
        )

    def _check_lab_mode(self, target: str, resolved_ip: Optional[str]) -> None:
        """LAB mode: allow private IP ranges for lab environments."""
        # Always allow loopback
        base = target.split(":")[0].strip("[]")
        if base in LOOPBACK_ADDRESSES or (resolved_ip and resolved_ip in LOOPBACK_ADDRESSES):
            return

        # Check allowlist first
        if base in self.allowlist or (resolved_ip and resolved_ip in self.allowlist):
            return

        # Check if IP is in private range (lab-safe)
        if resolved_ip:
            try:
                ip_obj = ipaddress.ip_address(resolved_ip)
                for network in PRIVATE_NETWORKS:
                    if ip_obj in network:
                        return
            except ValueError:
                pass

        raise AuthorizationError(
            f"Target '{target}' is not authorized. "
            "In LAB mode, only private IP ranges (192.168.x.x, 10.x.x.x, 172.16.x.x) "
            "and explicitly allowlisted targets are permitted."
        )


# Global instance
auth_manager = AuthorizationManager(
    mode=settings.AUTHORIZED_TARGET_MODE,
    allowlist=settings.allowed_targets,
)
