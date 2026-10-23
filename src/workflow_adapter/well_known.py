from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OAuthProtectedResourceConfig:
    """Configuration for RFC 9728 /.well-known/oauth-protected-resource metadata."""

    resource_uri: str
    issuer_url: str
    scopes_supported: tuple[str, ...] = ("mcp:service", "mcp:tools")

    def to_metadata_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource_uri,
            "authorization_servers": [self.issuer_url],
            "scopes_supported": list(self.scopes_supported),
            "bearer_methods_supported": ["header"],
            "resource_documentation": "https://modelcontextprotocol.io/specification",
        }
