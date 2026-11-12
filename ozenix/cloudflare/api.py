"""Minimal Cloudflare API v4 client (stdlib only).

The token is held in memory only for the lifetime of the client and is sent
solely in the Authorization header to api.cloudflare.com over HTTPS with
certificate verification. Responses never contain the token.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

API = "https://api.cloudflare.com/client/v4"
TIMEOUT = 30.0
MAX_PAGES = 50

# (method, url, headers, body) -> (status, parsed JSON)
Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, dict[str, Any]]]


class CloudflareError(Exception):
    def __init__(self, message: str, *, status: int = 0, codes: tuple[int, ...] = ()) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.codes = codes


def urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310 - fixed https API URL
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read() or b"{}")
        except ValueError:
            payload = {}
        return exc.code, payload
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CloudflareError(f"cannot reach the Cloudflare API: {exc}") from None


@dataclass(frozen=True)
class Zone:
    id: str
    name: str
    status: str
    plan: str


@dataclass(frozen=True)
class DnsRecord:
    id: str
    type: str
    name: str
    content: str
    proxied: bool
    comment: str


class Client:
    def __init__(self, token: str, *, transport: Transport = urllib_transport) -> None:
        if not token or any(c.isspace() for c in token):
            raise CloudflareError("empty or malformed API token")
        self._token = token
        self._transport = transport

    def __repr__(self) -> str:  # never leak the token through logs or tracebacks
        return "Client(token=***)"

    def _call(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = API + path + ("?" + urllib.parse.urlencode(query) if query else "")
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        status, payload = self._transport(method, url, headers, data)
        if not payload.get("success", False):
            errors = payload.get("errors") or []
            codes = tuple(int(e.get("code", 0)) for e in errors if isinstance(e, dict))
            text = "; ".join(str(e.get("message", e)) for e in errors if isinstance(e, dict))
            raise CloudflareError(
                text or f"Cloudflare API error (HTTP {status})", status=status, codes=codes
            )
        return payload

    def _pages(self, path: str, query: dict[str, str] | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for page in range(1, MAX_PAGES + 1):
            payload = self._call(
                "GET", path, query={**(query or {}), "page": str(page), "per_page": "50"}
            )
            result = payload.get("result") or []
            out.extend(result)
            info = payload.get("result_info") or {}
            if page >= int(info.get("total_pages", 1) or 1):
                break
        return out

    # --- token & zones ------------------------------------------------------------

    def verify(self) -> str:
        status: str = self._call("GET", "/user/tokens/verify")["result"]["status"]
        return status

    def zones(self) -> list[Zone]:
        return [
            Zone(z["id"], z["name"], z.get("status", ""), (z.get("plan") or {}).get("name", ""))
            for z in self._pages("/zones")
        ]

    def setting(self, zone_id: str, name: str) -> Any:
        return self._call("GET", f"/zones/{zone_id}/settings/{name}")["result"].get("value")

    # --- DNS -------------------------------------------------------------------------

    def records(self, zone_id: str, name: str | None = None) -> list[DnsRecord]:
        query = {"name": name} if name else None
        return [
            DnsRecord(
                r["id"],
                r["type"],
                r["name"],
                r["content"],
                bool(r.get("proxied")),
                r.get("comment") or "",
            )
            for r in self._pages(f"/zones/{zone_id}/dns_records", query)
        ]

    def create_record(
        self, zone_id: str, *, type: str, name: str, content: str, proxied: bool, comment: str
    ) -> DnsRecord:
        r = self._call(
            "POST",
            f"/zones/{zone_id}/dns_records",
            body={
                "type": type,
                "name": name,
                "content": content,
                "proxied": proxied,
                "ttl": 1,
                "comment": comment,
            },
        )["result"]
        return DnsRecord(
            r["id"],
            r["type"],
            r["name"],
            r["content"],
            bool(r.get("proxied")),
            r.get("comment") or "",
        )

    def delete_record(self, zone_id: str, record_id: str) -> None:
        self._call("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
