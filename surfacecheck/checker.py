"""One verified connection and one HEAD request per explicitly supplied URL."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import math
import re
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit, urlunsplit


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    path: str


def parse_target(value: str) -> Target:
    """Reject credentials, queries, ambiguous hosts and control characters."""
    if not value or len(value) > 4096:
        raise ValueError("URL must contain 1 to 4096 characters")
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("URL cannot contain whitespace, control characters or backslashes")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Use a complete http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in URLs are not supported")
    if "?" in value or "#" in value:
        raise ValueError("Query strings and fragments are not supported; provide a path only")
    host = parsed.hostname
    if "%" in host:
        raise ValueError("Encoded hosts and IPv6 zone identifiers are not supported")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = host.encode("idna").decode("ascii").lower()
        if len(host) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.rstrip(".").split(".")
        ):
            raise ValueError("Invalid hostname") from None
        # Avoid legacy numeric IPv4 formats interpreted differently by resolvers.
        if all(re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", x) for x in host.split(".")):
            raise ValueError("Use a canonical dotted IPv4 address") from None
    port = parsed.port
    if parsed.netloc.endswith(":") or (port is not None and not 1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535")
    port = port or (443 if parsed.scheme == "https" else 80)
    authority = f"[{host}]" if ":" in host else host
    authority += f":{port}"
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    return Target(urlunsplit((parsed.scheme, authority, path, "", "")), parsed.scheme, host, port, path)


def finding(code: str, severity: str, message: str, remedy: str) -> dict:
    return {"code": code, "severity": severity, "message": message, "remedy": remedy}


def analyze_headers(headers: list[tuple[str, str]], scheme: str) -> list[dict]:
    """Conservative response-header checks; these are observations, not exploits."""
    values: dict[str, list[str]] = {}
    for name, value in headers:
        values.setdefault(name.lower(), []).append(value.strip())
    results = []
    if scheme == "https":
        hsts = values.get("strict-transport-security", [])
        if not hsts:
            results.append(finding("HSTS_MISSING", "low", "HSTS header absent on this response.", "Consider HSTS after verifying HTTPS works for the intended host scope."))
        else:
            ages = re.findall(r"(?:^|;)\s*max-age\s*=\s*\"?([0-9]+)\"?\s*(?=;|$)", hsts[0], re.I)
            if len(ages) != 1 or int(ages[0]) == 0:
                results.append(finding("HSTS_INACTIVE", "low", "HSTS max-age is missing, malformed or zero.", "Set a valid positive max-age if HSTS is appropriate."))
    content_type = values.get("content-type", [""])[0].lower()
    is_html = "text/html" in content_type or "application/xhtml+xml" in content_type
    if is_html and not values.get("content-security-policy"):
        results.append(finding("CSP_MISSING", "low", "No enforced CSP on this HTML response.", "Develop and test a content-specific Content-Security-Policy."))
    if is_html and values.get("x-content-type-options", [""])[0].lower() != "nosniff":
        results.append(finding("NOSNIFF_MISSING", "low", "HTML response does not declare nosniff.", "Set X-Content-Type-Options: nosniff."))
    # Count affected cookies without retaining cookie names or values.
    counts = {"secure": 0, "httponly": 0, "samesite": 0, "none_insecure": 0}
    for cookie in values.get("set-cookie", []):
        parts = cookie.split(";")
        if "=" not in parts[0]:
            continue
        attrs = {}
        for part in parts[1:]:
            key, _, val = part.strip().partition("=")
            attrs[key.lower()] = val.strip().lower()
        counts["secure"] += "secure" not in attrs
        counts["httponly"] += "httponly" not in attrs
        counts["samesite"] += attrs.get("samesite") not in ("lax", "strict", "none")
        counts["none_insecure"] += attrs.get("samesite") == "none" and "secure" not in attrs
    for attr, count in counts.items():
        if count:
            results.append(finding(
                f"COOKIE_{attr.upper()}", "low",
                f"{count} Set-Cookie header(s) need review for {attr}.",
                "Review cookie purpose; use Secure, HttpOnly and an appropriate SameSite policy. SameSite=None requires Secure.",
            ))
    return results


def inspect(target: Target, *, timeout: float = 5.0, ca_file: str | None = None) -> dict:
    """Inspect without redirects, retries, response bodies, proxies or stored auth."""
    if not math.isfinite(timeout) or not 0.1 <= timeout <= 30:
        raise ValueError("Timeout must be a finite value from 0.1 to 30 seconds")
    started = time.monotonic()
    result = {"target": target.url, "status": "ok", "http_status": None, "tls": None, "findings": []}
    conn = None
    try:
        if target.scheme == "https":
            context = ssl.create_default_context(cafile=ca_file)
            context.set_alpn_protocols(["http/1.1"])
            conn = http.client.HTTPSConnection(target.host, target.port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(target.host, target.port, timeout=timeout)
            result["findings"].append(finding("HTTP_PLAINTEXT", "medium", "This URL uses unencrypted HTTP.", "Use HTTPS; this observation does not establish whether HTTPS is available."))
        conn.connect()
        if target.scheme == "https":
            cert = conn.sock.getpeercert()
            expires = ssl.cert_time_to_seconds(cert["notAfter"])
            days = math.floor((expires - time.time()) / 86400)
            result["tls"] = {
                "verified": True,
                "version": conn.sock.version(),
                "cipher": conn.sock.cipher()[0],
                "certificate_sha256": hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest(),
                "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat(),
                "days_remaining": days,
            }
            if days <= 30:
                result["findings"].append(finding("CERT_EXPIRING", "medium", f"Certificate expires in {days} day(s).", "Renew the certificate before expiration."))
        conn.request("HEAD", target.path, headers={"User-Agent": "SurfaceCheck/0.1", "Connection": "close"})
        response = conn.getresponse()
        result["http_status"] = response.status
        if response.status in (405, 501):
            result["status"] = "partial"
            result["findings"].append(finding("HEAD_UNSUPPORTED", "info", "Server does not support HEAD; header checks skipped.", "Review the endpoint manually; no GET fallback was sent."))
        else:
            result["findings"].extend(analyze_headers(response.getheaders(), target.scheme))
            if 300 <= response.status < 400:
                result["findings"].append(finding("REDIRECT_NOT_FOLLOWED", "info", "Redirect response observed; destination was not requested or stored.", "Supply the destination separately if it is within your authorized scope."))
        response.close()
    except ssl.SSLCertVerificationError:
        result["status"] = "error"
        result["findings"].append(finding("TLS_VERIFY_FAILED", "high", "Certificate chain or hostname verification failed.", "Check hostname, certificate validity, chain and trust store; use --ca-file for a private CA."))
    except (OSError, http.client.HTTPException, ValueError) as exc:
        result["status"] = "error"
        # Exception messages and raw headers may contain sensitive server content.
        result["findings"].append(finding("CONNECTION_FAILED", "info", f"Check could not complete ({type(exc).__name__}).", "Check reachability, protocol, timeout and CA configuration."))
    finally:
        if conn is not None:
            conn.close()
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result
