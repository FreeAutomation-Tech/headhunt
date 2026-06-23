from typing import List, Optional

import requests

HEADER_CHECKS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "severity": "HIGH",
        "description": "Enforces HTTPS connections to the server",
        "advice": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ),
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "severity": "HIGH",
        "description": "Controls resources the browser is allowed to load",
        "advice": (
            "Add: Content-Security-Policy: default-src 'self'"
        ),
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "MEDIUM",
        "description": "Prevents clickjacking by controlling framing",
        "advice": (
            "Add: X-Frame-Options: DENY or SAMEORIGIN"
        ),
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "description": "Prevents MIME type sniffing",
        "advice": (
            "Add: X-Content-Type-Options: nosniff"
        ),
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "LOW",
        "description": "Controls how much referrer info is sent",
        "advice": (
            "Add: Referrer-Policy: strict-origin-when-cross-origin"
        ),
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "LOW",
        "description": "Restricts browser API access",
        "advice": (
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
        ),
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "INFO",
        "description": "Deprecated — modern browsers ignore this header",
        "advice": (
            "Remove: X-XSS-Protection header (no longer needed)"
        ),
    },
    "cache-control": {
        "name": "Cache-Control",
        "severity": "MEDIUM",
        "description": "Controls caching behavior for sensitive content",
        "advice": (
            "Add: Cache-Control: no-cache, no-store, must-revalidate"
        ),
    },
    "pragma": {
        "name": "Pragma",
        "severity": "LOW",
        "description": "HTTP/1.0 cache control (legacy)",
        "advice": (
            "Add: Pragma: no-cache alongside Cache-Control"
        ),
    },
    "access-control-allow-origin": {
        "name": "Access-Control-Allow-Origin",
        "severity": "MEDIUM",
        "description": "Controls CORS policy",
        "advice": (
            "Restrict: Access-Control-Allow-Origin to specific origins, not '*'"
        ),
    },
}


HEADER_ORDER = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cache-control",
    "pragma",
    "access-control-allow-origin",
    "x-xss-protection",
]


class HeaderResult:
    def __init__(
        self,
        header_key: str,
        present: bool,
        value: Optional[str] = None,
        severity: str = "INFO",
        description: str = "",
        advice: str = "",
    ):
        self.header_key = header_key
        self.present = present
        self.value = value
        self.severity = severity
        self.description = description
        self.advice = advice

    def to_dict(self) -> dict:
        return {
            "header": HEADER_CHECKS.get(self.header_key, {}).get("name", self.header_key),
            "present": self.present,
            "value": self.value,
            "severity": self.severity,
            "description": self.description,
            "advice": self.advice,
        }


class ScanResult:
    def __init__(
        self,
        url: str,
        status_code: Optional[int] = None,
        headers: Optional[List[HeaderResult]] = None,
        error: Optional[str] = None,
        redirect_url: Optional[str] = None,
    ):
        self.url = url
        self.status_code = status_code
        self.headers = headers or []
        self.error = error
        self.redirect_url = redirect_url

    @property
    def score(self) -> int:
        total = len(self.headers)
        if total == 0:
            return 0
        passing = sum(1 for h in self.headers if h.present)
        return int((passing / total) * 100)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        elif s >= 75:
            return "B"
        elif s >= 55:
            return "C"
        elif s >= 35:
            return "D"
        else:
            return "F"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "grade": self.grade,
            "score": self.score,
            "headers": [h.to_dict() for h in self.headers],
            "error": self.error,
            "redirect_url": self.redirect_url,
        }


def scan_url(
    url: str, follow_redirects: bool = True, timeout: int = 15
) -> ScanResult:
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=follow_redirects,
            headers={"User-Agent": "HeadHunt/1.0 Security Scanner"},
        )
    except requests.RequestException as e:
        return ScanResult(url=url, error=str(e))

    results: List[HeaderResult] = []
    for key in HEADER_ORDER:
        check = HEADER_CHECKS.get(key, {})
        raw_value = resp.headers.get(key)
        present = raw_value is not None
        results.append(HeaderResult(
            header_key=key,
            present=present,
            value=raw_value,
            severity=check.get("severity", "INFO"),
            description=check.get("description", ""),
            advice=check.get("advice", ""),
        ))

    redirect_url = str(resp.url) if str(resp.url) != url else None

    return ScanResult(
        url=url,
        status_code=resp.status_code,
        headers=results,
        redirect_url=redirect_url,
    )
