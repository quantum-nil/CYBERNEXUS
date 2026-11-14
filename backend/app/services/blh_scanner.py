"""Broken-link and dangling-host (BLH) analysis for website scans.

This module is deliberately evidence-only: it never executes JavaScript, claims a
domain, or treats an unavailable provider as a clean result. All network access
uses the existing SSRF-safe HTTP fetcher and redirects are validated per hop.
"""
from __future__ import annotations

import ipaddress
import socket
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from backend.app.core.config import settings
from backend.app.engines.safe_http import UnsafeDestination, fetch as safe_fetch

try:  # dnspython is a declared backend dependency, but keep the module optional.
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None

MAX_EXTERNAL_LINKS = 50
MAX_REDIRECTS = 5
_ASSET_TAGS = {"a": "href", "script": "src", "link": "href", "iframe": "src", "img": "src"}
_FINGERPRINTS = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "s3.amazonaws.com": "Amazon S3",
    "storage.googleapis.com": "Google Cloud Storage",
    "azurewebsites.net": "Azure App Service",
    "vercel.app": "Vercel",
    "netlify.app": "Netlify",
}


class _ExternalLinkParser(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.links: set[str] = set()

    def handle_starttag(self, tag, attrs):
        attribute = _ASSET_TAGS.get(tag.lower())
        if not attribute:
            return
        value = dict(attrs).get(attribute)
        if not value or value.startswith(("#", "mailto:", "javascript:", "data:")):
            return
        candidate = urljoin(self.page_url, value.strip())
        parsed = urlsplit(candidate)
        base = urlsplit(self.page_url)
        if parsed.scheme in {"http", "https"} and parsed.hostname and parsed.hostname.lower().rstrip(".") != (base.hostname or "").lower().rstrip("."):
            self.links.add(candidate)


def _fingerprint(hostname: str, headers: dict, body: bytes) -> str | None:
    host = hostname.lower().rstrip(".")
    for suffix, provider in _FINGERPRINTS.items():
        if host == suffix or host.endswith("." + suffix):
            return provider
    text = body[:20000].decode("utf-8", "ignore").lower()
    server = str(headers.get("server", "")).lower()
    for needle, provider in (("no such app", "Heroku"), ("there isn't a github pages site here", "GitHub Pages"), ("site not found", "Netlify/Vercel")):
        if needle in text or needle in server:
            return provider
    return None


def _dns_evidence(hostname: str) -> dict:
    result = {"status": "available", "addresses": [], "cname": None, "nxdomain": False, "dangling": False, "evidence": []}
    try:
        result["addresses"] = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        result.update(status="nxdomain", nxdomain=True, evidence=[type(exc).__name__])
    if dns is not None:
        try:
            answers = dns.resolver.resolve(hostname, "CNAME", lifetime=settings.dns_timeout_seconds)
            result["cname"] = str(answers[0].target).rstrip(".")
        except dns.resolver.NXDOMAIN:
            result["nxdomain"] = True
            result["status"] = "nxdomain"
        except (dns.exception.DNSException, OSError):
            pass
    if result.get("cname") and not result.get("addresses"):
        result["dangling"] = True
        result["evidence"].append("CNAME has no address record")
    return result


def _risk_level(score: int) -> str:
    return "CRITICAL" if score >= 80 else "HIGH" if score >= 55 else "MEDIUM" if score >= 25 else "LOW"


def _fetch_with_redirects(url: str, max_bytes: int | None = None):
    """Fetch one resource while validating every redirect destination."""
    current = url
    seen = {current}
    redirects = 0
    while True:
        response = safe_fetch(current, timeout=5.0, max_bytes=max_bytes or settings.max_page_size_bytes)
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response, current, redirects
        location = response.headers.get("location")
        if not location or redirects >= MAX_REDIRECTS:
            return response, current, redirects
        destination = urljoin(current, location)
        parsed = urlsplit(destination)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or destination in seen:
            raise UnsafeDestination("invalid or looping redirect destination")
        # safe_fetch performs fresh DNS validation for the next hop.
        current = destination
        seen.add(current)
        redirects += 1


def check_link(url: str) -> dict:
    """Compatibility helper returning the basic HTTP link check requested by BLH."""
    try:
        response, final_url, redirects = _fetch_with_redirects(url, max_bytes=min(settings.max_page_size_bytes, 128 * 1024))
        return {"url": url, "status": response.status_code, "final_url": final_url, "redirects": redirects, "broken": response.status_code in {404, 410}}
    except Exception as exc:
        return {"url": url, "status": None, "error": str(exc), "broken": False}


def extract_external_links(url: str) -> list[str]:
    """Extract external HTTP(S) asset links without fetching or executing them."""
    response, final_url, _ = _fetch_with_redirects(url)
    parser = _ExternalLinkParser(final_url)
    parser.feed(response.body.decode("utf-8", "ignore"))
    return sorted(parser.links)[:MAX_EXTERNAL_LINKS]


def analyze_external_links(raw_url: str, authorization_guard=None) -> dict:
    """Analyze external resources for broken links and takeover indicators."""
    result = {"status": "COMPLETED", "target_url": raw_url, "external_links": [], "findings": [], "summary": {"total": 0, "broken": 0, "nxdomain": 0, "dangling": 0, "potential_takeover": 0, "risk_score": 0, "risk_level": "LOW"}, "limits": {"max_links": MAX_EXTERNAL_LINKS, "max_redirects": MAX_REDIRECTS, "javascript_executed": False}}
    try:
        root, root_url, _ = _fetch_with_redirects(raw_url)
        parser = _ExternalLinkParser(root_url)
        content_type = str(root.headers.get("content-type", "")).lower()
        if not content_type or "html" in content_type or "xhtml" in content_type:
            parser.feed(root.body.decode("utf-8", "ignore"))
        links = sorted(parser.links)[:MAX_EXTERNAL_LINKS]
    except (UnsafeDestination, ValueError, OSError, socket.timeout) as exc:
        result["status"] = "BLOCKED" if isinstance(exc, UnsafeDestination) else "UNAVAILABLE"
        result["error"] = str(exc)
        return result

    score = 0
    for link in links:
        if authorization_guard:
            authorization_guard()
        parsed = urlsplit(link)
        item = {"url": link, "status": None, "final_url": link, "broken": False, "dns": {}, "fingerprint": None, "claimability": {"status": "NOT_EVALUATED", "evidence": []}}
        try:
            response, final_url, redirects = _fetch_with_redirects(link, max_bytes=min(settings.max_page_size_bytes, 128 * 1024))
            item["status"] = response.status_code
            item["final_url"] = final_url
            item["redirects"] = redirects
            item["broken"] = response.status_code in {404, 410}
            item["fingerprint"] = _fingerprint(parsed.hostname or "", response.headers, response.body)
            if item["broken"]:
                score += 10
                result["findings"].append({"type": "BROKEN_EXTERNAL_RESOURCE", "url": link, "severity": "MEDIUM", "evidence": f"HTTP {response.status_code}"})
        except (UnsafeDestination, ValueError, OSError, socket.timeout) as exc:
            item["error"] = type(exc).__name__
            item["broken"] = False
        item["dns"] = _dns_evidence(parsed.hostname or "")
        dns_result = item["dns"]
        if dns_result.get("nxdomain") or dns_result.get("dangling"):
            result["summary"]["nxdomain"] += 1
            score += 25
            result["findings"].append({"type": "DANGLING_DNS", "url": link, "severity": "HIGH", "evidence": "NXDOMAIN" if dns_result.get("nxdomain") else "CNAME has no address record"})
        provider = item.get("fingerprint")
        if provider and (item.get("broken") or dns_result.get("nxdomain") or dns_result.get("dangling")):
            item["claimability"] = {"status": "POTENTIAL", "evidence": [provider, "provider response or DNS failure"], "note": "Evidence only; no domain registration or claim was attempted."}
            result["summary"]["potential_takeover"] += 1
            score += 35
            result["findings"].append({"type": "POTENTIAL_SUBDOMAIN_TAKEOVER", "url": link, "severity": "HIGH", "provider": provider})
        result["external_links"].append(item)

    result["summary"].update(total=len(links), broken=sum(1 for item in result["external_links"] if item["broken"]), dangling=sum(1 for item in result["external_links"] if item["dns"].get("nxdomain")), risk_score=min(100, score))
    result["summary"]["risk_level"] = _risk_level(result["summary"]["risk_score"])
    return result
