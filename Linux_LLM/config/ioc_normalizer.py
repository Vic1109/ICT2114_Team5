"""Generic IOC canonicalisation and boundary-aware matching.

This module must stay dataset-agnostic: it recognises syntactic indicator
classes, not named actors, malware families, vendors, or report titles.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable, List, Optional
from urllib.parse import urlparse, urlunparse


class IOCNormalizer:
    """Canonical comparison forms for machine-identifiable indicators."""

    HASH_LENGTH_TO_TYPE = {
        32: "md5",
        40: "sha1",
        64: "sha256",
        96: "sha384",
        128: "sha512",
    }
    BARE_HASH_RE = re.compile(
        r"\b(?:[A-Fa-f0-9]{128}|[A-Fa-f0-9]{96}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b"
    )
    COLON_FINGERPRINT_RE = re.compile(
        r"\b(?:[A-Fa-f0-9]{2}:){15,31}[A-Fa-f0-9]{2}\b"
    )
    CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    CWE_RE = re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE)
    EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
    DOMAIN_RE = re.compile(
        r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})(?=$|[^\w.-]|\.(?=\s|$))"
    )

    @classmethod
    def refang(cls, text: Any) -> str:
        normalized = str(text or "")
        if not normalized:
            return ""
        normalized = normalized.replace("\u200b", "").replace("\ufeff", "")
        normalized = re.sub(
            r"\s*(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s*",
            ".",
            normalized,
            flags=re.IGNORECASE,
        )
        normalized = re.sub(
            r"\s*(?:\[:\]|\[colon\]|\(colon\)|\{colon\})\s*",
            ":",
            normalized,
            flags=re.IGNORECASE,
        )
        normalized = re.sub(r"(?i)hxxps(?=://)", "https", normalized)
        normalized = re.sub(r"(?i)hxxp(?=://)", "http", normalized)
        return normalized.strip()

    @classmethod
    def canonical_ip(cls, value: Any) -> Optional[str]:
        text = cls.refang(value).strip().strip("[]")
        if not text:
            return None
        if text.endswith(".") and text.count(".") == 3:
            text = text[:-1]
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None

    @classmethod
    def canonical_domain(cls, value: Any) -> Optional[str]:
        text = cls.refang(value).strip().strip("[](){}<>\"'.,;:")
        if not text or "/" in text or "://" in text or "@" in text:
            return None
        text = text.lower().rstrip(".")
        if not text or "." not in text:
            return None
        if cls.canonical_ip(text):
            return None
        if not cls.DOMAIN_RE.fullmatch(text):
            return None
        return text

    @classmethod
    def canonical_url(cls, value: Any) -> Optional[str]:
        text = cls.refang(value).rstrip(".,;:!?)]}\"'")
        if not text:
            return None
        if "://" not in text:
            return None
        try:
            parsed = urlparse(text)
        except ValueError:
            return None
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            return None
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            return None
        try:
            hostname = str(ipaddress.ip_address(hostname))
        except ValueError:
            pass
        port = parsed.port
        netloc = hostname
        if port and not (
            (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        ):
            netloc = f"{hostname}:{port}"
        path = parsed.path or ""
        return urlunparse((scheme, netloc, path, "", parsed.query, ""))

    @classmethod
    def canonical_hash(cls, value: Any) -> Optional[str]:
        text = cls.refang(value).strip()
        if not text:
            return None
        compact = re.sub(r"[:\s]", "", text).lower()
        if len(compact) not in cls.HASH_LENGTH_TO_TYPE:
            return None
        if not re.fullmatch(r"[a-f0-9]+", compact):
            return None
        return compact

    @classmethod
    def hash_type(cls, value: Any) -> Optional[str]:
        canonical = cls.canonical_hash(value)
        if not canonical:
            return None
        return cls.HASH_LENGTH_TO_TYPE.get(len(canonical))

    @classmethod
    def canonical_cve(cls, value: Any) -> Optional[str]:
        text = str(value or "").strip()
        match = cls.CVE_RE.fullmatch(text) or cls.CVE_RE.search(text)
        if not match:
            return None
        year, number = match.group(0).upper().split("-")[1:]
        return f"CVE-{year}-{number}"

    @classmethod
    def canonical_cwe(cls, value: Any) -> Optional[str]:
        text = str(value or "").strip().upper()
        match = cls.CWE_RE.fullmatch(text) or cls.CWE_RE.search(text)
        if not match:
            return None
        return match.group(0).upper()

    @classmethod
    def canonical_email(cls, value: Any) -> Optional[str]:
        text = cls.refang(value).strip().strip("<>")
        match = cls.EMAIL_RE.fullmatch(text)
        if not match:
            return None
        return match.group(0).lower()

    @classmethod
    def classify(cls, value: Any) -> Optional[str]:
        text = str(value or "").strip()
        if not text:
            return None
        if cls.canonical_ip(text):
            return "ip"
        if cls.canonical_url(text) or "://" in text:
            if cls.canonical_url(text):
                return "url"
        if cls.canonical_email(text):
            return "email"
        if cls.canonical_cve(text):
            return "cve"
        if cls.canonical_hash(text):
            return "hash"
        if cls.canonical_domain(text):
            return "domain"
        return None

    @classmethod
    def canonical(cls, value: Any, ioc_type: Optional[str] = None) -> Optional[str]:
        kind = (ioc_type or cls.classify(value) or "").lower()
        if kind in {"ip", "ipv4", "ipv6"}:
            return cls.canonical_ip(value)
        if kind == "domain":
            return cls.canonical_domain(value)
        if kind == "url":
            return cls.canonical_url(value)
        if kind in {"hash", "md5", "sha1", "sha256", "sha384", "sha512", "fingerprint"}:
            return cls.canonical_hash(value)
        if kind == "cve":
            return cls.canonical_cve(value)
        if kind == "cwe":
            return cls.canonical_cwe(value)
        if kind == "email":
            return cls.canonical_email(value)
        if kind == "mitre_technique":
            text = str(value or "").strip().upper()
            return text if re.fullmatch(r"T\d{4}(?:\.\d{3})?", text) else None
        return None

    @classmethod
    def record(
        cls,
        original: Any,
        ioc_type: str,
        offset: int = -1,
        context: str = "",
        method: str = "deterministic",
    ) -> Optional[dict]:
        canonical = cls.canonical(original, ioc_type)
        if not canonical:
            return None
        return {
            "entity_type": ioc_type,
            "original_value": str(original),
            "canonical_value": canonical,
            "source_location": offset,
            "context": re.sub(r"\s+", " ", str(context or "")).strip()[:240],
            "extraction_method": method,
            "confidence": "high",
        }

    @classmethod
    def extract_ips(cls, text: str) -> List[str]:
        values = []
        haystack = cls.refang(text)
        for match in re.finditer(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)", haystack):
            canonical = cls.canonical_ip(match.group(0))
            if canonical:
                values.append(canonical)
        for match in re.finditer(r"(?<![\w.])([0-9A-Fa-f:]{2,79})(?![\w.])", haystack):
            candidate = match.group(1)
            if candidate.count(":") < 2:
                continue
            canonical = cls.canonical_ip(candidate)
            if canonical and ":" in canonical:
                values.append(canonical)
        return cls._unique(values)

    @classmethod
    def boundary_contains(cls, haystack: Any, needle: Any, ioc_type: Optional[str] = None) -> bool:
        text = str(haystack or "")
        term = cls.refang(needle)
        if not text or not term:
            return False
        kind = (ioc_type or cls.classify(term) or "").lower()
        search_texts = [text]
        refanged = cls.refang(text)
        if refanged != text:
            search_texts.append(refanged)

        if kind in {"ip", "ipv4", "ipv6"}:
            canonical = cls.canonical_ip(term)
            if not canonical:
                return False
            try:
                parsed = ipaddress.ip_address(canonical)
            except ValueError:
                return False
            if parsed.version == 4:
                pattern = re.compile(rf"(?<![\w.]){re.escape(canonical)}(?!\w|\.\d)")
                return any(pattern.search(candidate) for candidate in search_texts)
            forms = {parsed.compressed.lower(), parsed.exploded.lower(), canonical.lower()}
            for candidate in search_texts:
                lowered = candidate.lower()
                if any(form in lowered for form in forms) and canonical in cls.extract_ips(candidate):
                    return True
            return False

        if kind == "url":
            canonical = cls.canonical_url(term)
            if not canonical:
                return False
            for candidate in search_texts:
                for match in re.finditer(r"\b(?:https?|hxxps?)://[^\s<>'\"`)\]]+", candidate, flags=re.I):
                    if cls.canonical_url(match.group(0)) == canonical:
                        return True
            return False

        if kind == "domain":
            canonical = cls.canonical_domain(term)
            if not canonical:
                return False
            pattern = re.compile(
                rf"(?<![\w.-]){re.escape(canonical)}(?![\w.-])",
                re.IGNORECASE,
            )
            return any(pattern.search(candidate) for candidate in search_texts)

        if kind in {"hash", "md5", "sha1", "sha256", "sha384", "sha512", "fingerprint"}:
            canonical = cls.canonical_hash(term)
            if not canonical:
                return False
            compact_pattern = re.compile(rf"(?<![A-Fa-f0-9]){re.escape(canonical)}(?![A-Fa-f0-9])", re.I)
            colon_form = ":".join(canonical[index:index + 2] for index in range(0, len(canonical), 2))
            colon_pattern = re.compile(
                rf"(?<![A-Fa-f0-9:]){re.escape(colon_form)}(?![A-Fa-f0-9:])",
                re.I,
            )
            return any(
                compact_pattern.search(candidate) or colon_pattern.search(candidate)
                for candidate in search_texts
            )

        if kind == "cve":
            canonical = cls.canonical_cve(term)
            if not canonical:
                return False
            pattern = re.compile(rf"(?<![A-Za-z0-9-]){re.escape(canonical)}(?![A-Za-z0-9-])", re.I)
            return any(pattern.search(candidate) for candidate in search_texts)

        if kind == "email":
            canonical = cls.canonical_email(term)
            if not canonical:
                return False
            pattern = re.compile(rf"(?<![\w.-]){re.escape(canonical)}(?![\w.-])", re.I)
            return any(pattern.search(candidate) for candidate in search_texts)

        escaped = re.escape(term)
        if re.fullmatch(r"[A-Za-z0-9_.:/-]+", term):
            pattern = re.compile(rf"(?<![\w./:-]){escaped}(?![\w./:-])", re.IGNORECASE)
        else:
            pattern = re.compile(escaped, re.IGNORECASE)
        return any(pattern.search(candidate) for candidate in search_texts)

    @classmethod
    def lexical_contains(cls, haystack: Any, needle: Any, ioc_type: Optional[str] = None) -> bool:
        """Defanged/case/scheme-tolerant containment; stricter than substring, looser than exact URL equality."""
        if cls.boundary_contains(haystack, needle, ioc_type):
            return True
        kind = (ioc_type or cls.classify(needle) or "").lower()
        if kind != "url":
            return False
        canonical = cls.canonical_url(needle) or cls.canonical_url(cls.refang(needle))
        if not canonical:
            return False
        want = urlparse(canonical)
        want_host = (want.hostname or "").lower()
        want_path = want.path or ""
        if not want_host:
            return False
        search_texts = [str(haystack or ""), cls.refang(haystack)]
        for candidate in search_texts:
            for match in re.finditer(r"\b(?:https?|hxxps?)://[^\s<>'\"`)\]]+", candidate, flags=re.I):
                parsed_url = cls.canonical_url(match.group(0)) or cls.refang(match.group(0))
                parsed = urlparse(parsed_url)
                if (parsed.hostname or "").lower() == want_host and (parsed.path or "") == want_path:
                    return True
        return cls.boundary_contains(haystack, want_host, "domain")

    @staticmethod
    def _unique(values: Iterable[Any]) -> List[str]:
        unique: List[str] = []
        seen = set()
        for value in values:
            text = str(value or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(text)
        return unique
