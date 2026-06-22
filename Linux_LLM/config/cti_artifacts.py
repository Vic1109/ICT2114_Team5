import ipaddress
import re
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse


class CTIArtifactExtractor:
    """Extract common CTI artefacts from unstructured reports and alert context."""

    URL_RE = re.compile(r"\bhttps?://[^\s<>'\"`)\]]+", re.IGNORECASE)
    IPV4_CANDIDATE_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    DOMAIN_RE = re.compile(
        r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})(?![\w.-])"
    )
    EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
    HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
    CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
    ATTACK_GROUP_RE = re.compile(r"\b(?:APT\d{1,3}|G\d{4}|TA\d{4}|FIN\d{1,3})\b", re.IGNORECASE)

    COMMON_FALSE_DOMAIN_SUFFIXES = {
        ".exe", ".dll", ".sys", ".json", ".yaml", ".yml", ".conf", ".local",
        ".log", ".txt", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".md",
    }

    @classmethod
    def extract(cls, text: Any, max_items_per_type: int = 100) -> Dict[str, List[str]]:
        text = str(text or "")
        if not text.strip():
            return {}

        urls = cls._unique(cls._clean_url(match.group(0)) for match in cls.URL_RE.finditer(text))
        artefacts = {
            "ips": cls._extract_ips(text),
            "domains": cls._extract_domains(text, urls),
            "urls": urls,
            "emails": cls._unique(match.group(0).lower() for match in cls.EMAIL_RE.finditer(text)),
            "hashes": cls._unique(match.group(0).lower() for match in cls.HASH_RE.finditer(text)),
            "cves": cls._unique(match.group(0).upper() for match in cls.CVE_RE.finditer(text)),
            "mitre_techniques": cls._unique(match.group(0).upper() for match in cls.MITRE_TECHNIQUE_RE.finditer(text)),
            "threat_actors": cls._unique(match.group(0).upper() for match in cls.ATTACK_GROUP_RE.finditer(text)),
        }
        return {
            key: values[:max_items_per_type]
            for key, values in artefacts.items()
            if values
        }

    @classmethod
    def format_for_context(cls, artefacts: Dict[str, Iterable[Any]], max_items_per_type: int = 20) -> str:
        if not artefacts:
            return ""

        labels = {
            "ips": "IPs",
            "domains": "Domains",
            "urls": "URLs",
            "emails": "Emails",
            "hashes": "Hashes",
            "cves": "CVEs",
            "mitre_techniques": "MITRE Techniques",
            "threat_actors": "Threat Actors",
        }
        parts = []
        for key, label in labels.items():
            values = cls._unique(str(value) for value in artefacts.get(key, []) if value)
            if values:
                parts.append(f"{label}: {', '.join(values[:max_items_per_type])}")
        return "Extracted CTI Artefacts | " + " | ".join(parts) if parts else ""

    @staticmethod
    def count_by_type(artefacts: Dict[str, Iterable[Any]]) -> Dict[str, int]:
        return {
            key: len(list(values))
            for key, values in (artefacts or {}).items()
            if values
        }

    @classmethod
    def _extract_ips(cls, text: str) -> List[str]:
        ips = []
        for candidate in cls.IPV4_CANDIDATE_RE.findall(text):
            try:
                ips.append(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
        return cls._unique(ips)

    @classmethod
    def _extract_domains(cls, text: str, urls: List[str]) -> List[str]:
        domains = []
        email_domains = {
            email.split("@", 1)[1].lower()
            for email in cls.EMAIL_RE.findall(text)
            if "@" in email
        }

        for url in urls:
            hostname = urlparse(url).hostname
            if hostname:
                domains.append(hostname.lower())

        for match in cls.DOMAIN_RE.finditer(text):
            domain = match.group(0).lower().strip(".")
            if domain in email_domains:
                continue
            if any(domain.endswith(suffix) for suffix in cls.COMMON_FALSE_DOMAIN_SUFFIXES):
                continue
            try:
                ipaddress.ip_address(domain)
                continue
            except ValueError:
                pass
            domains.append(domain)

        return cls._unique(domains)

    @staticmethod
    def _clean_url(url: str) -> str:
        return url.rstrip(".,;:!?)\"]'}>").strip()

    @staticmethod
    def _unique(values: Iterable[Any]) -> List[str]:
        unique_values = []
        seen = set()
        for value in values:
            text = str(value or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            unique_values.append(text)
        return unique_values
