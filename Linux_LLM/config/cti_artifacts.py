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
    CTI_SECTION_PATTERNS = {
        "ioc_listing": re.compile(
            r"\b(?:ioc|indicator|indicators|hashes?|sha256|sha1|md5|c2 server|"
            r"command and control|malicious ip|malicious domain|callback domain)\b",
            re.IGNORECASE,
        ),
        "ttp_behavior": re.compile(
            r"\b(?:tactic|technique|procedure|ttp|mitre|attack|lateral movement|"
            r"persistence|privilege escalation|credential access|defense evasion|"
            r"execution|exfiltration|discovery|command[- ]and[- ]control)\b",
            re.IGNORECASE,
        ),
        "attribution": re.compile(
            r"\b(?:attributed to|associated with|threat actor|apt\d{1,3}|fin\d{1,3}|"
            r"ta\d{4}|g\d{4}|campaign|cluster|malware family|operator|nation[- ]state)\b",
            re.IGNORECASE,
        ),
        "remediation": re.compile(
            r"\b(?:mitigation|remediation|recommendation|block|isolate|patch|"
            r"disable|harden|detect|monitor|hunt|contain|eradicate|recover)\b",
            re.IGNORECASE,
        ),
        "victim_infrastructure": re.compile(
            r"\b(?:victim|target(?:ed)?|compromised host|internal network|enterprise|"
            r"organization|customer|affected system|infected machine)\b",
            re.IGNORECASE,
        ),
        "analysis_environment": re.compile(
            r"\b(?:sandbox|lab|test environment|analysis machine|virtual machine|"
            r"localhost|loopback|sample execution|detonation|pcap|researcher)\b",
            re.IGNORECASE,
        ),
        "vulnerability": re.compile(
            r"\b(?:cve-\d{4}-\d{4,7}|vulnerab|exploit|rce|remote code execution|"
            r"sql injection|xss|buffer overflow|zero[- ]day)\b",
            re.IGNORECASE,
        ),
    }
    ARTIFACT_DISPOSITION_PATTERNS = {
        "benign": re.compile(
            r"\b(?:benign|legitimate|clean|allowlist|allowlisted|known good|"
            r"false positive|not malicious|not associated with|not related to|"
            r"unrelated|security vendor|sinkhole|sinkholed|researcher domain|"
            r"trusted|normal traffic|expected traffic)\b",
            re.IGNORECASE,
        ),
        "malicious": re.compile(
            r"\b(?:malicious|ioc|indicator|c2|command and control|callback|beacon|"
            r"exfiltrat|payload|dropper|phishing|ransomware|trojan|backdoor|botnet|"
            r"attacker|adversary|threat actor|used by|associated with)\b",
            re.IGNORECASE,
        ),
        "victim": re.compile(
            r"\b(?:victim|target(?:ed)?|compromised host|affected system|infected machine|"
            r"internal host|internal network|enterprise|organization|customer)\b",
            re.IGNORECASE,
        ),
        "analysis_environment": re.compile(
            r"\b(?:sandbox|lab|test environment|analysis machine|virtual machine|detonation|"
            r"pcap|researcher|localhost|loopback|example)\b",
            re.IGNORECASE,
        ),
        "remediation_reference": re.compile(
            r"\b(?:block|allowlist|denylist|firewall|sinkhole|monitor for|hunt for|detect|"
            r"mitigation|remediation|recommendation)\b",
            re.IGNORECASE,
        ),
    }
    BEHAVIOR_PATTERNS = {
        "reconnaissance_or_scanning": re.compile(
            r"\b(?:scan|scanning|reconnaissance|recon|probe|enumerat|sweep|nmap|"
            r"masscan|port scan|discovery)\b",
            re.IGNORECASE,
        ),
        "credential_attack": re.compile(
            r"\b(?:credential|password|brute force|spray|phish|login attempt|"
            r"valid account|dump(?:ed|ing)? credentials?|lsass|mimikatz)\b",
            re.IGNORECASE,
        ),
        "phishing_or_email_delivery": re.compile(
            r"\b(?:phish|spearphish|spear[- ]phishing|email|smtp|attachment|"
            r"malspam|macro document|weaponized document|document review)\b",
            re.IGNORECASE,
        ),
        "possible_c2": re.compile(
            r"\b(?:c2|c&c|command and control|callback|beacon|implant|backdoor|"
            r"rat\b|remote access trojan|check[- ]in)\b",
            re.IGNORECASE,
        ),
        "possible_exfiltration": re.compile(
            r"\b(?:exfiltrat|data theft|stolen data|upload(?:ed|ing)?|"
            r"archive(?:d|s)? and upload|ftp|cloud storage|dropbox|mega)\b",
            re.IGNORECASE,
        ),
        "malware_or_destructive_activity": re.compile(
            r"\b(?:malware|ransomware|wiper|destructive|encrypt(?:ed|ion)?|"
            r"payload|dropper|trojan|worm|file write|delete shadow copies)\b",
            re.IGNORECASE,
        ),
        "lateral_movement_candidate": re.compile(
            r"\b(?:lateral movement|remote services?|smb|windows admin shares?|"
            r"psexec|wmic|rdp|ssh|winrm|admin share|network share)\b",
            re.IGNORECASE,
        ),
        "web_or_exploit_attempt": re.compile(
            r"\b(?:exploit|rce|remote code execution|web shell|sql injection|xss|"
            r"deserialization|path traversal|cve-\d{4}-\d{4,7})\b",
            re.IGNORECASE,
        ),
        "malware_execution_candidate": re.compile(
            r"\b(?:powershell|cmd\.exe|wscript|cscript|rundll32|regsvr32|"
            r"mshta|scheduled task|process injection|execute|execution)\b",
            re.IGNORECASE,
        ),
        "domain_or_tls_indicator": re.compile(
            r"\b(?:domain|dns|tls|ssl|certificate|sni|http host|hostname|url)\b",
            re.IGNORECASE,
        ),
    }

    @classmethod
    def extract(
        cls,
        text: Any,
        max_items_per_type: int = 100,
        include_non_public_ips: bool = True,
    ) -> Dict[str, List[str]]:
        text = str(text or "")
        if not text.strip():
            return {}

        urls = cls._unique(cls._clean_url(match.group(0)) for match in cls.URL_RE.finditer(text))
        ips = cls._extract_ips(text)
        public_ips = [ip for ip in ips if cls.is_public_ip(ip)]
        non_public_ips = [ip for ip in ips if not cls.is_public_ip(ip)]
        artefacts = {
            "ips": ips if include_non_public_ips else public_ips,
            "public_ips": public_ips,
            "non_public_ips": non_public_ips,
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
    def for_cti_context(cls, artefacts: Dict[str, Iterable[Any]]) -> Dict[str, List[str]]:
        """Return artifact values suitable for CTI retrieval context.

        Private, loopback, link-local, multicast, and other non-public IPs are
        retained in metadata as non_public_ips by extract(), but they should not
        be promoted as document-level CTI IoCs for matching uploaded reports.
        """
        if not artefacts:
            return {}

        filtered: Dict[str, List[str]] = {}
        for key, values in artefacts.items():
            if key in {"non_public_ips", "public_ips"}:
                continue
            if key == "ips":
                public_ips = [
                    str(value).strip()
                    for value in values or []
                    if value and cls.is_public_ip(str(value).strip())
                ]
                if public_ips:
                    filtered[key] = cls._unique(public_ips)
                continue
            cleaned = cls._unique(str(value) for value in values or [] if value)
            if cleaned:
                filtered[key] = cleaned
        return filtered

    @classmethod
    def classify_context(cls, text: Any, max_labels: int = 4) -> List[str]:
        """Classify a CTI passage by its likely analytical role."""
        text = str(text or "")
        if not text.strip():
            return []

        scores = []
        for label, pattern in cls.CTI_SECTION_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                scores.append((len(matches), label))

        labels = [
            label for _score, label in sorted(scores, key=lambda item: (-item[0], item[1]))
        ]
        return labels[:max_labels]

    @classmethod
    def format_context_labels(cls, labels: Iterable[Any]) -> str:
        values = cls._unique(str(label) for label in labels or [] if label)
        return "CTI Context Labels | " + ", ".join(values) if values else ""

    @classmethod
    def infer_behavior_tags(cls, text: Any, max_tags: int = 6) -> List[str]:
        """Infer coarse attack-behavior tags from CTI text for retrieval alignment."""
        text = str(text or "")
        if not text.strip():
            return []

        scores = []
        for label, pattern in cls.BEHAVIOR_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                scores.append((len(matches), label))

        return [
            label for _score, label in sorted(scores, key=lambda item: (-item[0], item[1]))
        ][:max_tags]

    @classmethod
    def format_behavior_tags(cls, labels: Iterable[Any]) -> str:
        values = cls._unique(str(label) for label in labels or [] if label)
        return "CTI Behavior Tags | " + ", ".join(values) if values else ""

    @classmethod
    def classify_artifact_dispositions(
        cls,
        text: Any,
        artefacts: Dict[str, Iterable[Any]] = None,
        context_window: int = 90,
        max_items_per_type: int = 30,
    ) -> Dict[str, Dict[str, str]]:
        """Classify extracted artefacts by likely role in the CTI passage."""
        text = str(text or "")
        artefacts = artefacts or cls.extract(text)
        dispositions: Dict[str, Dict[str, str]] = {}

        for artifact_type, term_type in (
            ("ips", "ip"),
            ("domains", "domain"),
            ("urls", "url"),
            ("hashes", None),
        ):
            values = cls._unique(str(value) for value in artefacts.get(artifact_type, []) if value)
            typed_dispositions = {}
            for value in values[:max_items_per_type]:
                typed_dispositions[value] = cls._classify_single_artifact_disposition(
                    text,
                    value,
                    term_type=term_type,
                    context_window=context_window,
                )
            if typed_dispositions:
                dispositions[artifact_type] = typed_dispositions

        return dispositions

    @classmethod
    def _classify_single_artifact_disposition(
        cls,
        text: str,
        value: str,
        term_type: str = None,
        context_window: int = 90,
    ) -> str:
        contexts = cls._artifact_contexts(
            text,
            value,
            term_type=term_type,
            radius=context_window,
            sentence_local=True,
        )
        if not contexts:
            contexts = cls._artifact_contexts(
                text,
                value,
                term_type=term_type,
                radius=context_window,
                sentence_local=False,
            )
        if not contexts:
            return "unknown"

        joined_context = " ".join(contexts)
        scores = {
            label: len(pattern.findall(joined_context))
            for label, pattern in cls.ARTIFACT_DISPOSITION_PATTERNS.items()
        }

        priority = ("benign", "malicious", "victim", "analysis_environment", "remediation_reference")
        best_label = max(priority, key=lambda label: (scores.get(label, 0), -priority.index(label)))
        if scores.get(best_label, 0) <= 0:
            return "unknown"
        return best_label

    @classmethod
    def _artifact_contexts(
        cls,
        text: str,
        value: str,
        term_type: str = None,
        radius: int = 90,
        sentence_local: bool = True,
    ) -> List[str]:
        if not text or not value:
            return []
        pattern = cls._artifact_pattern(value, term_type=term_type)
        contexts = []
        for match in pattern.finditer(text):
            if sentence_local:
                sentence_start = max(
                    text.rfind(".", 0, match.start()),
                    text.rfind("\n", 0, match.start()),
                    text.rfind(";", 0, match.start()),
                )
                sentence_end_candidates = [
                    index for index in (
                        text.find(".", match.end()),
                        text.find("\n", match.end()),
                        text.find(";", match.end()),
                    )
                    if index != -1
                ]
                start = sentence_start + 1 if sentence_start != -1 else max(0, match.start() - radius)
                end = min(sentence_end_candidates) if sentence_end_candidates else min(len(text), match.end() + radius)
            else:
                start = max(0, match.start() - radius)
                end = min(len(text), match.end() + radius)
            contexts.append(text[start:end])
        return contexts

    @classmethod
    def _artifact_pattern(cls, value: str, term_type: str = None):
        escaped = re.escape(str(value).strip())
        if term_type == "ip":
            return re.compile(rf"(?<![\w.]){escaped}(?![\w.])", re.IGNORECASE)
        if term_type in {"domain", "url"}:
            return re.compile(rf"(?<![\w.-]){escaped}(?![\w.-])", re.IGNORECASE)
        return re.compile(escaped, re.IGNORECASE)

    @classmethod
    def summarize_dispositions(
        cls,
        dispositions: Dict[str, Dict[str, str]],
        max_items: int = 8,
    ) -> str:
        if not dispositions:
            return ""

        grouped: Dict[str, List[str]] = {}
        for artifact_type, values in dispositions.items():
            for value, disposition in values.items():
                grouped.setdefault(disposition, []).append(f"{artifact_type}:{value}")

        parts = []
        for disposition in ("malicious", "benign", "victim", "analysis_environment", "remediation_reference", "unknown"):
            values = grouped.get(disposition) or []
            if values:
                parts.append(f"{disposition}: {', '.join(values[:max_items])}")
        return "CTI Artifact Disposition | " + " | ".join(parts) if parts else ""

    @classmethod
    def apply_section_context_to_dispositions(
        cls,
        dispositions: Dict[str, Dict[str, str]],
        section_labels: Iterable[Any],
    ) -> Dict[str, Dict[str, str]]:
        """Use CTI section context to classify artifacts that had no local role signal."""
        if not dispositions:
            return {}

        labels = {str(label).lower() for label in section_labels or [] if label}
        section_default = None
        if "analysis_environment" in labels:
            section_default = "analysis_environment"
        elif "victim_infrastructure" in labels:
            section_default = "victim"
        elif "remediation" in labels:
            section_default = "remediation_reference"
        elif "ioc_listing" in labels:
            section_default = "malicious"

        if not section_default:
            return dispositions

        adjusted: Dict[str, Dict[str, str]] = {}
        for artifact_type, values in dispositions.items():
            adjusted[artifact_type] = {}
            for value, disposition in values.items():
                adjusted[artifact_type][value] = (
                    section_default
                    if str(disposition or "").lower() == "unknown"
                    else disposition
                )
        return adjusted

    @classmethod
    def assess_extraction_quality(
        cls,
        text: Any,
        pages: int = 0,
        artefacts: Dict[str, Iterable[Any]] = None,
    ) -> Dict[str, Any]:
        """Assess whether extracted CTI text is likely complete enough for RAG."""
        text = str(text or "")
        artefacts = artefacts or cls.extract(text)
        page_count = max(0, int(pages or 0))
        character_count = len(text)
        words = re.findall(r"\b[A-Za-z0-9_.:/-]{2,}\b", text)
        word_count = len(words)
        image_marker_count = len(re.findall(r"\[IMAGES DETECTED:", text, flags=re.IGNORECASE))
        table_marker_count = len(re.findall(r"\[TABLES DETECTED\]", text, flags=re.IGNORECASE))
        chars_per_page = int(character_count / page_count) if page_count else character_count
        artifact_total = sum(len(list(values)) for values in (artefacts or {}).values() if values)

        warnings = []
        if page_count and chars_per_page < 250:
            warnings.append("low_text_density")
        if page_count and image_marker_count >= max(1, page_count // 2):
            warnings.append("image_heavy_pdf_no_ocr")
        if page_count and word_count < max(80, page_count * 35):
            warnings.append("few_extracted_words")
        if page_count >= 3 and artifact_total == 0:
            warnings.append("no_cti_artifacts_extracted")

        if not text.strip():
            quality = "empty"
        elif len(warnings) >= 2:
            quality = "low"
        elif warnings:
            quality = "medium"
        else:
            quality = "high"

        return {
            "quality": quality,
            "warnings": warnings,
            "pages": page_count,
            "characters": character_count,
            "words": word_count,
            "chars_per_page": chars_per_page,
            "image_marker_count": image_marker_count,
            "table_marker_count": table_marker_count,
            "artifact_total": artifact_total,
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

    @staticmethod
    def is_public_ip(value: str) -> bool:
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return False
        return bool(ip.is_global)

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
