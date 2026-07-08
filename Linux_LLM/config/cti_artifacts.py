import ipaddress
import re
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse


class CTIArtifactExtractor:
    """Extract common CTI artefacts from unstructured reports and alert context."""

    EXTRACTION_PIPELINE_VERSION = "2026-07-cti-rag-v4"

    URL_RE = re.compile(r"\bhttps?://[^\s<>'\"`)\]]+", re.IGNORECASE)
    IPV4_CANDIDATE_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    DOMAIN_RE = re.compile(
        r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})(?=$|[^\w.-]|\.(?=\s|$))"
    )
    EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
    HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
    CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
    ATTACK_GROUP_RE = re.compile(r"\b(?:APT\d{1,3}|G\d{4}|TA\d{4}|FIN\d{1,3})\b", re.IGNORECASE)
    ACTOR_CONTEXT_PATTERNS = [
        re.compile(
            r"\b(?:threat\s+actor|actor|intrusion\s+set|adversary|activity\s+group|cluster|group)\s*"
            r"(?:known\s+as|called|tracked\s+as|named|identified\s+as|:)\s*(?P<names>[^\r\n.;]{1,200})",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?P<names>[^\r\n.;]{1,160})\s+"
            r"(?:is|are|was|were)\s+(?:also\s+)?(?:a\s+|an\s+)?"
            r"(?:known\s+)?(?:threat\s+actor|actors|intrusion\s+set|adversary|activity\s+group|cluster|tracked\s+actors?)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?P<names>[^\r\n.;]{1,160})\s+"
            r"(?:is|are|was|were)\s+(?:associated|linked|attributed|connected)\s+(?:with|to)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:associated|linked|attributed|connected)\s+(?:with|to)\s+(?P<names>[^\r\n.;]{1,200})",
            re.IGNORECASE,
        ),
    ]
    ACTOR_ALIAS_CONTEXT_PATTERNS = [
        re.compile(
            r"\b(?:alias(?:es)?|aka|also\s+known\s+as|tracked\s+as|known\s+as)\s*"
            r"(?::|-|\s+)?\s*(?P<names>[^\r\n.;]{1,200})",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:threat\s+actor|actor|intrusion\s+set|adversary|activity\s+group|cluster|group)\s+"
            r"(?:alias(?:es)?|aka)\s*[:\-]?\s*(?P<names>[^\r\n.;]{1,200})",
            re.IGNORECASE,
        ),
    ]
    ACTOR_FALSE_POSITIVES = {
        "THE", "THIS", "THAT", "THESE", "THOSE", "AND", "OR", "A", "AN",
        "THREAT", "ACTOR", "ACTORS", "GROUP", "CLUSTER", "CAMPAIGN",
        "OPERATION",
        "MALWARE", "REPORT", "ANALYSIS", "INDICATORS", "IOC", "IOCS",
        "CVE", "MITRE", "ATTACK", "TECHNIQUE", "TACTIC", "PROCEDURE",
        "HTTP", "HTTPS", "DNS", "TLS", "TCP", "UDP", "IP", "URL",
        "WINDOWS", "LINUX", "MICROSOFT", "GOOGLE", "GITHUB",
        "KNOWN", "ALSO", "ASSOCIATED", "LINKED", "ATTRIBUTED", "CONNECTED",
        "USED", "USES", "USING", "MALICIOUS", "PAYLOAD", "FILE", "HOST",
        "INCIDENT", "ALERT", "EVENT", "SOURCE", "DESTINATION",
    }
    LINE_WRAPPED_INDICATOR_RE = re.compile(
        r"(?P<left>[A-Za-z0-9:/._~?#\[\]@!$&'()*+,;=%-]{3,})\s*[\r\n]+\s*"
        r"(?P<right>[A-Za-z0-9:/._~?#\[\]@!$&'()*+,;=%-]{3,})"
    )

    COMMON_FALSE_DOMAIN_SUFFIXES = {
        ".exe", ".dll", ".sys", ".json", ".yaml", ".yml", ".conf", ".local",
        ".log", ".txt", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".md",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".vbs",
        ".vbe", ".js", ".jse", ".ps1", ".bat", ".cmd", ".lnk", ".hta",
        ".scr", ".msi", ".cpl", ".cab", ".iso", ".zip", ".7z", ".rar",
        ".tmp", ".ini", ".cfg", ".dat", ".php", ".html", ".py",
    }
    COMMON_FALSE_DOMAIN_TLDS = {
        "a", "about", "across", "activity", "additionally", "against", "although",
        "actors", "and", "append", "argv", "attack", "based", "close",
        "commands", "connects", "creates", "credentials", "delete", "despite", "did",
        "direct", "download", "environment", "essential", "even", "evidence",
        "exit", "figure", "findall", "five", "from", "future", "group",
        "guidance", "here", "https", "immediately", "incident", "information",
        "intrusion", "lateral", "malicious", "minutes", "months", "multiple",
        "notably", "notes", "operations", "path", "percentage", "phishing",
        "please", "posted", "preliminary", "prior", "privileges", "read", "by",
        "register", "runs", "services", "successful", "target", "thanks",
        "the", "these", "this", "those", "ultimatelyencrypted", "upload",
        "validation", "values", "victimology", "ware", "web", "we", "when",
        "win", "with",
    }
    COMMON_FALSE_DOMAIN_PREFIXES = {
        "f", "re", "sys", "system", "net", "trojan", "ransomware",
        "malware", "script", "file", "item", "status", "records",
        "writers", "updater", "foxconn", "wscript", "zlib",
    }
    KNOWN_TLDS_FOR_GLUE_REPAIR = {
        "com", "net", "org", "top", "icu", "site", "cn", "th", "tm", "onion",
    }
    PROMOTABLE_CTI_TLDS = {
        "com", "net", "org", "edu", "gov", "mil", "int", "example", "test",
        "biz", "info", "name", "pro", "mobi", "asia", "cat", "jobs", "tel",
        "top", "icu", "site", "xyz", "live", "online", "shop", "club", "vip",
        "work", "click", "link", "space", "website", "pw", "cc", "ws", "tk",
        "ml", "ga", "cf", "gq", "su", "ru", "cn", "hk", "tw", "jp", "kr",
        "th", "tm", "vn", "id", "sg", "my", "ph", "in", "pk", "bd", "au",
        "nz", "us", "ca", "mx", "br", "ar", "co", "io", "me", "uk", "de",
        "fr", "nl", "be", "pl", "cz", "sk", "at", "ch", "se", "no", "fi",
        "dk", "es", "it", "pt", "gr", "ro", "bg", "hu", "ie", "eu", "tr",
        "ua", "by", "kz", "ir", "il", "za", "ng", "ke", "eg", "ma", "onion",
        "cfd", "cyou", "monster", "lol", "buzz", "fun", "one", "quest",
        "rest", "bond", "mom", "cam", "bar", "host", "cloud", "support",
        "center", "services", "email", "download", "stream", "review",
    }
    DOMAIN_GLUE_SUFFIX_RE = re.compile(
        r"^(?:(?:domains?|urls?)(?:h|https?)?|h|https?|returns?|both|can|the|this|until|now|conclusionthe)$",
        re.IGNORECASE,
    )
    LOW_SIGNAL_CTIDOMAINS = {
        "w3.org", "www.w3.org", "schema.org", "www.schema.org",
        "github.com", "www.github.com", "raw.githubusercontent.com",
        "community.riskiq.com", "riskiq.com", "www.riskiq.com",
        "gmail.com", "web.archive.org", "archive.org",
        "dhs.gov", "www.dhs.gov", "justice.gov", "www.justice.gov",
        "cloud.google.com", "console.cloud.google.com",
        "www.mandiant.com", "mandiant.com",
        "www.proofpoint.com", "proofpoint.com",
        "www.brighttalk.com", "brighttalk.com",
        "twitter.com", "www.twitter.com",
        "linkedin.com", "www.linkedin.com",
        "facebook.com", "www.facebook.com",
        "www.trustwave.com", "trustwave.com",
        "www.symantec.com", "symantec.com",
        "www.virustotal.com", "virustotal.com",
        "unit42.paloaltonetworks.com", "start.paloaltonetworks.com",
        "www.paloaltonetworks.com", "paloaltonetworks.com",
    }
    LOW_SIGNAL_CTI_IPS = {
        "1.0.0.1", "1.1.1.1", "8.8.4.4", "8.8.8.8", "9.9.9.9",
        "208.67.220.220", "208.67.222.222",
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
        text = cls._normalize_indicator_text(str(text or ""))
        if not text.strip():
            return {}

        urls = cls._extract_urls(text)
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
            "threat_actors": cls._extract_threat_actors(text, expand_related=False),
            "threat_actor_aliases": cls._extract_declared_threat_actor_aliases(text),
        }
        return {
            key: values[:max_items_per_type]
            for key, values in artefacts.items()
            if values
        }

    @classmethod
    def extract_structured(
        cls,
        data: Any,
        max_items_per_type: int = 100,
    ) -> Dict[str, List[str]]:
        """Extract CTI artifacts from structured JSON/STIX semantics.

        This intentionally complements regex extraction. Structured fields can
        identify actor/malware/campaign names that are impossible to infer
        safely from arbitrary prose alone.
        """
        artefacts: Dict[str, List[str]] = {}

        def add(key: str, value: Any):
            if value in (None, "", [], {}):
                return
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    add(key, item)
                return
            if isinstance(value, dict):
                for item in value.values():
                    add(key, item)
                return
            text = str(value).strip()
            if not text:
                return
            artefacts.setdefault(key, [])
            artefacts[key].append(text)

        def add_named(key: str, value: Any):
            if value in (None, "", [], {}):
                return
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    add_named(key, item)
                return
            if isinstance(value, dict):
                for name_key in ("name", "aliases", "value"):
                    if value.get(name_key) not in (None, "", [], {}):
                        add_named(key, value.get(name_key))
                return
            add(key, value)

        def merge_extracted(value: Any):
            extracted = cls.extract(value)
            for key, values in extracted.items():
                add(key, values)

        def add_external_references(refs: Any):
            if not isinstance(refs, list):
                return
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                external_id = ref.get("external_id")
                source_name = str(ref.get("source_name") or "").lower()
                if external_id:
                    if cls.MITRE_TECHNIQUE_RE.fullmatch(str(external_id)):
                        add("mitre_techniques", str(external_id).upper())
                    elif cls.CVE_RE.fullmatch(str(external_id)):
                        add("cves", str(external_id).upper())
                    elif source_name in {"mitre-attack", "capec", "cve"}:
                        add("external_ids", external_id)
                add("urls", ref.get("url"))

        def visit(value: Any, parent_type: str = ""):
            if isinstance(value, list):
                for item in value:
                    visit(item, parent_type=parent_type)
                return
            if not isinstance(value, dict):
                merge_extracted(value)
                return

            object_type = str(value.get("type") or parent_type or "").strip().lower()
            if object_type == "bundle":
                visit(value.get("objects") or [], parent_type="")
                return

            if object_type in {"threat-actor", "intrusion-set"}:
                add_named("threat_actors", value.get("name"))
                add_named("threat_actor_aliases", value.get("aliases"))
            elif object_type == "malware":
                add_named("malware_families", value.get("name"))
                add_named("malware_families", value.get("aliases"))
            elif object_type == "tool":
                add_named("tools", value.get("name"))
                add_named("tools", value.get("aliases"))
            elif object_type == "campaign":
                add_named("campaigns", value.get("name"))
                add_named("campaigns", value.get("aliases"))
            elif object_type == "course-of-action":
                add_named("courses_of_action", value.get("name"))
                add_named("courses_of_action", value.get("aliases"))
            elif object_type in {"attack-pattern", "vulnerability"}:
                if object_type == "vulnerability":
                    add("cves", value.get("name"))

            for key, child in value.items():
                key_norm = str(key or "").strip().lower().replace("-", "_")
                if key_norm in {
                    "type", "id", "created", "modified", "revoked",
                    "report_id", "title", "severity", "description",
                }:
                    continue
                if key_norm == "external_references":
                    add_external_references(child)
                    continue
                if key_norm == "pattern":
                    merge_extracted(child)
                    continue
                if key_norm in {"threat_actor", "threat_actors", "actor", "actors", "intrusion_set", "intrusion_sets", "apt_group"}:
                    add_named("threat_actors", child)
                elif key_norm in {"threat_actor_alias", "threat_actor_aliases", "actor_alias", "actor_aliases", "aliases"}:
                    add_named("threat_actor_aliases", child)
                elif key_norm in {"malware", "malwares", "malware_family", "malware_families"}:
                    add_named("malware_families", child)
                elif key_norm in {"campaign", "campaigns"}:
                    add_named("campaigns", child)
                elif key_norm in {"tool", "tools"}:
                    add_named("tools", child)
                elif key_norm in {"course_of_action", "courses_of_action", "mitigation", "mitigations"}:
                    add_named("courses_of_action", child)
                elif key_norm in {"mitre", "mitre_attack", "attack_pattern", "attack_patterns", "technique", "techniques"}:
                    merge_extracted(child)
                elif key_norm in {"observable", "observables", "indicator", "indicators", "pattern", "value", "url", "domain", "ip", "hash"}:
                    merge_extracted(child)
                else:
                    visit(child, parent_type=object_type)

        visit(data)
        normalized = {
            key: cls._unique(values)[:max_items_per_type]
            for key, values in artefacts.items()
            if values
        }
        if "cves" in normalized:
            normalized["cves"] = cls._unique(value.upper() for value in normalized["cves"])[:max_items_per_type]
        if "mitre_techniques" in normalized:
            normalized["mitre_techniques"] = cls._unique(value.upper() for value in normalized["mitre_techniques"])[:max_items_per_type]
        return normalized

    @classmethod
    def merge_artifacts(cls, *artifact_sets: Dict[str, Iterable[Any]], max_items_per_type: int = 100) -> Dict[str, List[str]]:
        merged: Dict[str, List[Any]] = {}
        for artifacts in artifact_sets:
            for key, values in (artifacts or {}).items():
                if values in (None, "", [], {}):
                    continue
                merged.setdefault(key, [])
                if isinstance(values, (list, tuple, set)):
                    merged[key].extend(values)
                else:
                    merged[key].append(values)
        return {
            key: cls._unique(values)[:max_items_per_type]
            for key, values in merged.items()
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
                    and str(value).strip() not in cls.LOW_SIGNAL_CTI_IPS
                ]
                if public_ips:
                    filtered[key] = cls._unique(public_ips)
                continue
            if key == "domains":
                cleaned = cls._unique(
                    str(value).strip().lower()
                    for value in values or []
                    if value and cls._is_promotable_cti_domain(str(value).strip().lower())
                )
                if cleaned:
                    filtered[key] = cleaned
                continue
            if key == "urls":
                cleaned_urls = []
                for value in values or []:
                    url = str(value or "").strip()
                    if not url:
                        continue
                    try:
                        hostname = (urlparse(url).hostname or "").lower()
                    except ValueError:
                        hostname = ""
                    if hostname and cls._is_low_signal_domain(hostname):
                        continue
                    if hostname and not cls._is_promotable_cti_domain(hostname):
                        continue
                    cleaned_urls.append(url)
                cleaned = cls._unique(cleaned_urls)
                if cleaned:
                    filtered[key] = cleaned
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
            "threat_actor_aliases": "Related Actor Aliases",
            "malware_families": "Malware Families",
            "campaigns": "Campaigns",
            "tools": "Tools",
            "courses_of_action": "Courses of Action",
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
    def _extract_urls(cls, text: str) -> List[str]:
        urls = []
        for match in cls.URL_RE.finditer(text or ""):
            raw = match.group(0)
            starts = [m.start() for m in re.finditer(r"(?i)https?://", raw)]
            if not starts:
                continue
            starts.append(len(raw))
            for index in range(len(starts) - 1):
                segment = raw[starts[index]:starts[index + 1]]
                segment = re.split(
                    r"(?i)(?:mailto:|---|\[SECONDARY|\|Pagina|\[|\]|\{|\})",
                    segment,
                    maxsplit=1,
                )[0]
                cleaned = cls._clean_url(segment)
                if not cleaned:
                    continue
                try:
                    parsed = urlparse(cleaned)
                except ValueError:
                    continue
                if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                    continue
                urls.append(cleaned)
        return cls._unique(urls)

    @classmethod
    def _extract_threat_actors(cls, text: str, expand_related: bool = False) -> List[str]:
        del expand_related  # Kept for backward-compatible callers; actor expansion is evidence-based only.
        text = text or ""
        actors = [
            match.group(0).upper()
            for match in cls.ATTACK_GROUP_RE.finditer(text)
            if not cls._match_is_in_actor_alias_context(text, match.start())
            and not cls._match_is_in_low_confidence_metadata_context(text, match.start())
        ]
        for pattern in cls.ACTOR_CONTEXT_PATTERNS:
            for match in pattern.finditer(text):
                actors.extend(cls._split_actor_candidates(match.group("names")))
        return cls._unique(cls._normalize_actor_name(actor) for actor in actors if cls._is_plausible_actor_name(actor))

    @classmethod
    def _extract_declared_threat_actor_aliases(cls, text: str) -> List[str]:
        text = text or ""
        aliases: List[str] = []
        for pattern in cls.ACTOR_ALIAS_CONTEXT_PATTERNS:
            for match in pattern.finditer(text):
                aliases.extend(cls._split_actor_candidates(match.group("names")))
        aliases.extend(cls._extract_actor_alias_section_candidates(text))
        observed = {str(actor).upper() for actor in cls._extract_threat_actors(text, expand_related=False)}
        return cls._unique(
            cls._normalize_actor_name(alias)
            for alias in aliases
            if cls._is_plausible_actor_name(alias)
            and cls._normalize_actor_name(alias).upper() not in observed
        )

    @staticmethod
    def _match_is_in_actor_alias_context(text: str, start: int) -> bool:
        line_start = max(text.rfind("\n", 0, start), text.rfind("\r", 0, start)) + 1
        prefix = text[line_start:start][-160:]
        if re.search(
            r"\b(?:alias(?:es)?|aka|also\s+known\s+as|known\s+as|tracked\s+as)\b[^\r\n.;]{0,120}$",
            prefix,
            flags=re.IGNORECASE,
        ):
            return True
        lookback = text[max(0, line_start - 240):line_start]
        return bool(
            re.search(
                r"(?im)(?:^|\n)\s*(?:#{1,6}\s*)?(?:threat\s+actor\s+|actor\s+)?aliases\s*:?\s*$",
                lookback,
            )
            or re.search(r"(?is)[\"']aliases[\"']\s*:\s*\[[^\]]{0,500}$", lookback)
        )

    @staticmethod
    def _match_is_in_low_confidence_metadata_context(text: str, start: int) -> bool:
        line_start = max(text.rfind("\n", 0, start), text.rfind("\r", 0, start)) + 1
        prefix = text[line_start:start][-120:]
        if re.search(
            r"(?:^|\b|[\"'])(?:report[_\s-]*id|source[_\s-]*file|file(?:name)?|title|severity)[\"']?\s*:?\s*[\"']?$",
            prefix,
            flags=re.IGNORECASE,
        ):
            return True
        lookback = text[max(0, line_start - 160):line_start]
        return bool(
            re.search(
                r"(?im)(?:^|\n)\s*#{1,6}\s*(?:report\s*id|source\s*file|file(?:name)?|title|severity)\s*$",
                lookback,
            )
        )

    @classmethod
    def _extract_actor_alias_section_candidates(cls, text: str) -> List[str]:
        aliases: List[str] = []
        section_pattern = re.compile(
            r"(?ims)^\s*#{1,6}\s*(?:threat\s+actor\s+|actor\s+)?aliases\s*:?\s*$"
            r"(?P<body>.*?)(?=^\s*#{1,6}\s+\S|\Z)"
        )
        for match in section_pattern.finditer(text or ""):
            for line in match.group("body").splitlines():
                candidate = re.sub(r"^\s*(?:[-*+]|\d+[.)])\s*", "", line).strip()
                candidate = candidate.strip(" \t\r\n'\"`,[]")
                if candidate:
                    aliases.append(candidate)
        return aliases

    @classmethod
    def _split_actor_candidates(cls, raw: str) -> List[str]:
        normalized = re.sub(r"\s+(?:and|or)\s+", ", ", str(raw or ""), flags=re.IGNORECASE)
        return [
            candidate
            for candidate in (cls._normalize_actor_name(part) for part in normalized.split(","))
            if candidate
        ]

    @classmethod
    def _normalize_actor_name(cls, value: str) -> str:
        value = re.sub(r"\s+", " ", str(value or "").strip(" \t\r\n'\"`.,;:()[]{}<>"))
        value = re.sub(
            r"^(?:the\s+)?(?:threat\s+actor|actor|intrusion\s+set|adversary|activity\s+group|cluster|group)\s+",
            "",
            value,
            flags=re.IGNORECASE,
        ).strip()
        value = re.sub(
            r"\s+(?:activity|incident|alert|event|campaign|operation|report|analysis)$",
            "",
            value,
            flags=re.IGNORECASE,
        ).strip()
        if cls.ATTACK_GROUP_RE.fullmatch(value):
            return value.upper()
        return value.upper()

    @classmethod
    def _is_plausible_actor_name(cls, candidate: str) -> bool:
        candidate = str(candidate or "").strip(" \t\r\n'\"`.,;:()[]{}<>")
        if not candidate:
            return False
        normalized = cls._normalize_actor_name(candidate)
        upper = normalized.upper()
        if cls.ATTACK_GROUP_RE.fullmatch(normalized):
            return True
        if upper in cls.ACTOR_FALSE_POSITIVES:
            return False
        if any(part in cls.ACTOR_FALSE_POSITIVES for part in upper.split()) and len(upper.split()) == 1:
            return False
        if cls.CVE_RE.fullmatch(normalized) or cls.MITRE_TECHNIQUE_RE.fullmatch(normalized):
            return False
        if any(char in normalized for char in ("/", "\\", "@")):
            return False
        if cls.HASH_RE.fullmatch(normalized):
            return False
        if cls.DOMAIN_RE.fullmatch(normalized) or normalized.lower().endswith(tuple(cls.COMMON_FALSE_DOMAIN_SUFFIXES)):
            return False
        words = normalized.split()
        if len(words) > 4:
            return False
        if words and all(word in cls.ACTOR_FALSE_POSITIVES for word in words):
            return False
        if words and words[0] in {"OPERATION", "CAMPAIGN", "REPORT", "ANALYSIS"}:
            return False
        has_actor_signal = (
            bool(re.search(r"\b(?:APT|FIN|TA|G)\d+\b", normalized, re.IGNORECASE))
            or any(re.search(r"[A-Z][a-z]+[A-Z][A-Za-z0-9]*", word) for word in words)
            or any(word[:1].isupper() and word[1:].islower() for word in words)
            or any(word.isupper() and len(word) >= 4 for word in words)
        )
        return bool(has_actor_signal)

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
            try:
                hostname = urlparse(url).hostname
            except ValueError:
                continue
            if hostname:
                hostname = hostname.lower()
                try:
                    ipaddress.ip_address(hostname)
                    continue
                except ValueError:
                    pass
                for candidate in cls._domain_candidate_variants(hostname):
                    if candidate and not cls._is_false_domain(candidate):
                        domains.append(candidate)

        for match in cls.DOMAIN_RE.finditer(text):
            for domain in cls._domain_candidate_variants(match.group(0)):
                if not domain:
                    continue
                if domain in email_domains:
                    continue
                if cls._is_false_domain(domain):
                    continue
                try:
                    ipaddress.ip_address(domain)
                    continue
                except ValueError:
                    pass
                domains.append(domain)

        return cls._unique(domains)

    @classmethod
    def _domain_candidate_variants(cls, domain: str) -> List[str]:
        domain = str(domain or "").lower().strip(".")
        if not domain or "." not in domain:
            return []

        variants = []

        def add(candidate: str):
            cleaned = cls._clean_domain_candidate(candidate)
            if cleaned and cleaned not in variants:
                variants.append(cleaned)

        onion_pattern = re.compile(r"([a-z2-7]{16}|[a-z2-7]{56})\.onion", re.IGNORECASE)
        for match in onion_pattern.finditer(domain):
            add(match.group(0))
            suffix = domain[match.end():].lstrip(".-_/")
            if suffix and "." in suffix:
                add(suffix)

        labels = domain.split(".")
        if labels[-1] == "onion" and len(labels) >= 2:
            tail_match = re.search(r"([a-z2-7]{16}|[a-z2-7]{56})$", labels[-2], re.IGNORECASE)
            if tail_match:
                add(tail_match.group(1) + ".onion")

        if not variants:
            add(domain)
        return variants

    @classmethod
    def _clean_domain_candidate(cls, domain: str) -> str:
        domain = str(domain or "").lower().strip(".")
        if "." not in domain:
            return ""
        labels = domain.split(".")
        if any(not label for label in labels):
            return ""

        tld = labels[-1]
        for known_tld in sorted(cls.KNOWN_TLDS_FOR_GLUE_REPAIR, key=len, reverse=True):
            if tld == known_tld:
                return domain
            if tld.startswith(known_tld):
                suffix = tld[len(known_tld):]
                if suffix and cls.DOMAIN_GLUE_SUFFIX_RE.fullmatch(suffix):
                    labels[-1] = known_tld
                    return ".".join(labels)
        return domain

    @classmethod
    def _is_false_domain(cls, domain: str) -> bool:
        domain = str(domain or "").lower().strip(".")
        if not domain or "." not in domain:
            return True
        labels = domain.split(".")
        if any(not label for label in labels):
            return True
        if any(domain.endswith(suffix) for suffix in cls.COMMON_FALSE_DOMAIN_SUFFIXES):
            return True
        if labels[-1].startswith(("pdf", "html", "php", "py", "lnk", "exe", "dll", "bat", "cmd", "ps1", "txt")):
            return True
        if re.search(
            r"\.(?:exe|dll|lnk|bat|cmd|ps1|vbs|pdf|py|php|html|txt|dat|tmp|ini|cfg)https?$",
            domain,
        ):
            return True
        tld = labels[-1]
        if tld in cls.COMMON_FALSE_DOMAIN_TLDS:
            return True
        if labels[0] in cls.COMMON_FALSE_DOMAIN_PREFIXES and tld in cls.COMMON_FALSE_DOMAIN_TLDS | {
            "path", "name", "fullname", "decompress", "run", "echo",
        }:
            return True
        if len(domain) > 120:
            return True
        return False

    @classmethod
    def _is_low_signal_domain(cls, domain: str) -> bool:
        domain = str(domain or "").lower().strip(".")
        if not domain:
            return False
        return any(
            domain == low_signal or domain.endswith("." + low_signal)
            for low_signal in cls.LOW_SIGNAL_CTIDOMAINS
        )

    @classmethod
    def _is_promotable_cti_domain(cls, domain: str) -> bool:
        domain = cls._clean_domain_candidate(domain)
        if not domain:
            return False
        if cls._is_false_domain(domain) or cls._is_low_signal_domain(domain):
            return False
        tld = domain.rsplit(".", 1)[-1]
        return tld in cls.PROMOTABLE_CTI_TLDS or tld.startswith("xn--")

    @classmethod
    def _normalize_indicator_text(cls, text: str) -> str:
        """Normalize common PDF/CTI IoC formatting before regex extraction."""
        if not text:
            return ""

        normalized = (
            text.replace("\ufeff", "")
            .replace("\u200b", "")
            .replace("\u200c", "")
            .replace("\u200d", "")
            .replace("\xad", "")
        )

        def join_wrapped(match):
            left = match.group("left")
            right = match.group("right")
            combined = left + right
            left_numeric_dots = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){1,3}", left))
            right_numeric_dots = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){1,3}", right))
            if left_numeric_dots or right_numeric_dots:
                try:
                    ipaddress.ip_address(combined)
                    return combined
                except ValueError:
                    pass
                return f"{left} {right}"
            if left.lower().endswith(tuple(cls.COMMON_FALSE_DOMAIN_SUFFIXES)):
                return match.group(0)
            colon_indicates_wrapped_url = (
                left.rstrip(":").lower() in {"http", "https", "hxxp", "hxxps"}
                or right.startswith("//")
            )
            indicatorish = (
                "." in left or "." in right
                or "/" in left or "/" in right
                or "[" in left or "]" in right
                or ((":" in left or ":" in right) and colon_indicates_wrapped_url)
                or (len(combined) in {32, 40, 64} and re.fullmatch(r"[A-Fa-f0-9]+", combined))
            )
            return combined if indicatorish else match.group(0)

        for _ in range(3):
            next_value = cls.LINE_WRAPPED_INDICATOR_RE.sub(join_wrapped, normalized)
            if next_value == normalized:
                break
            normalized = next_value

        replacements = (
            (r"(?i)\bhxxps\b", "https"),
            (r"(?i)\bhxxp\b", "http"),
            (r"(?i)\[\s*:\s*\]|\(\s*:\s*\)", ":"),
            (r"(?i)\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}", "."),
            (r"(?i)\s+\[\s*dot\s*\]\s+|\s+\(\s*dot\s*\)\s+", "."),
            (r"(?i)\s+dot\s+", "."),
        )
        for pattern, replacement in replacements:
            normalized = re.sub(pattern, replacement, normalized)

        normalized = re.sub(r"(?i)\bhttps?\s*:\s*/\s*/", lambda m: m.group(0).replace(" ", ""), normalized)
        return normalized

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
