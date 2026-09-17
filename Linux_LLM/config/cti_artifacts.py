import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from ioc_normalizer import IOCNormalizer


class CTIArtifactExtractor:
    """Extract common CTI artefacts from unstructured reports and alert context."""

    EXTRACTION_PIPELINE_VERSION = "2026-09-cti-rag-v9"

    URL_RE = re.compile(r"\bhttps?://[^\s<>'\"`)\]]+", re.IGNORECASE)
    # Permit normal sentence punctuation after an address while still refusing
    # partial matches inside dotted identifiers such as ``1.2.3.4.5``.
    IPV4_CANDIDATE_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
    # Conservative IPv6 candidates; every match is validated with ipaddress.
    IPV6_TOKEN_RE = re.compile(r"(?<![\w.])([0-9A-Fa-f:]{2,79})(?![\w.])")
    FILENAME_RE = re.compile(
        r"(?<![\w./-])(?P<name>[A-Za-z0-9][\w.-]{0,80}\.(?:exe|dll|sys|ps1|vbs|js|jse|vbe|"
        r"hta|bat|cmd|scr|lnk|docm|xlsm|pptm|rtf|msi|zip|rar|7z|iso))(?![\w.-])",
        re.IGNORECASE,
    )
    FILE_PATH_RE = re.compile(
        r"(?<![\w])(?P<path>(?:[A-Za-z]:\\|\\\\|/(?:etc|var|tmp|opt|usr|home|root)/)"
        r"[^\s,;\"'<>]{3,220})",
    )
    REGISTRY_RE = re.compile(
        r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
        r"HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\s,;\"'<>]{3,220}",
        re.IGNORECASE,
    )
    MUTEX_RE = re.compile(
        r"\b(?:(?:named\s+)?mutex(?:es)?|mutex\s+name)\s*[:\-]\s*"
        r"(?P<name>[A-Za-z0-9_\\.-]{3,80})"
        r"|\b(?P<global>Global\\[A-Za-z0-9_.-]{3,80})",
        re.IGNORECASE,
    )
    USER_AGENT_RE = re.compile(
        r"\buser[- ]agent\s*[:\-]\s*(?P<ua>[^\r\n]{8,240})",
        re.IGNORECASE,
    )
    CRYPTO_ADDRESS_RE = re.compile(
        r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62}|0x[a-fA-F0-9]{40})\b"
    )
    DOMAIN_RE = re.compile(
        r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})(?=$|[^\w.-]|\.(?=\s|$))"
    )
    EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
    HASH_RE = IOCNormalizer.BARE_HASH_RE
    CERT_FINGERPRINT_RE = IOCNormalizer.COLON_FINGERPRINT_RE
    CVE_RE = IOCNormalizer.CVE_RE
    CWE_RE = IOCNormalizer.CWE_RE
    MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
    MITRE_TACTIC_RE = re.compile(r"\bTA\d{4}\b", re.IGNORECASE)
    ATTACK_GROUP_RE = re.compile(r"\b(?:APT\d{1,3}|G\d{4}|FIN\d{1,3})\b", re.IGNORECASE)
    ACTOR_CONTEXT_PATTERNS = [
        re.compile(
            r"\b(?:threat\s+actor|actor|intrusion\s+set|adversary|activity\s+group|cluster|group)\s*"
            r"(?:known\s+as|called|tracked\s+as|named|identified\s+as|:)\s*(?P<names>[^\r\n.;]{1,200})",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:threat\s+actor|intrusion\s+set|activity\s+group)\s+"
            r"(?P<names>[A-Z][A-Za-z0-9._-]{2,40}(?:\s+[A-Z][A-Za-z0-9._-]{1,40}){0,2})\b",
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
        "WHICH", "ONE", "OF", "COMMAND", "SECURITY", "INTERNET",
        "JSCRIPT", "EXECUTING", "NEXT", "GEN", "IOT", "OFFICE", "MONKEYS",
        "RELATED", "ARTICLE", "ARTICLES", "BLOG", "WHITEPAPER",
        "TEAM", "SYSTEM", "SERVICES", "SERVERS", "SAMPLES", "CONTROL",
        "NEWS", "RANSOMWARE", "GRID", "ELECTRIC",
    }
    MALWARE_FALSE_POSITIVES = ACTOR_FALSE_POSITIVES | {
        "POWER", "SHELL", "POWERSHELL", "OFFICE", "WORD", "EXCEL", "ADOBE",
        "PYTHON", "JAVASCRIPT", "INTERNET", "EXPLORER", "CHROME", "FIREFOX",
        "WINDOWS", "LINUX", "MICROSOFT", "GOOGLE", "GITHUB", "MANDIANT",
        "FIREEYE", "CROWDSTRIKE", "KASPERSKY", "SYMANTEC", "PROOFPOINT",
        "PALO", "ALTO", "SENTINEL", "DEFENDER", "ANTIVIRUS", "PAYLOAD",
        "SAMPLE", "BINARY", "DOCUMENT", "MACRO", "SCRIPT", "LOADER",
        "BACKDOOR", "RANSOMWARE", "TROJAN", "STEALER", "WIPER", "DROPPER",
        "FAMILY", "VARIANT", "VERSION", "MODULE", "COMPONENT",
        "CHAIN", "INSIGHT", "DEEP", "CLICKING", "PERSONAL", "COMMUNICATION",
        "STORED", "PERFORMED", "TARGETING", "CREDENTIALS", "LIGHTWEIGHT",
        "SENTINELABS", "SENTINELONE", "SECURELIST", "THREATPOST", "CYWARE",
    }
    TOOL_FALSE_POSITIVES = MALWARE_FALSE_POSITIVES | {
        "COMMAND", "LINE", "UTILITY", "FRAMEWORK", "PLATFORM", "SERVICE",
        "SAAS",
    }
    LOW_SIGNAL_FILENAMES = {
        "jquery.js", "bootstrap.js", "index.js", "app.js", "main.js",
        "script.js", "style.css", "readme.md", "license.txt",
    }
    MALWARE_CONTEXT_PATTERNS = [
        re.compile(
            r"\b(?:malware(?:\s+family)?|backdoor|trojan|ransomware|wiper|stealer|"
            r"loader|dropper|rat|implant|botnet|rootkit)\s+"
            r"(?:family\s+)?"
            r"(?:called|named|known as|tracked as|labelled|labeled)\s*"
            r"[:\-]?\s*(?P<names>[A-Za-z][A-Za-z0-9._-]{1,60}(?:\s+[A-Za-z][A-Za-z0-9._-]{1,40}){0,2})",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:malware(?:\s+family)?)\s+(?P<names>[A-Z][A-Za-z0-9._-]{2,40})\b",
        ),
        re.compile(
            r"\b(?P<names>[A-Z][A-Za-z0-9._-]{2,40}(?:\s+[A-Z][A-Za-z0-9._-]{2,40}){0,2})\s+"
            r"(?:malware(?:\s+family)?|backdoor|trojan|ransomware|wiper|stealer|"
            r"loader|dropper|rat|implant|botnet|rootkit)\b",
        ),
        re.compile(
            r"(?i)\b(?:used|uses|using|deployed|dropped|delivered|installed|launched|"
            r"employ(?:ed|s|ing)?)\s+(?:the\s+)?"
            r"(?-i:(?P<names>[A-Z]{3,}[A-Za-z0-9._-]{0,40}|[A-Z][a-z]+[A-Z][A-Za-z0-9._-]{1,40}))"
            r"(?=\s|$|[.,;:]|\s+(?:backdoor|trojan|ransomware|wiper|stealer|loader|"
            r"dropper|rat|implant|malware|against|to|for|in|on|with|after))"
        ),
    ]
    CAMPAIGN_CONTEXT_PATTERNS = [
        re.compile(
            r"(?i)\b(?:operation|campaign)\s+(?:called|named|known as|tracked as)\s*"
            r"[:\-]?\s*(?-i:(?P<names>[A-Z][A-Za-z0-9._-]{2,40}(?:\s+[A-Z][A-Za-z0-9._-]{2,40}){0,3}))"
        ),
        re.compile(
            r"\b(?P<names>Operation\s+[A-Z][A-Za-z0-9._-]{2,40}(?:\s+[A-Z][A-Za-z0-9._-]{2,40}){0,2})\b",
        ),
    ]
    TOOL_CONTEXT_PATTERNS = [
        re.compile(
            r"\b(?:tool(?:s)?|utility|utilities|framework)\s+"
            r"(?:called|named|known as|such as)\s*[:\-]?\s*"
            r"(?P<names>[A-Za-z][A-Za-z0-9._-]{2,40}(?:\s+[A-Za-z][A-Za-z0-9._-]{1,40}){0,2})",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?P<names>[A-Z][A-Za-z0-9._-]{2,40})\s+(?:tool|utility|framework)\b",
        ),
        re.compile(
            r"(?i)\b(?:the\s+)?(?:tool|utility|framework)\s+"
            r"(?-i:(?P<names>[A-Z][A-Za-z0-9._-]{2,40}))\b",
        ),
    ]
    RELATIONSHIP_VERB_MAP = (
        ("uses", re.compile(r"\b(?:used|uses|using|deployed|deploying|launched|delivered|employ(?:ed|s|ing)?)\b", re.IGNORECASE)),
        ("aliases", re.compile(r"\b(?:also known as|aka|alias(?:es)?|tracked as|attributed as)\b", re.IGNORECASE)),
        ("attributed_to", re.compile(r"\b(?:attributed to|attribution to|linked to|associated with)\b", re.IGNORECASE)),
        ("exploits", re.compile(r"\b(?:exploit(?:s|ed|ing)?|leveraged|took advantage of)\b", re.IGNORECASE)),
        ("targets", re.compile(r"\b(?:target(?:s|ed|ing)?|against|victim(?:s)?)\b", re.IGNORECASE)),
        ("communicates_with", re.compile(r"\b(?:c2|c&c|command and control|callback|beacon(?:s|ing)?|connect(?:s|ed|ing)? to)\b", re.IGNORECASE)),
        ("delivers", re.compile(r"\b(?:deliver(?:s|ed|ing)?|drops|dropped|dropping|install(?:s|ed|ing)?)\b", re.IGNORECASE)),
    )
    RELATIONSHIP_POLARITY_PATTERNS = (
        ("denied", re.compile(
            r"\b(?:not (?:been )?(?:attributed|linked|associated|confirmed)|"
            r"incorrectly attributed|no (?:confident )?(?:attribution|evidence)|"
            r"denied|does not use|did not use|unrelated to|is not attributed)\b",
            re.IGNORECASE,
        )),
        ("unconfirmed", re.compile(
            r"\b(?:unconfirmed|not confidently|remains (?:unconfirmed|unknown|unclear|unattributed)|"
            r"relationship between.{0,80}unconfirmed)\b",
            re.IGNORECASE,
        )),
        ("suspected", re.compile(r"\b(?:suspect(?:ed|s)?|possibly|may (?:have|be)|might)\b", re.IGNORECASE)),
        ("assessed", re.compile(r"\b(?:assess(?:es|ed|ment)? that|researchers assess|likely|probably)\b", re.IGNORECASE)),
        ("reported", re.compile(r"\b(?:report(?:s|ed)? that|according to|claimed)\b", re.IGNORECASE)),
        ("explicit", re.compile(r"\b(?:used|uses|using|deployed|delivered|confirmed)\b", re.IGNORECASE)),
    )
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
        "the", "these", "this", "those", "upload",
        "validation", "values", "victimology", "ware", "web", "we", "when",
        "win", "with",
        "application", "vbscript", "powershell", "persistence",
        "great", "recent", "following", "each", "xml", "png", "jpg", "jpeg",
        "gif", "css", "once", "shapes",
    }
    COMMON_FALSE_DOMAIN_PREFIXES = {
        "f", "re", "sys", "system", "net", "trojan", "ransomware",
        "malware", "script", "file", "item", "status", "records",
        "writers", "updater", "wscript", "zlib",
    }
    KNOWN_TLDS_FOR_GLUE_REPAIR = {
        "com", "net", "org", "top", "icu", "site", "onion", "info", "biz",
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
        r"^(?:(?:domains?|urls?)(?:h|https?)?|h|https?|returns?|both|can|the|this|"
        r"until|now|once|and|from|with|that|which|also|into|for|"
        r"was|were|is|are|by|to|of|in|on|at|as|or|if|then|when|html|pdf|png|jpg)$",
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
        "sentinelone.com", "www.sentinelone.com",
        "google.com", "www.google.com", "policies.google.com",
        "reddit.com", "www.reddit.com",
        "youtube.com", "www.youtube.com",
        "medium.com", "www.medium.com",
        "wikipedia.org", "en.wikipedia.org",
        "microsoft.com", "www.microsoft.com",
        "apple.com", "www.apple.com",
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
        include_relationships: bool = True,
    ) -> Dict[str, List[str]]:
        text = cls._normalize_indicator_text(str(text or ""))
        if not text.strip():
            return {}

        urls = cls._extract_urls(text)
        ips = cls._extract_ips(text)
        public_ips = [ip for ip in ips if cls.is_public_ip(ip)]
        non_public_ips = [ip for ip in ips if not cls.is_public_ip(ip)]
        ipv6 = [ip for ip in ips if ":" in ip]
        hashes = cls._extract_hashes(text)
        artefacts = {
            "ips": ips if include_non_public_ips else public_ips,
            "public_ips": public_ips,
            "non_public_ips": non_public_ips,
            "ipv6": ipv6,
            "domains": cls._extract_domains(text, urls),
            "urls": urls,
            "emails": cls._unique(IOCNormalizer.canonical_email(match.group(0)) or match.group(0).lower() for match in cls.EMAIL_RE.finditer(text)),
            "hashes": hashes,
            "cves": cls._unique(IOCNormalizer.canonical_cve(match.group(0)) or match.group(0).upper() for match in cls.CVE_RE.finditer(text)),
            "cwes": cls._unique(IOCNormalizer.canonical_cwe(match.group(0)) or match.group(0).upper() for match in cls.CWE_RE.finditer(text)),
            "mitre_techniques": cls._unique(match.group(0).upper() for match in cls.MITRE_TECHNIQUE_RE.finditer(text)),
            "mitre_tactics": cls._unique(match.group(0).upper() for match in cls.MITRE_TACTIC_RE.finditer(text)),
            "threat_actors": cls._extract_threat_actors(text, expand_related=False),
            "threat_actor_aliases": cls._extract_declared_threat_actor_aliases(text),
            "malware_families": cls._extract_named_entities(text, cls.MALWARE_CONTEXT_PATTERNS, cls._is_plausible_malware_name),
            "campaigns": cls._extract_named_entities(text, cls.CAMPAIGN_CONTEXT_PATTERNS, cls._is_plausible_campaign_name),
            "tools": cls._extract_named_entities(text, cls.TOOL_CONTEXT_PATTERNS, cls._is_plausible_tool_name),
            "filenames": cls._extract_filenames(text),
            "file_paths": cls._extract_file_paths(text),
            "registry_keys": cls._extract_registry_keys(text),
            "mutexes": cls._extract_mutexes(text),
            "user_agents": cls._extract_user_agents(text),
            "crypto_addresses": cls._unique(match.group(0) for match in cls.CRYPTO_ADDRESS_RE.finditer(text)),
        }
        if include_relationships:
            artefacts["relationships"] = cls._format_relationship_strings(
                cls.extract_relationship_records(text, artefacts)
            )
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

            if object_type == "relationship":
                source_name = value.get("source_ref")
                target_name = value.get("target_ref")
                rel_type = str(value.get("relationship_type") or "related-to").strip().lower()
                if isinstance(source_name, str) and isinstance(target_name, str):
                    add("relationships", f"{source_name} {rel_type} {target_name}")
            elif object_type in {"threat-actor", "intrusion-set"}:
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
            if key == "ipv6":
                cleaned = [
                    str(value).strip()
                    for value in values or []
                    if value and cls.is_public_ip(str(value).strip())
                ]
                if cleaned:
                    filtered[key] = cls._unique(cleaned)
                continue
            if key in {"filenames", "file_paths", "registry_keys", "mutexes", "user_agents", "crypto_addresses"}:
                cleaned = cls._unique(str(value).strip() for value in values or [] if value)
                if key == "filenames":
                    cleaned = [name for name in cleaned if name.lower() not in cls.LOW_SIGNAL_FILENAMES]
                if cleaned:
                    filtered[key] = cleaned
                continue
            if key == "relationships":
                cleaned = cls._unique(str(value).strip() for value in values or [] if value)
                if cleaned:
                    filtered[key] = cleaned
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
            "mitre_tactics": "MITRE Tactics",
            "threat_actors": "Threat Actors",
            "threat_actor_aliases": "Related Actor Aliases",
            "malware_families": "Malware Families",
            "campaigns": "Campaigns",
            "tools": "Tools",
            "courses_of_action": "Courses of Action",
            "filenames": "Filenames",
            "file_paths": "File Paths",
            "registry_keys": "Registry Keys",
            "mutexes": "Mutexes",
            "user_agents": "User Agents",
            "ipv6": "IPv6",
            "cwes": "CWEs",
            "relationships": "Relationships",
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
    def _extract_hashes(cls, text: str) -> List[str]:
        values = []
        for match in cls.HASH_RE.finditer(text or ""):
            canonical = IOCNormalizer.canonical_hash(match.group(0))
            if canonical:
                values.append(canonical)
        for match in cls.CERT_FINGERPRINT_RE.finditer(text or ""):
            canonical = IOCNormalizer.canonical_hash(match.group(0))
            if canonical:
                values.append(canonical)
        return cls._unique(values)

    @classmethod
    def extract_ioc_records(cls, text: Any, max_items: int = 80) -> List[Dict[str, Any]]:
        """Return machine-identifiable IOCs with canonical form, offset, and sentence context."""
        original = str(text or "")
        if not original.strip():
            return []
        normalized = cls._normalize_indicator_text(original)
        sentences = cls._split_sentences(normalized)
        records: List[Dict[str, Any]] = []

        def context_for(offset: int, length: int) -> str:
            for sentence in sentences:
                start = normalized.find(sentence)
                if start <= offset <= start + len(sentence):
                    return sentence[:240]
            return normalized[max(0, offset - 80):offset + length + 80][:240]

        extractors = (
            ("ip", lambda: [
                (match.start(), match.group(0), "ip")
                for match in re.finditer(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)", normalized)
            ] + [
                (match.start(), match.group(1), "ip")
                for match in cls.IPV6_TOKEN_RE.finditer(normalized)
                if match.group(1).count(":") >= 2
            ]),
            ("url", lambda: [(match.start(), match.group(0), "url") for match in cls.URL_RE.finditer(normalized)]),
            ("email", lambda: [(match.start(), match.group(0), "email") for match in cls.EMAIL_RE.finditer(normalized)]),
            ("cve", lambda: [(match.start(), match.group(0), "cve") for match in cls.CVE_RE.finditer(normalized)]),
            ("cwe", lambda: [(match.start(), match.group(0), "cwe") for match in cls.CWE_RE.finditer(normalized)]),
            ("hash", lambda: [(match.start(), match.group(0), "hash") for match in cls.HASH_RE.finditer(normalized)]
                           + [(match.start(), match.group(0), "hash") for match in cls.CERT_FINGERPRINT_RE.finditer(normalized)]),
            ("domain", lambda: [(match.start(), match.group(0), "domain") for match in cls.DOMAIN_RE.finditer(normalized)]),
        )
        seen = set()
        for _kind, producer in extractors:
            for offset, original_value, ioc_type in producer():
                record = IOCNormalizer.record(
                    original_value,
                    ioc_type,
                    offset=offset,
                    context=context_for(offset, len(str(original_value))),
                )
                if not record:
                    continue
                key = (record["entity_type"], record["canonical_value"])
                if key in seen:
                    continue
                seen.add(key)
                records.append(record)
                if len(records) >= max_items:
                    return records
        return records

    @classmethod
    def _extract_ips(cls, text: str) -> List[str]:
        ips = []
        for candidate in cls.IPV4_CANDIDATE_RE.findall(text):
            try:
                ips.append(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
        for match in cls.IPV6_TOKEN_RE.finditer(text or ""):
            candidate = match.group(1)
            if candidate.count(":") < 2:
                continue
            try:
                parsed = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if parsed.version != 6:
                continue
            ips.append(str(parsed))
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
        labelled = []
        for match in cls.ATTACK_GROUP_RE.finditer(text):
            if cls._match_is_in_actor_alias_context(text, match.start()):
                continue
            if cls._match_is_in_low_confidence_metadata_context(text, match.start()):
                continue
            if cls._match_is_in_related_content_context(text, match.start()):
                continue
            labelled.append(match.group(0).upper())
        counts = {}
        for token in labelled:
            counts[token] = counts.get(token, 0) + 1
        actors = []
        for token, count in counts.items():
            if count >= 2:
                actors.append(token)
            elif token.startswith(("FIN", "G")):
                actors.append(token)
            elif cls._token_has_attribution_context(text, token):
                actors.append(token)
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

    @staticmethod
    def _match_is_in_related_content_context(text: str, start: int) -> bool:
        line_start = max(text.rfind("\n", 0, start), text.rfind("\r", 0, start)) + 1
        prefix = text[line_start:start]
        lookback = text[max(0, line_start - 240):start]
        pattern = (
            r"(?i)\b(?:related (?:articles?|content|posts?|reading)|also (?:read|see)|"
            r"you may also|recommended|more from|popular posts?|from the blog)\b"
        )
        return bool(re.search(pattern, lookback) or re.search(pattern, prefix))

    @classmethod
    def _token_has_attribution_context(cls, text: str, token: str) -> bool:
        pattern = re.compile(rf"(?i)(?<!\w){re.escape(token)}(?!\w)")
        for match in pattern.finditer(text or ""):
            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 80)
            window = text[start:end]
            if re.search(
                r"(?i)\b(?:threat actor|threat group|intrusion set|adversary|attributed|activity group|"
                r"apt group|tracked as|also known as)\b",
                window,
            ):
                return True
        return False

    @classmethod
    def _extract_named_entities(cls, text: str, patterns, validator) -> List[str]:
        names: List[str] = []
        for pattern in patterns:
            for match in pattern.finditer(text or ""):
                raw = match.group("names")
                normalized = re.sub(r"\s+(?:and|or)\s+", ", ", str(raw or ""), flags=re.IGNORECASE)
                for part in normalized.split(","):
                    candidate = re.sub(r"\s+", " ", part).strip(" \t\r\n'\"`.,;:()[]{}<>")
                    candidate = re.sub(r"^(?:the|a|an)\s+", "", candidate, flags=re.IGNORECASE).strip()
                    if validator(candidate):
                        names.append(candidate)
        return cls._unique(names)

    @classmethod
    def _is_plausible_malware_name(cls, candidate: str) -> bool:
        candidate = str(candidate or "").strip(" \t\r\n'\"`.,;:()[]{}<>")
        if not candidate:
            return False
        upper = candidate.upper()
        if upper in cls.MALWARE_FALSE_POSITIVES:
            return False
        if any(part in cls.MALWARE_FALSE_POSITIVES for part in upper.split()):
            return False
        if cls.ATTACK_GROUP_RE.fullmatch(candidate) or cls.CVE_RE.fullmatch(candidate):
            return False
        if cls.MITRE_TECHNIQUE_RE.fullmatch(candidate) or cls.MITRE_TACTIC_RE.fullmatch(candidate):
            return False
        if cls.DOMAIN_RE.fullmatch(candidate) or candidate.lower().endswith(tuple(cls.COMMON_FALSE_DOMAIN_SUFFIXES)):
            return False
        words = candidate.split()
        if not (1 <= len(words) <= 3):
            return False
        if len(candidate) < 3 or len(candidate) > 48:
            return False
        if words[0].lower() in {
            "to", "with", "is", "by", "from", "in", "via", "over", "the", "and", "or",
            "for", "on", "at", "as", "of",
        }:
            return False
        if any(re.search(r"[A-Z]{3,}[a-z]+[A-Z]", word) for word in words):
            return False
        if any(re.search(r"[A-Z]{5,}[a-z]", word) for word in words):
            return False
        if len(words) >= 2 and not any(
            re.fullmatch(r"[A-Z]{3,40}", word)
            or re.fullmatch(r"[A-Z][a-z]+[A-Z][A-Za-z0-9_-]*", word)
            or "-" in word
            for word in words
        ):
            return False
        return any(cls._looks_like_named_malware_token(word) for word in words)

    @staticmethod
    def _looks_like_named_malware_token(token: str) -> bool:
        token = str(token or "").strip()
        if len(token) < 3:
            return False
        if re.search(r"[A-Z]{3,}[a-z]+[A-Z]", token):
            return False
        if token.lower().endswith(("-tailored", "-derived", "-based", "-related", "-themed")):
            return False
        if re.fullmatch(r"[A-Z]{3,40}", token):
            return True
        if re.fullmatch(r"[A-Z][a-z]+[A-Z][A-Za-z0-9_-]*", token):
            return True
        if re.search(r"\d", token) or "-" in token:
            return True
        if token.lower().endswith(("rat", "bot", "stealer", "locker", "wiper", "backdoor")):
            return True
        return bool(re.fullmatch(r"[A-Z][a-z]{3,39}", token))

    @classmethod
    def _is_plausible_campaign_name(cls, candidate: str) -> bool:
        candidate = str(candidate or "").strip(" \t\r\n'\"`.,;:()[]{}<>")
        if not candidate:
            return False
        if candidate.upper() in cls.MALWARE_FALSE_POSITIVES:
            return False
        if cls.ATTACK_GROUP_RE.fullmatch(candidate) or cls.CVE_RE.fullmatch(candidate):
            return False
        words = candidate.split()
        if words and words[0].lower() == "operation" and len(words) == 1:
            return False
        return 1 <= len(words) <= 4 and 3 <= len(candidate) <= 60

    @classmethod
    def _is_plausible_tool_name(cls, candidate: str) -> bool:
        candidate = str(candidate or "").strip(" \t\r\n'\"`.,;:()[]{}<>")
        if not candidate:
            return False
        upper = candidate.upper()
        if upper in cls.TOOL_FALSE_POSITIVES:
            return False
        if any(part in cls.TOOL_FALSE_POSITIVES for part in upper.split()):
            return False
        if cls.ATTACK_GROUP_RE.fullmatch(candidate) or cls.CVE_RE.fullmatch(candidate):
            return False
        return 1 <= len(candidate.split()) <= 3 and 3 <= len(candidate) <= 40

    @classmethod
    def _extract_filenames(cls, text: str) -> List[str]:
        names = []
        for match in cls.FILENAME_RE.finditer(text or ""):
            name = match.group("name")
            if name and name.lower() not in cls.LOW_SIGNAL_FILENAMES:
                names.append(name)
        return cls._unique(names)

    @classmethod
    def _extract_file_paths(cls, text: str) -> List[str]:
        paths = []
        for match in cls.FILE_PATH_RE.finditer(text or ""):
            path = match.group("path").rstrip(".,;:)")
            if not path:
                continue
            windows = path.replace("/", "\\")
            # Require a host AND share for UNC paths so ``POS\\cashier07`` is
            # not treated as a filesystem path.
            if windows.startswith("\\\\") and windows.count("\\") < 3:
                continue
            paths.append(path)
        return cls._unique(paths)

    @classmethod
    def _extract_registry_keys(cls, text: str) -> List[str]:
        keys = []
        for match in cls.REGISTRY_RE.finditer(text or ""):
            key = match.group(0).rstrip(".,;:)")
            while "\\\\" in key:
                key = key.replace("\\\\", "\\")
            if key:
                keys.append(key)
        return cls._unique(keys)

    @classmethod
    def _extract_mutexes(cls, text: str) -> List[str]:
        values = []
        for match in cls.MUTEX_RE.finditer(text or ""):
            value = match.group("name") or match.group("global")
            if value:
                values.append(value.strip())
        return cls._unique(values)

    @classmethod
    def _extract_user_agents(cls, text: str) -> List[str]:
        values = []
        for match in cls.USER_AGENT_RE.finditer(text or ""):
            ua = re.sub(r"\s+", " ", match.group("ua") or "").strip(" \t\"'")
            if ua:
                values.append(ua[:240])
        return cls._unique(values)

    @classmethod
    def extract_relationship_records(
        cls,
        text: Any,
        artefacts: Dict[str, List[str]] = None,
        max_items: int = 40,
    ) -> List[Dict[str, str]]:
        """Extract chunk-local entity relationships with source-sentence provenance.

        Relationships are only recorded when both endpoints were independently
        extracted from the same text, so co-occurrence in a large document is
        not enough to imply ``Actor A used Malware C``.
        """
        text = str(text or "")
        artefacts = artefacts or cls.extract(text, include_relationships=False)
        sentences = cls._split_sentences(text)
        records: List[Dict[str, str]] = []
        seen = set()

        def add(subject: str, predicate: str, obj: str, evidence: str, subject_type: str, object_type: str, polarity: str):
            key = (subject.lower(), predicate, obj.lower(), polarity)
            if key in seen or subject.lower() == obj.lower():
                return
            seen.add(key)
            records.append({
                "subject": subject,
                "predicate": predicate,
                "object": obj,
                "subject_type": subject_type,
                "object_type": object_type,
                "polarity": polarity,
                "confidence": {
                    "explicit": "high",
                    "reported": "medium",
                    "assessed": "medium",
                    "suspected": "low",
                    "unconfirmed": "low",
                    "denied": "unsupported",
                }.get(polarity, "medium"),
                "evidence": re.sub(r"\s+", " ", evidence).strip()[:240],
            })

        entity_groups = (
            ("threat_actors", artefacts.get("threat_actors") or []),
            ("threat_actor_aliases", artefacts.get("threat_actor_aliases") or []),
            ("malware_families", artefacts.get("malware_families") or []),
            ("tools", artefacts.get("tools") or []),
            ("campaigns", artefacts.get("campaigns") or []),
            ("cves", artefacts.get("cves") or []),
            ("mitre_techniques", artefacts.get("mitre_techniques") or []),
            ("domains", artefacts.get("domains") or []),
            ("ips", artefacts.get("public_ips") or artefacts.get("ips") or []),
            ("hashes", artefacts.get("hashes") or []),
            ("filenames", artefacts.get("filenames") or []),
        )

        for sentence in sentences:
            if len(sentence) > 480:
                continue
            present = []
            lower = sentence.lower()
            for entity_type, values in entity_groups:
                for value in values:
                    token = str(value or "").strip()
                    if not token or len(token) < 3:
                        continue
                    if token.lower() not in lower and token.upper() not in sentence:
                        continue
                    present.append((entity_type, token))
                    if len(present) >= 8:
                        break
                if len(present) >= 8:
                    break
            if len(present) < 2:
                continue
            for index, (left_type, left) in enumerate(present):
                for right_type, right in present[index + 1:]:
                    if left_type == right_type and left_type not in {
                        "threat_actors", "threat_actor_aliases", "malware_families",
                    }:
                        continue
                    span = cls._text_between(sentence, left, right)
                    if not span or len(span) > 240:
                        continue
                    chosen = cls._select_relationship_predicate(left_type, right_type, span)
                    if chosen is None:
                        polarity_hint = cls._relationship_polarity(sentence)
                        if polarity_hint in {"denied", "unconfirmed", "suspected", "assessed", "reported"}:
                            chosen = "associated_with"
                        else:
                            continue
                    polarity = cls._relationship_polarity(sentence)
                    if {left_type, right_type} <= {"threat_actors", "threat_actor_aliases"}:
                        if not re.search(r"(?i)\b(?:alias(?:es)?|aka|also known as|tracked as)\b", span):
                            continue
                        chosen = "aliases"
                    if chosen == "exploits" and "cves" not in {left_type, right_type}:
                        continue
                    if "mitre_techniques" in {left_type, right_type} and {left_type, right_type} & {
                        "domains", "ips", "hashes", "filenames", "urls",
                    }:
                        continue
                    if (
                        {"domains", "ips", "hashes", "filenames"} & {left_type, right_type}
                        and chosen not in {"communicates_with", "uses", "delivers", "exploits", "attributed_to"}
                    ):
                        continue
                    if (
                        {"domains", "ips"} & {left_type, right_type}
                        and chosen == "exploits"
                    ):
                        continue
                    actor_types = {"threat_actors", "threat_actor_aliases"}
                    if chosen == "attributed_to" and (left_type in actor_types) != (right_type in actor_types):
                        if left_type in actor_types:
                            add(right, chosen, left, sentence, right_type, left_type, polarity)
                        else:
                            add(left, chosen, right, sentence, left_type, right_type, polarity)
                    elif chosen == "uses":
                        subject_priority = {
                            "threat_actors": 0,
                            "threat_actor_aliases": 1,
                            "campaigns": 2,
                            "malware_families": 3,
                            "tools": 4,
                        }
                        if subject_priority.get(right_type, 9) < subject_priority.get(left_type, 9):
                            add(right, chosen, left, sentence, right_type, left_type, polarity)
                        else:
                            add(left, chosen, right, sentence, left_type, right_type, polarity)
                    elif left_type in {"cves", "mitre_techniques", "domains", "ips", "hashes", "filenames"}:
                        add(right, chosen, left, sentence, right_type, left_type, polarity)
                    else:
                        add(left, chosen, right, sentence, left_type, right_type, polarity)
                    if len(records) >= max_items:
                        return records
        return records

    @classmethod
    def _select_relationship_predicate(cls, left_type: str, right_type: str, span: str) -> Optional[str]:
        """Choose a predicate from span evidence and entity types, not co-occurrence."""
        types = {left_type, right_type}
        found = [name for name, pattern in cls.RELATIONSHIP_VERB_MAP if pattern.search(span)]
        if "cves" in types:
            if "malware_families" in types and re.search(r"(?i)\bafter exploiting\b", span):
                return None
            if "exploits" in found or re.search(r"(?i)\bexploit", span):
                if types & {"threat_actors", "threat_actor_aliases", "malware_families", "tools", "campaigns"}:
                    return "exploits"
            return None
        if types & {"threat_actors", "threat_actor_aliases"} and types & {"malware_families", "tools"}:
            if "uses" in found:
                return "uses"
            if "delivers" in found:
                return "delivers"
        if "campaigns" in types and types & {"malware_families", "tools", "threat_actors", "threat_actor_aliases"}:
            if "uses" in found:
                return "uses"
            if "targets" in found:
                return "targets"
        if types & {"domains", "ips"} and types & {
            "threat_actors", "threat_actor_aliases", "malware_families", "tools", "campaigns",
        }:
            if "communicates_with" in found:
                return "communicates_with"
            if "attributed_to" in found:
                return "attributed_to"
            if "uses" in found:
                return "uses"
        if "mitre_techniques" in types and types & {
            "threat_actors", "threat_actor_aliases", "malware_families", "tools", "campaigns",
        }:
            if "uses" in found:
                return "uses"
            if found and found[0] != "exploits":
                return found[0]
            return None
        if found:
            return found[0]
        return None

    @classmethod
    def _format_relationship_strings(cls, records: Iterable[Dict[str, str]]) -> List[str]:
        values = []
        for record in records or []:
            subject = str(record.get("subject") or "").strip()
            predicate = str(record.get("predicate") or "").strip()
            obj = str(record.get("object") or "").strip()
            polarity = str(record.get("polarity") or "explicit").strip()
            if not (subject and predicate and obj):
                continue
            if polarity in {"denied", "unconfirmed", "suspected", "assessed", "reported"}:
                values.append(f"{subject} {polarity} {predicate} {obj}")
            else:
                values.append(f"{subject} {predicate} {obj}")
        return cls._unique(values)

    @classmethod
    def _relationship_polarity(cls, sentence: str) -> str:
        text = str(sentence or "")
        for name, pattern in cls.RELATIONSHIP_POLARITY_PATTERNS:
            if pattern.search(text):
                return name
        return "explicit"

    @staticmethod
    def _text_between(text: str, left: str, right: str) -> str:
        haystack = str(text or "")
        left_text = str(left or "")
        right_text = str(right or "")
        if not haystack or not left_text or not right_text:
            return ""
        lower = haystack.lower()
        left_at = lower.find(left_text.lower())
        right_at = lower.find(right_text.lower())
        if left_at < 0 or right_at < 0:
            return ""
        start = min(left_at + len(left_text), right_at + len(right_text))
        end = max(left_at, right_at)
        if end <= start:
            return ""
        return haystack[start:end]

    @staticmethod
    def _split_sentences(text: str) -> List[str]:
        parts = re.split(r"(?<=[.!?;\n])\s+", str(text or ""))
        sentences: List[str] = []
        for part in parts:
            part = part.strip()
            if len(part) < 12:
                continue
            if len(part) <= 420:
                sentences.append(part)
                continue
            for piece in re.split(r"(?<=[,;:])\s+| {2,}|\t+", part):
                piece = piece.strip()
                if len(piece) >= 12:
                    sentences.append(piece[:420])
        return sentences

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
        if re.search(r"[#:/]|^\d", normalized):
            return False
        if cls.MITRE_TACTIC_RE.fullmatch(normalized):
            return False
        if upper in cls.ACTOR_FALSE_POSITIVES:
            return False
        if any(part in cls.ACTOR_FALSE_POSITIVES for part in upper.split()) and len(upper.split()) == 1:
            return False
        if cls.CVE_RE.fullmatch(normalized) or cls.MITRE_TECHNIQUE_RE.fullmatch(normalized):
            return False
        if any(char in normalized for char in ("/", "\\", "@", "!", ")", "(", '"', "'", "“", "”")):
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
        if any(
            re.sub(r"[^A-Z0-9]", "", word) in cls.ACTOR_FALSE_POSITIVES
            for word in words
        ):
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
        return bool(
            ip.is_global
            and not ip.is_multicast
            and not ip.is_reserved
            and not ip.is_loopback
            and not ip.is_link_local
            and not ip.is_unspecified
        )

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
        if (
            len(labels) == 2
            and tld not in cls.PROMOTABLE_CTI_TLDS
            and not tld.startswith("xn--")
            and len(tld) > 4
        ):
            return True
        if labels[0] in cls.COMMON_FALSE_DOMAIN_PREFIXES and tld in cls.COMMON_FALSE_DOMAIN_TLDS | {
            "path", "name", "fullname", "decompress", "run", "echo",
        }:
            return True
        if len(domain) > 120:
            return True
        if len(domain) > 48 and "-" not in domain and domain.count(".") == 1:
            return True
        tld = labels[-1]
        sld = labels[-2] if len(labels) >= 2 else ""
        if len(sld) <= 1:
            return True
        if tld in {"th", "tm"} and len(labels) == 2:
            return True
        if tld == "host" and len(labels) == 2:
            return True
        if len(labels) == 2 and sld.isdigit():
            return True
        if re.search(r"\.com[a-z]{2,}", domain):
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
            right_core = right.rstrip(".,;:)")
            left_core = left.rstrip(".,;:)")
            # Sentence-wrapped identifiers (CVE, email, "Campaign ...") must
            # remain separate tokens. Only join fragments of the same IOC.
            if re.match(r"(?i)(?:cve-|cwe-|t\d{4})", right_core) and re.fullmatch(r"[A-Za-z]{2,}", left_core):
                return f"{left} {right}"
            if "@" in right and re.fullmatch(r"[A-Za-z]{2,}", left_core):
                return f"{left} {right}"
            if "@" in left and re.match(r"[A-Za-z]", right_core):
                return f"{left} {right}"
            if left.endswith(".") and right[:1].isupper():
                return f"{left} {right}"
            indicatorish = (
                ("." in left.rstrip(".") or "." in right_core)
                or "/" in left or "/" in right
                or "[" in left or "]" in right
                or colon_indicates_wrapped_url
                or (len(combined) in {32, 40, 64, 96, 128} and re.fullmatch(r"[A-Fa-f0-9]+", combined))
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
            (r"(?i)(?<=[A-Za-z0-9])hxxps://", "https://"),
            (r"(?i)(?<=[A-Za-z0-9])hxxp://", "http://"),
            (r"(?i)hxxps://", "https://"),
            (r"(?i)hxxp://", "http://"),
            (r"(?i)\[\s*:\s*\]|\(\s*:\s*\)", ":"),
            (r"(?i)\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}", "."),
            (r"(?i)\s+\[\s*dot\s*\]\s+|\s+\(\s*dot\s*\)\s+", "."),
            (r"(?i)\s+dot\s+", "."),
        )
        for pattern, replacement in replacements:
            normalized = re.sub(pattern, replacement, normalized)

        normalized = re.sub(r"(?i)\bhttps?\s*:\s*/\s*/", lambda m: m.group(0).replace(" ", ""), normalized)
        # PDF/HTML glue often concatenates a path onto the next scheme: ``/cdhxxp://``.
        normalized = re.sub(r"(?i)(?<=[A-Za-z0-9])(?=https?://)", " ", normalized)
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
