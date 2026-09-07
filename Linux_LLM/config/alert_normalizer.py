"""Single canonical normalisation boundary for every Wazuh ingestion path.

Manual upload, SSH live ingestion and SSH archive ingestion all route alerts
through :meth:`AlertNormalizer.normalize` before anything downstream reads
them. Previously only manual uploads were normalised, so native Wazuh decoder
output arriving over SSH -- sshd, syscheck/FIM, Windows eventchannel/Sysmon,
auditd -- reached the analyser with none of its security fields in the places
the analyser looks, and was frequently discarded as "no meaningful alert
information".

Design notes
------------
* **Aliases, not per-module schemas.** Every source variation is declared once
  in :data:`AlertNormalizer.ALIAS_REGISTRY` and mapped into the canonical
  Wazuh/EVE-shaped ``data.*`` paths that ``AlertAnalyzer.clean_log_data``
  already consumes. Adding a decoder means adding a row to the registry, not
  editing retrieval, chunking and reporting code.
* **Non-destructive.** Aliases only ever fill a *missing* target, the original
  record is preserved verbatim as ``_raw_alert``, and unmapped security-looking
  fields are sampled into ``_unknown_security_fields``.
* **Provenance.** ``_evidence_provenance`` records which source path populated
  each canonical field, so a claim in a report can be traced to a decoder field.
* **No silent drops.** A record that only partially normalises keeps whatever
  was recovered and gains a ``_normalization_warnings`` entry; counters are
  exposed through :meth:`AlertNormalizer.normalize_many` for operators.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "alert-schema-v3"
# Accepted as already-normalised so re-entering the boundary is a no-op.
COMPATIBLE_SCHEMA_VERSIONS = {SCHEMA_VERSION}


class AlertNormalizer:
    """Map heterogeneous alert shapes onto one canonical representation."""

    SCHEMA_VERSION = SCHEMA_VERSION

    # Suricata EVE records arrive with their protocol objects at the top level
    # rather than under ``data``.
    EVE_KEYS = frozenset({
        "event_type", "src_ip", "dest_ip", "src_port", "dest_port", "proto",
        "app_proto", "alert", "http", "dns", "tls", "flow", "fileinfo",
        "process", "vulnerability", "threat", "ioc", "ics", "windows", "network",
    })

    # Elastic Common Schema and other dotted/nested conventions.
    ECS_ALIASES: Tuple[Tuple[str, str], ...] = (
        ("source.ip", "data.src_ip"),
        ("source.port", "data.src_port"),
        ("destination.ip", "data.dest_ip"),
        ("destination.port", "data.dest_port"),
        ("network.transport", "data.proto"),
        ("network.protocol", "data.app_proto"),
        ("url.full", "data.http.url"),
        ("url.domain", "data.http.hostname"),
        ("user_agent.original", "data.http.user_agent"),
        ("dns.question.name", "data.dns.rrname"),
        ("tls.server.ja3s", "data.tls.ja3s"),
        ("file.name", "data.fileinfo.filename"),
        ("file.path", "data.fileinfo.path"),
        ("file.hash.md5", "data.fileinfo.md5"),
        ("file.hash.sha1", "data.fileinfo.sha1"),
        ("file.hash.sha256", "data.fileinfo.sha256"),
        ("process.name", "data.process.name"),
        ("process.command_line", "data.process.command_line"),
        ("process.executable", "data.process.path"),
        ("process.pid", "data.process.pid"),
        ("process.parent.executable", "data.process.parent_process"),
        ("host.name", "agent.name"),
        ("host.ip", "agent.ip"),
        ("user.name", "data.user.name"),
        ("vulnerability.id", "data.vulnerability.id"),
        ("vulnerability.product", "data.vulnerability.product"),
        ("vulnerability.version", "data.vulnerability.version"),
        ("threat.actor", "data.threat.actor"),
        ("threat.campaign", "data.threat.campaign"),
        ("threat.software", "data.threat.malware"),
        ("event.original", "full_log"),
    )

    # Native Wazuh decoder output. These are the fields that previously had no
    # route into the analyser at all.
    NATIVE_WAZUH_ALIASES: Tuple[Tuple[str, str], ...] = (
        # Generic network decoders (sshd, web, firewall, ...).
        ("data.srcip", "data.src_ip"),
        ("data.dstip", "data.dest_ip"),
        ("data.srcport", "data.src_port"),
        ("data.dstport", "data.dest_port"),
        ("data.srcuser", "data.user.name"),
        ("data.dstuser", "data.user.target_name"),
        ("data.protocol", "data.app_proto"),
        ("data.url", "data.http.url"),
        ("data.status", "data.http.status"),
        ("data.system_name", "data.host.name"),
        ("data.hostname", "data.host.name"),
        ("data.command", "data.process.command_line"),

        # Syscheck / FIM.
        ("syscheck.path", "data.fileinfo.path"),
        ("syscheck.path", "data.fileinfo.filename"),
        ("syscheck.md5_after", "data.fileinfo.md5"),
        ("syscheck.sha1_after", "data.fileinfo.sha1"),
        ("syscheck.sha256_after", "data.fileinfo.sha256"),
        ("syscheck.size_after", "data.fileinfo.size"),
        ("syscheck.event", "data.fileinfo.state"),
        ("syscheck.uname_after", "data.user.name"),
        ("syscheck.win_perm_after", "data.fileinfo.permissions"),
        ("data.syscheck.path", "data.fileinfo.path"),
        ("data.syscheck.path", "data.fileinfo.filename"),
        ("data.syscheck.md5_after", "data.fileinfo.md5"),
        ("data.syscheck.sha1_after", "data.fileinfo.sha1"),
        ("data.syscheck.sha256_after", "data.fileinfo.sha256"),
        ("data.syscheck.event", "data.fileinfo.state"),
        ("data.syscheck.uname_after", "data.user.name"),

        # Windows eventchannel / Sysmon.
        ("data.win.eventdata.commandLine", "data.process.command_line"),
        ("data.win.eventdata.image", "data.process.path"),
        ("data.win.eventdata.originalFileName", "data.process.name"),
        ("data.win.eventdata.parentImage", "data.process.parent_process"),
        ("data.win.eventdata.parentCommandLine", "data.process.parent_command_line"),
        ("data.win.eventdata.processId", "data.process.pid"),
        ("data.win.eventdata.user", "data.process.user"),
        ("data.win.eventdata.subjectUserName", "data.user.name"),
        ("data.win.eventdata.targetUserName", "data.user.target_name"),
        ("data.win.eventdata.sourceIp", "data.src_ip"),
        ("data.win.eventdata.ipAddress", "data.src_ip"),
        ("data.win.eventdata.destinationIp", "data.dest_ip"),
        ("data.win.eventdata.sourcePort", "data.src_port"),
        ("data.win.eventdata.destinationPort", "data.dest_port"),
        ("data.win.eventdata.destinationHostname", "data.http.hostname"),
        ("data.win.eventdata.queryName", "data.dns.rrname"),
        ("data.win.eventdata.targetFilename", "data.fileinfo.filename"),
        ("data.win.eventdata.protocol", "data.app_proto"),
        ("data.win.system.computer", "data.host.name"),
        ("data.win.system.eventID", "data.event_type"),

        # Linux auditd.
        ("data.audit.exe", "data.process.path"),
        ("data.audit.command", "data.process.name"),
        ("data.audit.pid", "data.process.pid"),
        ("data.audit.acct", "data.user.name"),
        ("data.audit.uid", "data.user.uid"),
        ("data.audit.auid", "data.user.audit_uid"),
        ("data.audit.euid", "data.user.effective_uid"),
        ("data.audit.file.name", "data.fileinfo.filename"),
        ("data.audit.cwd", "data.process.working_directory"),
        ("data.audit.key", "data.audit_rule_key"),

        # Osquery / cloud decoders keep their identifying fields reachable.
        ("data.osquery.columns.path", "data.fileinfo.path"),
        ("data.aws.sourceIPAddress", "data.src_ip"),
        ("data.aws.userIdentity.userName", "data.user.name"),
        ("data.office365.ClientIP", "data.src_ip"),
        ("data.office365.UserId", "data.user.name"),
        ("data.gcp.jsonPayload.sourceIP", "data.src_ip"),
    )

    ALIAS_REGISTRY: Tuple[Tuple[str, str], ...] = ECS_ALIASES + NATIVE_WAZUH_ALIASES

    # Canonical paths worth recording provenance for once populated.
    CANONICAL_PATHS: Tuple[str, ...] = (
        "rule.id", "rule.description", "rule.level", "rule.mitre",
        "agent.name", "agent.ip", "data.src_ip", "data.dest_ip",
        "data.src_port", "data.dest_port", "data.proto", "data.app_proto",
        "data.alert", "data.http", "data.dns", "data.tls", "data.ioc",
        "data.process", "data.files", "data.fileinfo", "data.vulnerability",
        "data.threat", "data.ics", "data.windows", "data.network", "data.mitre",
        "data.user", "data.host", "full_log",
    )

    # Containers we recurse into when sampling unknown fields, so their
    # unmapped children are preserved instead of the whole container consuming
    # the sampling budget.
    KNOWN_CONTAINERS = frozenset({
        "rule", "agent", "manager", "decoder", "data", "timestamp", "full_log",
        "location", "_source", "event_type", "src_ip", "dest_ip", "src_port",
        "dest_port", "proto", "app_proto", "alert", "http", "dns", "tls",
        "flow", "fileinfo", "files", "process", "network", "source",
        "destination", "url", "file", "host", "user", "vulnerability", "threat",
        "event", "affected_items", "alerts",
        # Native Wazuh containers added with the decoder aliases above.
        "syscheck", "win", "eventdata", "system", "audit", "execve",
        "osquery", "aws", "office365", "gcp", "docker", "sca",
    })

    MAX_TEXT_FIELD_CHARS = 4096

    # ------------------------------------------------------------------
    # Small path helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_alert_root(alert: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
        """Return the alert body, accepting Elasticsearch ``_source`` wrappers."""
        if "_source" not in alert:
            return alert
        source = alert.get("_source")
        if not isinstance(source, dict):
            raise ValueError(f"Alert {index}: _source must be a JSON object")
        return source

    @staticmethod
    def path_value(value: Any, path: str) -> Any:
        """Read either a literal dotted key or its nested-object equivalent."""
        if isinstance(value, dict) and path in value:
            return value.get(path)
        current: Any = value
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current.get(part)
        return current

    @staticmethod
    def set_nested_missing(root: Dict[str, Any], path: str, value: Any) -> bool:
        """Fill a canonical path only when it is currently empty."""
        if value in (None, "", [], {}):
            return False
        current = root
        parts = path.split(".")
        for part in parts[:-1]:
            child = current.get(part)
            if not isinstance(child, dict):
                child = {}
                current[part] = child
            current = child
        if current.get(parts[-1]) in (None, "", [], {}):
            current[parts[-1]] = value
            return True
        return False

    @classmethod
    def bounded_unknown_fields(
        cls, value: Any, depth: int = 0, budget: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """Keep a small analyst-visible sample of otherwise unmapped fields.

        Future decoder fields therefore remain visible to an analyst even
        though no alias exists for them yet.
        """
        if budget is None:
            budget = [32]
        if not isinstance(value, dict) or depth > 5 or budget[0] <= 0:
            return {}
        output: Dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item)):
            if budget[0] <= 0:
                break
            text_key = str(key)
            child = value.get(key)
            if text_key.lower() in cls.KNOWN_CONTAINERS:
                nested = cls.bounded_unknown_fields(child, depth + 1, budget)
                if nested:
                    output[text_key] = nested
                continue
            if isinstance(child, dict):
                nested = cls.bounded_unknown_fields(child, depth + 1, budget)
                if nested:
                    output[text_key] = nested
            elif isinstance(child, list):
                safe = [item for item in child[:8] if isinstance(item, (str, int, float, bool))]
                if safe:
                    output[text_key] = safe
                    budget[0] -= 1
            elif isinstance(child, (str, int, float, bool)) and str(child)[:1024]:
                output[text_key] = str(child)[:1024] if isinstance(child, str) else child
                budget[0] -= 1
        return output

    @staticmethod
    def parse_embedded_event(value: Any, depth: int = 0) -> Optional[Dict[str, Any]]:
        """Parse a serialised EVE/ECS record carried inside a text field."""
        if depth > 2 or not isinstance(value, str) or not value.strip() or len(value) > 65536:
            return None
        candidate = value.strip()
        if not (candidate.startswith("{") and candidate.endswith("}")):
            return None
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, RecursionError):
            return None
        return parsed if isinstance(parsed, dict) else None

    # ------------------------------------------------------------------
    # Decoder-specific reconstruction
    # ------------------------------------------------------------------

    @classmethod
    def _reconstruct_auditd_command(cls, root: Dict[str, Any]) -> Optional[str]:
        """Rebuild a command line from auditd's execve a0..aN argument fields."""
        execve = cls.path_value(root, "data.audit.execve")
        if not isinstance(execve, dict):
            return None
        arguments = []
        for index in range(64):
            value = execve.get(f"a{index}")
            if value in (None, ""):
                break
            arguments.append(str(value))
        if not arguments:
            return None
        return " ".join(arguments)[:cls.MAX_TEXT_FIELD_CHARS]

    @staticmethod
    def _split_sysmon_hashes(value: Any) -> Dict[str, str]:
        """Split Sysmon's ``SHA256=...,MD5=...`` hash string into fields."""
        text = str(value or "")
        if not text:
            return {}
        found: Dict[str, str] = {}
        for algorithm, digest in re.findall(r"(?i)\b(md5|sha1|sha256|imphash)\s*=\s*([0-9a-fA-F]{8,64})", text):
            found.setdefault(algorithm.lower(), digest.lower())
        return found

    # ------------------------------------------------------------------
    # Canonical projection
    # ------------------------------------------------------------------

    @classmethod
    def _canonical_view(cls, root: Dict[str, Any], provenance: Dict[str, List[str]]) -> Dict[str, Any]:
        """Project the normalised alert onto the canonical block.

        This is a read-only view over the canonical ``data.*`` paths. Nothing
        downstream is required to consume it, but it gives a stable, decoder
        independent shape for future consumers and for operator inspection.
        """
        def value(path: str) -> Any:
            return cls.path_value(root, path)

        def compact(mapping: Dict[str, Any]) -> Dict[str, Any]:
            return {key: item for key, item in mapping.items() if item not in (None, "", [], {})}

        data = root.get("data") if isinstance(root.get("data"), dict) else {}
        alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}

        return {
            "event_metadata": compact({
                "timestamp": value("timestamp"),
                "event_type": value("data.event_type"),
                "location": value("location"),
                "signature": alert.get("signature"),
                "category": alert.get("category"),
                "signature_id": alert.get("signature_id"),
            }),
            "wazuh_metadata": compact({
                "rule_id": value("rule.id"),
                "rule_level": value("rule.level"),
                "rule_description": value("rule.description"),
                "rule_groups": value("rule.groups"),
                "decoder": value("decoder.name") or value("decoder"),
                "manager": value("manager.name"),
            }),
            "agent": compact({
                "id": value("agent.id"),
                "name": value("agent.name"),
                "ip": value("agent.ip"),
            }),
            "host": compact({
                "name": value("data.host.name") or value("agent.name"),
            }),
            "network": compact({
                "src_ip": value("data.src_ip"),
                "src_port": value("data.src_port"),
                "dest_ip": value("data.dest_ip"),
                "dest_port": value("data.dest_port"),
                "proto": value("data.proto"),
                "app_proto": value("data.app_proto"),
                "http": data.get("http"),
                "dns": data.get("dns"),
                "tls": data.get("tls"),
            }),
            "process": compact(data.get("process") if isinstance(data.get("process"), dict) else {}),
            "user": compact(data.get("user") if isinstance(data.get("user"), dict) else {}),
            "file": compact(data.get("fileinfo") if isinstance(data.get("fileinfo"), dict) else {}),
            "iocs": compact(data.get("ioc") if isinstance(data.get("ioc"), dict) else {}),
            "mitre": compact({
                "rule": value("rule.mitre"),
                "data": value("data.mitre"),
            }),
            "_provenance": provenance,
        }

    # ------------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------------

    @classmethod
    def normalize(cls, alert: Dict[str, Any], index: int = 0,
                  ingestion_source: str = "unknown") -> Dict[str, Any]:
        """Canonicalize one alert from any ingestion path.

        Idempotent: an alert that already carries the current schema marker is
        returned as a copy without reprocessing, so passing through the
        boundary twice is harmless.
        """
        if not isinstance(alert, dict):
            raise ValueError(f"Alert {index}: record must be a JSON object")
        if alert.get("_canonical_normalized_version") in COMPATIBLE_SCHEMA_VERSIONS:
            return json.loads(json.dumps(alert, default=str))

        raw_alert = json.loads(json.dumps(alert, default=str))
        normalized_alert = json.loads(json.dumps(alert, default=str))
        warnings: List[str] = []

        try:
            root = cls.get_alert_root(normalized_alert, index)
        except ValueError as error:
            # Preserve the record rather than discarding it; downstream code
            # can still index the raw text and an operator can see why.
            warnings.append(str(error))
            root = normalized_alert

        provenance: Dict[str, List[str]] = {}

        def record(target: str, source: str, value: Any) -> None:
            if cls.set_nested_missing(root, target, value):
                provenance.setdefault(target, []).append(source)

        # A direct Suricata EVE object keeps its protocol records at top level.
        if any(key in root for key in cls.EVE_KEYS):
            for key in cls.EVE_KEYS:
                if key in root:
                    record(f"data.{key}", key, root.get(key))

        for source_path, target_path in cls.ALIAS_REGISTRY:
            record(target_path, source_path, cls.path_value(root, source_path))

        # Serialized EVE/ECS records carried inside text fields.
        for source_path, candidate in (
            ("full_log", root.get("full_log")),
            ("event.original", cls.path_value(root, "event.original")),
            ("data.event.original", cls.path_value(root, "data.event.original")),
        ):
            embedded = cls.parse_embedded_event(candidate)
            if not embedded:
                continue
            for key in cls.EVE_KEYS:
                if key in embedded:
                    record(f"data.{key}", f"{source_path}.{key}", embedded.get(key))
            for alias, target in cls.ALIAS_REGISTRY:
                record(target, f"{source_path}.{alias}", cls.path_value(embedded, alias))

        # Decoder-specific reconstruction that a flat alias cannot express.
        auditd_command = cls._reconstruct_auditd_command(root)
        if auditd_command:
            record("data.process.command_line", "data.audit.execve.a*", auditd_command)

        sysmon_hashes = cls._split_sysmon_hashes(cls.path_value(root, "data.win.eventdata.hashes"))
        for algorithm, digest in sysmon_hashes.items():
            record(f"data.fileinfo.{algorithm}", "data.win.eventdata.hashes", digest)

        cls._coerce_container_shapes(root, warnings)
        cls._apply_flat_conveniences(root)

        for canonical_path in cls.CANONICAL_PATHS:
            if cls.path_value(root, canonical_path) not in (None, "", [], {}):
                provenance.setdefault(canonical_path, [canonical_path])

        if not cls.path_value(root, "rule.description") and not cls.path_value(root, "data.alert.signature"):
            warnings.append("No rule description or alert signature could be derived")

        normalized_alert["_canonical_normalized_version"] = cls.SCHEMA_VERSION
        normalized_alert["_ingestion_source"] = str(ingestion_source or "unknown")
        normalized_alert["_raw_alert"] = raw_alert
        normalized_alert["_evidence_provenance"] = provenance
        normalized_alert["_unknown_security_fields"] = cls.bounded_unknown_fields(raw_alert)
        normalized_alert["_canonical"] = cls._canonical_view(root, provenance)
        if warnings:
            normalized_alert["_normalization_warnings"] = warnings[:8]

        return normalized_alert

    @classmethod
    def _coerce_container_shapes(cls, root: Dict[str, Any], warnings: List[str]) -> None:
        """Force scalar/array/dict variation into the shapes readers expect."""
        for container in ("rule", "agent", "data"):
            if not isinstance(root.get(container), dict):
                if root.get(container) not in (None, "", [], {}):
                    warnings.append(f"{container} was not an object and was preserved in _raw_alert")
                root[container] = {}

        data = root["data"]

        alert_value = data.get("alert")
        alert_data = alert_value if isinstance(alert_value, dict) else {}
        if alert_value not in (None, "", {}) and not isinstance(alert_value, dict):
            alert_data["signature"] = str(alert_value)
        data["alert"] = alert_data

        for nested_field in (
            "http", "tls", "email", "threat", "ioc", "process", "flow",
            "metadata", "smb", "modbus", "ics", "windows", "network",
            "vulnerability", "user", "host", "fileinfo",
        ):
            value = data.get(nested_field)
            if value in (None, ""):
                data[nested_field] = {}
            elif not isinstance(value, dict):
                data[nested_field] = {"value": value}

        dns_value = data.get("dns")
        dns = dns_value if isinstance(dns_value, dict) else {}
        if dns_value not in (None, "", {}) and not isinstance(dns_value, dict):
            dns["query"] = dns_value
        data["dns"] = dns
        # Native decoders emit a flat rrname; EVE emits a query list.
        if dns.get("rrname") and not dns.get("query"):
            dns["query"] = [{"rrname": dns.get("rrname"), "rrtype": dns.get("rrtype")}]
        query = dns.get("query")
        if isinstance(query, dict):
            dns["query"] = [query]
        elif query is not None and not isinstance(query, list):
            dns["query"] = [{"rrname": query}]

        files = data.get("files")
        if files is not None and not isinstance(files, list):
            data["files"] = [files if isinstance(files, dict) else {"value": files}]
        fileinfo = data.get("fileinfo")
        if isinstance(fileinfo, dict) and fileinfo and data.get("files") is None:
            data["files"] = [fileinfo]

    @classmethod
    def _apply_flat_conveniences(cls, root: Dict[str, Any]) -> None:
        """Accept flat convenience fields used by hand-written test alerts."""
        rule = root["rule"]
        data = root["data"]
        alert_data = data["alert"]

        for flat_key, target in (
            ("rule_id", "id"),
            ("rule_description", "description"),
        ):
            if root.get(flat_key) and not rule.get(target):
                rule[target] = root.get(flat_key)
        if root.get("rule_level") is not None and rule.get("level") is None:
            rule["level"] = root.get("rule_level")

        for flat_key, target in (("src_ip", "src_ip"), ("dest_ip", "dest_ip"), ("dst_ip", "dest_ip")):
            if root.get(flat_key) and not data.get(target):
                data[target] = root.get(flat_key)

        for flat_key, target in (
            ("alert_signature", "signature"),
            ("alert_category", "category"),
            ("signature_id", "signature_id"),
        ):
            if root.get(flat_key) and not alert_data.get(target):
                alert_data[target] = root.get(flat_key)

        # A record with no description at all would be dropped downstream as
        # "no meaningful alert information", so derive the best available label
        # rather than losing the alert.
        if not rule.get("description") and not alert_data.get("signature"):
            derived = (
                root.get("message")
                or data.get("event_type")
                or root.get("event_type")
                or cls.path_value(root, "data.audit.type")
                or cls.path_value(root, "syscheck.event")
                or cls.path_value(root, "data.syscheck.event")
                or cls.path_value(root, "decoder.name")
                or "Unclassified security event"
            )
            rule["description"] = str(derived)[:1000]

    @classmethod
    def normalize_many(
        cls,
        alerts: Any,
        ingestion_source: str = "unknown",
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Normalise a batch, counting rather than silently dropping failures."""
        normalized: List[Dict[str, Any]] = []
        stats = {
            "received": 0,
            "normalized": 0,
            "with_warnings": 0,
            "failed": 0,
            "ingestion_source": str(ingestion_source or "unknown"),
        }
        for index, alert in enumerate(alerts or [], 1):
            stats["received"] += 1
            if not isinstance(alert, dict):
                stats["failed"] += 1
                continue
            try:
                result = cls.normalize(alert, index=index, ingestion_source=ingestion_source)
            except Exception:
                # Never lose a record to a normalisation bug: keep the original
                # so it can still be indexed and reprocessed later.
                stats["failed"] += 1
                fallback = dict(alert)
                fallback["_normalization_warnings"] = ["Normalisation failed; raw alert preserved"]
                normalized.append(fallback)
                continue
            stats["normalized"] += 1
            if result.get("_normalization_warnings"):
                stats["with_warnings"] += 1
            normalized.append(result)
        return normalized, stats


def normalize_alerts(alerts: Any, ingestion_source: str = "unknown") -> List[Dict[str, Any]]:
    """Convenience wrapper for ingestion paths that do not need the counters."""
    normalized, _stats = AlertNormalizer.normalize_many(alerts, ingestion_source=ingestion_source)
    return normalized
