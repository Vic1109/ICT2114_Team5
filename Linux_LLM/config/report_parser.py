"""
Report Parser for converting between Markdown and JSON structure
"""
import re
from typing import Dict, List, Any
from datetime import datetime


class ReportParser:
    """Parse and serialize threat analysis reports"""
    
    @staticmethod
    def parse_report(markdown_text: str) -> Dict[str, Any]:
        """
        Parse markdown report into editable JSON structure
        
        Args:
            markdown_text: Raw markdown report from LLM
            
        Returns:
            Dictionary with structured report data
        """
        report = {
            "executive_summary": "",
            "key_findings": [],
            "threats": [],
            "mitre_techniques": [],
            "recommendations": [],
            "preserved_rich_sections_markdown": ReportParser._extract_rich_sections(markdown_text),
            "preserved_appendix_markdown": ReportParser._extract_preserved_appendix(markdown_text),
            "metadata": {
                "threat_level": "MEDIUM",
                "total_alerts": 0,
                "generated_at": datetime.now().isoformat(),
                "priority_actions": 0
            }
        }
        
        lines = markdown_text.split('\n')
        current_section = None
        buffer = []

        def flush_section():
            nonlocal buffer, current_section
            if current_section == "executive_summary" and buffer:
                summary = ReportParser._clean_summary_text(buffer)
                if summary:
                    report["executive_summary"] = summary
            elif current_section == "key_findings" and buffer:
                report["key_findings"] = ReportParser._parse_bullet_list(buffer)
            elif current_section == "recommendations" and buffer:
                raw_recs = ReportParser._parse_action_list(buffer)
                report["recommendations"] = ReportParser._clean_recommendations(raw_recs)
            buffer = []
        
        for line in lines:
            line_stripped = line.strip()
            
            if "**Analysis Complete**" in line:
                flush_section()
                break
            
            section_name, inline_content = ReportParser._detect_section_with_inline_content(line)

            if section_name == "executive_summary":
                flush_section()
                current_section = "executive_summary"
                buffer = [inline_content] if inline_content else []
                continue
                
            elif section_name == "key_findings":
                flush_section()
                current_section = "key_findings"
                buffer = [inline_content] if inline_content else []
                continue
                
            elif section_name == "threats":
                flush_section()
                current_section = "threats_table"
                buffer = []
                continue
                
            elif section_name == "mitre":
                flush_section()
                current_section = "mitre"
                buffer = []
                continue
                
            elif section_name == "recommendations":
                flush_section()
                current_section = "recommendations"
                buffer = [inline_content] if inline_content else []
                continue

            elif section_name == "rich":
                flush_section()
                current_section = None
                buffer = []
                continue

            elif section_name in {"technical_summary", "appendix", "stop"}:
                flush_section()
                current_section = None
                buffer = []
                continue
            
            if current_section and line_stripped:
                buffer.append(line)
        
        flush_section()
        
        report["metadata"] = ReportParser._extract_metadata(markdown_text)
        report["threats"] = ReportParser._parse_threats_table(markdown_text)
        report["mitre_techniques"] = ReportParser._parse_mitre_techniques(markdown_text)
        report["mitre_original_techniques"] = list(report["mitre_techniques"])
        report["mitre_technique_details"] = ReportParser._mitre_technique_details(markdown_text)
        report["mitre_selection_edited"] = False
        report["mitre_modified_techniques"] = []
        if not report["executive_summary"].strip() and not report["preserved_rich_sections_markdown"]:
            report["executive_summary"] = ReportParser._derive_executive_summary(report)
        if not report["key_findings"]:
            report["key_findings"] = ReportParser._derive_key_findings(report)
        if not report["recommendations"]:
            derived_recs = ReportParser._derive_recommendations(report)
            if derived_recs:
                report["recommendations"] = derived_recs
        report["metadata"]["priority_actions"] = len(report["recommendations"])
        
        return report

    @staticmethod
    def _detect_section_with_inline_content(line: str) -> tuple[str, str]:
        """Classify a heading and keep useful text that appears after the heading marker."""
        text = line.strip()
        if not text:
            return "", ""

        normalized = text.strip("#").strip()
        normalized = re.sub(r"^\*{1,3}|\*{1,3}$", "", normalized).strip()
        normalized = re.sub(r"^\d+(?:\.\d+)*[.)]?\s*", "", normalized).strip()
        normalized = re.sub(r"^(?:section|phase)\s+\d+[:.)-]?\s*", "", normalized, flags=re.IGNORECASE)
        lowered = normalized.lower()

        # Section detection must not classify ordinary prose merely because it
        # contains words such as "threat", "source", or "unanswered questions".
        known_heading_prefix = re.match(
            r"^(?:executive summary|key findings?|top(?:\s+\d+)?\s+.*threats?|"
            r"mitre\s+att(?:&|a)ck|immediate actions?|recommendations?|priority actions?|"
            r"actions? required|technical summary|incident assessment|attribution assessment|"
            r"evidence assessment|prioritized response plan|investigation plan|hunt hypotheses|"
            r"limitations|unanswered questions|report finalization|report qa findings|"
            r"rag sources used|visual threat analysis|analysis complete)\b",
            normalized,
            flags=re.IGNORECASE,
        )
        explicit_markdown_heading = bool(re.match(r"^\s*(?:#{1,6}\s+|\*\*)", text))
        if not known_heading_prefix and not explicit_markdown_heading:
            return "", ""

        def inline_after(pattern: str) -> str:
            match = re.match(pattern, normalized, flags=re.IGNORECASE)
            if not match:
                return ""
            return ReportParser._clean_inline_heading_content(match.group(1))

        if "analysis complete" in lowered:
            return "stop", ""
        if (
            "report finalization" in lowered
            or "report qa findings" in lowered
            or "rag sources used" in lowered
            or "visual threat analysis" in lowered
        ):
            return "appendix", ""
        if "executive summary" in lowered:
            return "executive_summary", inline_after(r"executive\s+summary(?:\s*\([^)]*\))?\s*:?\s*(.*)$")
        if "key finding" in lowered:
            return "key_findings", inline_after(r"key\s+findings?(?:\s*\([^)]*\))?\s*:?\s*(.*)$")
        if re.search(r"\bmitre\s+att(?:&|a)ck\b", lowered):
            return "mitre", ""
        if (
            "immediate action" in lowered
            or "recommendation" in lowered
            or "priority action" in lowered
            or "action required" in lowered
        ):
            return "recommendations", inline_after(
                r"(?:immediate\s+actions?(?:\s+required)?|recommendations?|priority\s+actions?|actions?\s+required|(?:prioritized\s+response\s+plan(?:\s+and\s+immediate\s+actions?)?))(?:\s*\([^)]*\))?\s*:?\s*(.*)$"
            )
        if re.match(
            r"^(?:incident assessment|attribution assessment|evidence assessment|"
            r"prioritized response plan|investigation plan|hunt hypotheses|"
            r"limitations|unanswered questions)\b",
            lowered,
        ):
            return "rich", ""
        if "technical summary" in lowered:
            return "technical_summary", ""
        if "threat" in lowered and (
            "top" in lowered
            or "priority" in lowered
            or "network" in lowered
            or "source" in lowered
            or "indicator" in lowered
        ):
            return "threats", ""
        return "", ""

    @staticmethod
    def _clean_inline_heading_content(text: str) -> str:
        text = str(text or "").strip()
        text = re.sub(r"^\*{1,3}|\*{1,3}$", "", text).strip()
        text = text.strip(":- \t")
        if not text or text.lower() in {"", "n/a", "none"}:
            return ""
        return text

    @staticmethod
    def _clean_summary_text(lines: List[str]) -> str:
        cleaned = []
        for line in lines:
            text = str(line or "").strip()
            if not text:
                continue
            if re.fullmatch(r'<!--.*?-->', text):
                continue
            if text in {"-", "*", "N/A", "n/a", "None", "none"}:
                continue
            if re.fullmatch(r'[-*_]{3,}', text):
                continue
            if text.startswith("|"):
                continue
            cleaned.append(text)
        return "\n".join(cleaned).strip()

    @staticmethod
    def _derive_executive_summary(report: Dict[str, Any]) -> str:
        findings = [str(item).strip().rstrip(".") for item in report.get("key_findings", []) if str(item).strip()]
        threats = report.get("threats", []) or []
        techniques = [str(item.get("id") if isinstance(item, dict) else item).strip() for item in report.get("mitre_techniques", []) if item]
        metadata = report.get("metadata", {}) or {}

        threat_level = str(metadata.get("threat_level") or "MEDIUM").upper()
        total_alerts = metadata.get("total_alerts") or 0
        parts = [
            f"This {threat_level.lower()} severity analysis covers {total_alerts} alert{'s' if total_alerts != 1 else ''}."
        ]

        if findings:
            parts.append(findings[0] + ".")
        if len(findings) > 1:
            parts.append(findings[1] + ".")

        if threats:
            top_threat = threats[0]
            ip = top_threat.get("ip") or "the top observed indicator"
            activity = top_threat.get("activity") or "suspicious activity"
            severity = top_threat.get("severity") or threat_level
            parts.append(f"The highest-priority network threat is {ip}, associated with {activity} and rated {severity}.")

        if techniques:
            parts.append(f"Mapped MITRE ATT&CK techniques include {', '.join(techniques[:4])}.")

        if len(parts) == 1:
            return ""
        return " ".join(parts)

    @staticmethod
    def _derive_key_findings(report: Dict[str, Any]) -> List[str]:
        """Derive editor-visible findings when the markdown used an unexpected heading style."""
        findings: List[str] = []
        metadata = report.get("metadata", {}) or {}
        threats = report.get("threats", []) or []
        recommendations = report.get("recommendations", []) or []
        techniques = report.get("mitre_techniques", []) or []

        threat_level = str(metadata.get("threat_level") or "MEDIUM").upper()
        total_alerts = metadata.get("total_alerts") or 0
        findings.append(f"Overall threat level is {threat_level} across {total_alerts} alert{'s' if total_alerts != 1 else ''}.")

        if threats:
            top = threats[0]
            indicator = top.get("ip") or "the top observed indicator"
            activity = top.get("activity") or "suspicious activity"
            severity = top.get("severity") or threat_level
            findings.append(f"Top priority indicator is {indicator}, associated with {activity} and rated {severity}.")
        if techniques:
            normalized = [
                str(item.get("id") if isinstance(item, dict) else item).strip()
                for item in techniques
                if item
            ]
            if normalized:
                findings.append("Mapped MITRE ATT&CK techniques include " + ", ".join(normalized[:5]) + ".")
        if recommendations:
            findings.append(f"{len(recommendations)} immediate action{'s' if len(recommendations) != 1 else ''} were identified for analyst review.")

        return [finding for finding in findings if finding.strip()][:6]

    @staticmethod
    def _derive_recommendations(report: Dict[str, Any]) -> List[str]:
        """Recover actions from rich narrative when the heading was non-standard."""
        items: List[str] = []
        rich = str(report.get("preserved_rich_sections_markdown") or "")
        for line in rich.splitlines():
            stripped = line.strip()
            match = re.match(r"^(?:[-*]|\d+\.|P[123]\b[:.)-]?)(?:\s+|\s*)(.+)$", stripped)
            if not match:
                continue
            action = match.group(1).strip()
            if action and not action.startswith("|"):
                items.append(action)
            if len(items) >= 8:
                break
        if items:
            return ReportParser._clean_recommendations(items)
        findings = [str(item).strip() for item in report.get("key_findings") or [] if str(item).strip()]
        if findings:
            return [
                "Preserve telemetry for the affected asset and reconstruct the event sequence from the current alert.",
                "Treat retrieved CTI as historical context unless it independently overlaps current-alert indicators.",
            ]
        return []
    
    @staticmethod
    def _parse_bullet_list(lines: List[str]) -> List[str]:
        """Extract bullet points from lines"""
        items = []
        for line in lines:
            line = line.strip()
            if line.startswith('-') or line.startswith('*'):
                item = re.sub(r'^[\-\\*]\s*', '', line).strip()
                if item and not item.startswith('**'): 
                    items.append(item)
            elif re.match(r'^\d+\.', line):
                item = re.sub(r'^\d+\.\s*', '', line).strip()
                if item:
                    items.append(item)
            elif line and not line.startswith('|') and not re.fullmatch(r'-{3,}', line):
                # Some LLM outputs use short paragraphs instead of bullets.
                items.append(line)
        return items

    @staticmethod
    def _clean_recommendations(items: List[str]) -> List[str]:
        """Remove placeholder lines like Technical Summary markers from recommendations"""
        cleaned: List[str] = []
        for item in items:
            stripped = item.strip()
            normalized = stripped.lower()
            normalized_alpha = re.sub(r'[^a-z0-9]+', ' ', normalized).strip()
            if not stripped:
                continue
            if normalized.startswith("technical summary"):
                continue
            if normalized_alpha == "technical summary":
                continue
            if all(ch in "-*" for ch in stripped):
                continue
            cleaned.append(item)
        return cleaned

    @staticmethod
    def _parse_action_list(lines: List[str]) -> List[str]:
        """Actions must be explicit list items; prose such as Priority is metadata."""
        items = []
        for line in lines:
            stripped = str(line or "").strip()
            if re.match(r"^[-*]\s+\S", stripped):
                items.append(re.sub(r"^[-*]\s+", "", stripped).strip())
            elif re.match(r"^\d+[.)]\s+\S", stripped):
                items.append(re.sub(r"^\d+[.)]\s+", "", stripped).strip())
        return items
    
    @staticmethod
    def _parse_threats_table(markdown: str) -> List[Dict[str, str]]:
        """Parse threats from markdown table"""
        threats = []
        
        in_table = False
        headers = []
        
        for line in markdown.split('\n'):
            if '|' in line and ReportParser._is_threat_table_header(line):
                headers = [h.strip() for h in line.split('|')[1:-1]]
                in_table = True
                continue
            elif in_table and '|' in line:
                cells = [c.strip() for c in line.split('|')[1:-1]]
                if cells and all(re.fullmatch(r':?-{3,}:?', c.replace(" ", "")) for c in cells):
                    continue
                if len(cells) >= 3 and cells[0]:
                    row = {
                        ReportParser._normalize_table_header(header): cells[idx]
                        for idx, header in enumerate(headers)
                        if idx < len(cells)
                    }
                    ip_value = (
                        row.get("ip_address")
                        or row.get("source_ip")
                        or row.get("src_ip")
                        or row.get("ip")
                        or row.get("indicator")
                        or row.get("ioc")
                        or row.get("host")
                        or row.get("domain")
                        or (cells[0] if len(cells) > 0 else "")
                    )
                    threat = {
                        "ip": ip_value,
                        "type": row.get("type", "Not established"),
                        "country": row.get("country", ""),
                        "direction": row.get("direction", "Not established"),
                        "activity": (
                            row.get("activity")
                            or row.get("observed_activity")
                            or row.get("description")
                            or row.get("behavior")
                            or row.get("technique")
                            or ""
                        ),
                        "severity": row.get("severity", "MEDIUM"),
                        "confidence": row.get("confidence") or "Not established",
                        "count": row.get("count", "1")
                    }
                    threats.append(threat)
            elif in_table and not '|' in line:
                break
        
        return threats[:10]  

    @staticmethod
    def _normalize_table_header(header: str) -> str:
        return re.sub(r'[^a-z0-9]+', '_', header.strip().lower()).strip('_')

    @staticmethod
    def _is_threat_table_header(line: str) -> bool:
        if '|' not in line:
            return False
        headers = [
            ReportParser._normalize_table_header(header)
            for header in line.split('|')[1:-1]
        ]
        if not headers:
            return False
        joined = " ".join(headers)
        has_indicator = any(
            header in {
                "ip",
                "ip_address",
                "source_ip",
                "src_ip",
                "indicator",
                "ioc",
                "domain",
                "host"
            }
            for header in headers
        )
        has_threat_context = any(
            token in joined
            for token in ("activity", "severity", "count", "country", "direction", "confidence", "type", "description", "behavior")
        )
        return has_indicator and has_threat_context
    
    @staticmethod
    def _mitre_ids(text: str) -> List[str]:
        """Ignore explicitly withdrawn IDs in a shared source record."""
        text = re.sub(r"~~.*?~~", "", str(text or ""))
        # Source destinations are citations, not independent mapping declarations.
        text = re.sub(r"(\[[^\]\n]*\])\([^\n)]*\)", r"\1", text)
        text = re.sub(r"(?:https?|ftp)://[^\s<>]+", "", text, flags=re.IGNORECASE)
        return sorted({value.upper() for value in re.findall(r"\bT\d{4}(?:\.\d{3})?(?!\w|\.\d)", text, re.IGNORECASE)})

    @staticmethod
    def _mitre_id_pattern(technique_id: str) -> str:
        # Removing a parent must not alter a separately retained subtechnique.
        return r"\b" + re.escape(technique_id) + r"(?!\w|\.\d)"

    @staticmethod
    def _mitre_declared_ids(line: str) -> List[str]:
        return sorted({value for value, _, _ in ReportParser._mitre_declaration_spans(line)})

    @staticmethod
    def _mitre_declaration_spans(line: str) -> List[tuple[str, int, int]]:
        prefix = re.match(r"^\s*(?:(?:[-*]|\d+[.)]|#{1,6})\s+)?", line)
        offset = prefix.end() if prefix else 0
        field_prefix = re.match(r"^(?:\*\*)?technique(?:\s+id)?\s*:\s*", line[offset:], re.IGNORECASE)
        if field_prefix:
            offset += field_prefix.end()
        token = re.compile(r"(?:(?:\*\*|`|\[)?(T\d{4}(?:\.\d{3})?(?!\w|\.\d))"
                           r"(?:(?:\*\*|`)|\](?:\([^\n)]*\))?)?|"
                           r"(?:\*\*|`)?\[technique removed by analyst\](?:\([^\n)]*\))?(?:\*\*|`)?)", re.IGNORECASE)
        declared = []
        while True:
            match = token.match(line[offset:])
            if not match:
                break
            if match.group(1):
                declared.append((match.group(1).upper(), offset + match.start(1), offset + match.end(1)))
            offset += match.end()
            separator = re.match(r"\s*(?:,|/|&|\band\b)\s*", line[offset:], re.IGNORECASE)
            if not separator:
                break
            offset += separator.end()
        return declared

    @staticmethod
    def _mitre_table_cells(line: str) -> List[str]:
        return [cell.strip() for cell in re.split(r"(?<!\\)\|", line.strip().strip("|"))]

    @staticmethod
    def _is_mitre_table_header(cells: List[str]) -> bool:
        labels = {"id", "technique_id", "mitre_id", "technique_ids", "technique", "technique_name", "mitre_technique"}
        return any(ReportParser._normalize_table_header(cell) in labels for cell in cells)

    @staticmethod
    def _mitre_section_spans(lines: List[str]) -> List[tuple[int, int]]:
        """Locate every mapping, including separate current/inferred/CTI sections."""
        spans = []
        index = 0
        while index < len(lines):
            section, _ = ReportParser._detect_section_with_inline_content(lines[index])
            if section != "mitre":
                index += 1
                continue
            start = index
            heading = re.match(r"^\s*(#{1,6})\s+", lines[index])
            level = len(heading.group(1)) if heading else 2
            index += 1
            while index < len(lines):
                candidate = lines[index]
                next_section, _ = ReportParser._detect_section_with_inline_content(candidate)
                next_heading = re.match(r"^\s*(#{1,6})\s+", candidate)
                if next_section == "mitre" or "**Analysis Complete**" in candidate:
                    break
                if next_heading and len(next_heading.group(1)) <= level:
                    break
                if not next_heading and next_section:
                    break
                # Bold technique/evidence-class subheadings belong to a bold
                # MITRE container. Recognized report sections above end it.
                index += 1
            spans.append((start, index))
        return spans

    @staticmethod
    def _mitre_records(lines: List[str]) -> List[Dict[str, Any]]:
        """Keep mapping records intact so unchanged rationale/citations survive edits."""
        records = []
        headers = []
        index = 0
        while index < len(lines):
            line = lines[index]
            ids = ReportParser._mitre_ids(line)
            declared_ids = ReportParser._mitre_declared_ids(line)
            cells = ReportParser._mitre_table_cells(line) if "|" in line else []
            block_marker = re.match(r"^\s*(?:[-*]\s+|\d+[.)]\s+|#{1,6}\s+)", line) or (declared_ids and line.lstrip().startswith("**"))
            if cells and not block_marker and (line.lstrip().startswith("|") or headers or ReportParser._is_mitre_table_header(cells)):
                if not ids:
                    if ReportParser._is_mitre_table_header(cells):
                        headers = [ReportParser._normalize_table_header(cell) for cell in cells]
                    index += 1
                    continue
                id_column = next((position for position, header in enumerate(headers)
                                  if header in {"id", "technique_id", "mitre_id", "technique_ids"}), None)
                if id_column is None:
                    id_column = next((position for position, header in enumerate(headers)
                                      if header in {"technique", "technique_name", "mitre_technique"}), None)
                id_cell = (cells[id_column] if id_column is not None and id_column < len(cells)
                           else "" if headers else next((cell for cell in cells if ReportParser._mitre_ids(cell)), ""))
                ids = ReportParser._mitre_ids(id_cell)
                fields = dict(zip(headers, cells))
                records.append({"start": index, "end": index + 1, "ids": ids, "text": line,
                                "fields": fields, "headers": list(headers), "cells": cells, "id_column": id_column})
                index += 1
                continue
            headers = []
            # A mapping may be a bullet, technique subheading, or prose paragraph.
            if not ids:
                index += 1
                continue
            ids = declared_ids or ids
            start = index
            heading = re.match(r"^\s*(#{1,6})\s+", line)
            bold_heading = bool(re.match(r"^\s*\*\*[^*]+\*\*\s*:?\s*$", line))
            heading_level = len(heading.group(1)) if heading else 7 if bold_heading else None
            bullet = re.match(r"^(\s*)(?:[-*]|\d+[.)])\s+", line)
            index += 1
            while index < len(lines):
                candidate = lines[index]
                next_heading = re.match(r"^\s*(#{1,6})\s+", candidate)
                next_bold_heading = bool(re.match(r"^\s*\*\*[^*]+\*\*\s*:?\s*$", candidate))
                next_bullet = re.match(r"^(\s*)(?:[-*]|\d+[.)])\s+", candidate)
                if candidate.lstrip().startswith("|") or ("|" in candidate and ReportParser._is_mitre_table_header(
                    ReportParser._mitre_table_cells(candidate)
                )) or ReportParser._detect_section_with_inline_content(candidate)[0]:
                    break
                if next_heading and (heading_level is None or len(next_heading.group(1)) <= heading_level):
                    break
                if next_bold_heading and (ReportParser._mitre_ids(candidate) or not re.search(
                    r"supporting evidence|rationale|provenance|citation|confidence", candidate, re.IGNORECASE
                )):
                    break
                if ReportParser._mitre_declared_ids(candidate):
                    break
                if next_bullet and heading_level is None and (not bullet or len(next_bullet.group(1)) <= len(bullet.group(1))):
                    break
                if heading_level is None and re.match(r"^\s*T\d{4}(?:\.\d{3})?\b", candidate, re.IGNORECASE):
                    break
                if re.match(r"^\s*(?:Confidence|Evidence boundary|Limitations?)\s*:", candidate, re.IGNORECASE):
                    break
                if heading_level is None and not bullet and not candidate.strip():
                    break
                index += 1
            records.append({"start": start, "end": index, "ids": ids,
                            "text": "".join(lines[start:index]), "fields": {}})
        return records

    @staticmethod
    def _mitre_technique_details(markdown: str) -> Dict[str, Any]:
        lines = markdown.splitlines(keepends=True)
        spans = ReportParser._mitre_section_spans(lines)
        details: Dict[str, Any] = {}
        for start, end in spans or [(0, len(lines))]:
            section_lines = lines[start + 1:end] if spans else lines
            for record in ReportParser._mitre_records(section_lines):
                if not spans and not ReportParser._is_legacy_mitre_record(record):
                    continue
                classifications = ReportParser._mitre_record_classifications(
                    section_lines, record, lines[start] if spans else "")
                for technique_id in record["ids"]:
                    detail = details.setdefault(technique_id.upper(), {"evidence_classes": []})
                    for classification in classifications:
                        if classification not in detail["evidence_classes"]:
                            detail["evidence_classes"].append(classification)
                    for field, key in (("technique_name", "name"), ("tactic", "tactic")):
                        if record["fields"].get(field):
                            detail.setdefault(key, record["fields"][field])
        return details

    @staticmethod
    def _is_legacy_mitre_record(record: Dict[str, Any]) -> bool:
        if record.get("cells"):
            return any(header in {"id", "technique_id", "mitre_id", "technique_ids", "technique"}
                       for header in record.get("headers") or [])
        return bool(ReportParser._mitre_declared_ids(record["text"].splitlines()[0]))

    @staticmethod
    def _mitre_evidence_classes(text: str) -> List[str] | None:
        lowered = text.lower()
        classes = []
        explicitly_unknown = bool(re.search(r"unclassified|unspecified|not established|not supported|no supported|not mapped|not explicit", lowered))
        inferred = bool(re.search(r"infer(?:red|ence)", lowered)) and not re.search(r"not\s+infer(?:red|ence)", lowered)
        historical = bool(re.search(r"historical|context only|not observed", lowered))
        if not explicitly_unknown and re.search(r"explicit|observed|current alert metadata", lowered):
            affirmative = re.sub(r"\bnot\s+(?:independently\s+)?observed\b", "", lowered)
            if re.search(r"explicit|current alert metadata", affirmative) or (not inferred and not historical and re.search(r"observed", affirmative)):
                classes.append("explicit_current")
        if inferred:
            classes.append("inferred_current")
        if historical:
            classes.append("historical_only")
        if explicitly_unknown:
            classes.append("unspecified")
        return classes or None

    @staticmethod
    def _mitre_record_classifications(lines: List[str], record: Dict[str, Any], root_heading: str) -> List[str]:
        context = record["fields"].get("evidence_classification") or record["fields"].get("evidence_class")
        if context:
            return ReportParser._mitre_evidence_classes(context) or ["unspecified"]
        # Keep a heading stack: a peer 'Unclassified' section must not inherit
        # the preceding Explicit/Observed section's evidence classification.
        root_match = re.match(r"^\s*(#{1,6})\s+", root_heading)
        root_level = len(root_match.group(1)) if root_match else 2
        stack = [(root_level, root_heading)]
        for line in lines[:record["start"] + 1]:
            heading = re.match(r"^\s*(#{1,6})\s+", line)
            bold = re.match(r"^\s*\*\*[^*]+\*\*\s*:?\s*$", line)
            if heading:
                level = len(heading.group(1))
            elif bold:
                level = root_level + (2 if ReportParser._mitre_ids(line) else 3 if re.search(
                    r"supporting evidence|rationale|provenance|citation|confidence", line, re.IGNORECASE
                ) else 1)
            else:
                continue
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, line))
        if not record.get("cells"):
            first_line = record["text"].splitlines()[0]
            # An inline classification declaration can override its container;
            # incidental comparisons inside rationale cannot do so.
            declared_class = re.search(r"\bevidence class(?:ification)?\s*:\s*", first_line, re.IGNORECASE)
            if declared_class:
                own_label = re.split(r";\s*(?:rationale|supporting evidence|provenance|citation)\s*:",
                                     first_line[declared_class.end():], maxsplit=1, flags=re.IGNORECASE)[0]
                own_class = ReportParser._mitre_evidence_classes(own_label)
                if own_class is not None:
                    return own_class
        for _, heading_text in reversed(stack):
            classification = ReportParser._mitre_evidence_classes(heading_text)
            if classification is not None:
                return classification
        return ["unspecified"]

    @staticmethod
    def _parse_mitre_techniques(markdown: str) -> List[str]:
        """Read all evidence classes without treating citations elsewhere as mappings."""
        return sorted(ReportParser._mitre_technique_details(markdown))

    @staticmethod
    def _reconcile_mitre_mapping(report_data: Dict[str, Any], rich_sections: str) -> str:
        """Apply selected IDs to rich mapping records without rewriting retained evidence."""
        if "mitre_techniques" not in report_data:
            return rich_sections
        selected = {}
        for item in report_data.get("mitre_techniques", []) or []:
            value = item.get("id", "") if isinstance(item, dict) else item
            if isinstance(value, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", value.strip(), re.IGNORECASE):
                selected[value.strip().upper()] = item
        lines = rich_sections.splitlines(keepends=True)
        spans = ReportParser._mitre_section_spans(lines)
        original = set(ReportParser._mitre_technique_details(rich_sections)) if spans else set()
        modified = report_data.get("mitre_modified_techniques")
        if not isinstance(modified, list):
            modified = list(selected) if report_data.get("mitre_selection_edited") else []
        modified = {str(value).strip().upper() for value in modified}
        if spans and set(selected) == original and not modified:
            return rich_sections
        removed = original - set(selected)
        for start, end in reversed(spans):
            section_lines = lines[start:end]
            records = ReportParser._mitre_records(section_lines[1:])
            for record in records:
                record["evidence_classes"] = ReportParser._mitre_record_classifications(section_lines[1:], record, section_lines[0])
            for record in reversed(records):
                record_ids = {value.upper() for value in record["ids"]}
                first, last = record["start"] + 1, record["end"] + 1
                if record_ids.intersection(removed) and not record_ids.intersection(selected):
                    section_lines[first:last] = []
                    continue
                if record_ids.intersection(removed):
                    # A shared record cannot be dropped without losing retained evidence.
                    # Change only declarations; source evidence/citation URLs remain intact.
                    text = ReportParser._withdraw_shared_mitre_declarations(record, removed)
                    section_lines[first:last] = [text]
                # Only explicitly touched IDs may change labels. Merely enriching the
                # form with catalog names must not rewrite an untouched source mapping.
                touched = record_ids.intersection(selected).intersection(modified)
                if len(record_ids) == 1 and touched:
                    item = selected[next(iter(touched))]
                    if isinstance(item, dict):
                        replacement = ReportParser._correct_mitre_record_labels(record, item)
                        if replacement is not None:
                            section_lines[first:last] = [replacement]
            if removed:
                section_lines.insert(1, "\nAnalyst review applied: deselected mappings are omitted or explicitly marked removed.\n")
            lines[start:end] = section_lines
        reconciled = "".join(lines).rstrip()
        additions = set(selected) - original
        if additions:
            addition_lines = ["## MITRE ATT&CK — Analyst Additions (Evidence Not Established)", "",
                              "These analyst selections require supporting evidence and classification; selection alone does not establish current observation.", ""]
            for technique_id in sorted(additions):
                item = selected[technique_id]
                name = str(item.get("name") or "").strip() if isinstance(item, dict) else ""
                # Catalog labels are display text, never new Markdown structure or evidence.
                name = re.sub(r"[\r\n|]", " ", name)
                addition_lines.append(f"- **{technique_id}**{(' — ' + name) if name else ''}: Analyst added; evidence classification not established.")
            reconciled = "\n\n".join(part for part in (reconciled, "\n".join(addition_lines)) if part)
        return reconciled

    @staticmethod
    def _withdraw_shared_mitre_declarations(record: Dict[str, Any], removed: set[str]) -> str:
        text = record["text"]
        cells = list(record.get("cells") or [])
        column = record.get("id_column")
        if cells:
            if column is None:
                column = next((index for index, cell in enumerate(cells) if ReportParser._mitre_ids(cell)), None)
            if column is not None:
                cell = cells[column]
                protected = [match.span(1) for match in re.finditer(r"\]\(([^\n)]*)\)", cell)]
                protected += [match.span() for match in re.finditer(r"(?:https?|ftp)://[^\s<>]+", cell, re.IGNORECASE)]
                replacements = [match for value in removed for match in re.finditer(
                    ReportParser._mitre_id_pattern(value), cell, re.IGNORECASE)
                    if not any(first <= match.start() and match.end() <= last for first, last in protected)]
                labels = [match.span(1) for match in re.finditer(r"\[([^\]\n]*)\]\(", cell)]
                for match in sorted(replacements, key=lambda value: value.start(), reverse=True):
                    marker = ("technique removed by analyst" if any(first <= match.start() and match.end() <= last
                              for first, last in labels) else "[technique removed by analyst]")
                    cell = cell[:match.start()] + marker + cell[match.end():]
                cells[column] = cell
                return "| " + " | ".join(cells) + " |" + ("\n" if text.endswith("\n") else "")
        declarations = ReportParser._mitre_declaration_spans(text.splitlines()[0])
        if declarations:
            labels = [match.span(1) for match in re.finditer(r"\[([^\]\n]*)\]\(", text.splitlines()[0])]
            for value, first, last in reversed(declarations):
                if value in removed:
                    marker = ("technique removed by analyst" if any(start <= first and last <= end
                              for start, end in labels) else "[technique removed by analyst]")
                    text = text[:first] + marker + text[last:]
            return text
        # Ambiguous shared prose has no safely separable declaration. State the
        # retained mappings explicitly and preserve its original source as context.
        retained = sorted(set(record["ids"]) - removed)
        declaration = ", ".join(f"**{value}**" for value in retained)
        source = "\n".join("  > " + line for line in text.splitlines())
        classification = ReportParser._mitre_class_declaration(record)
        return (f"- {declaration} — Retained approved mapping. {classification}\n"
                f"\n  Supporting source context (comparisons are not additional approved mappings):\n{source}\n")

    @staticmethod
    def _mitre_class_declaration(record: Dict[str, Any]) -> str:
        labels = {"explicit_current": "Explicit alert metadata", "inferred_current": "Deterministic current-behavior inference",
                  "historical_only": "Historical context only; not observed", "unspecified": "Not established"}
        classes = record.get("evidence_classes") or ["unspecified"]
        return "Evidence classification: " + "; ".join(labels[value] for value in classes if value in labels) + "."

    @staticmethod
    def _correct_mitre_record_labels(record: Dict[str, Any], item: Dict[str, Any]) -> str | None:
        """Correct touched labels while retaining their evidence and citations."""
        cells = list(record.get("cells") or [])
        if not cells:
            name = re.sub(r"[\r\n|]", " ", str(item.get("name") or "")).strip()
            tactic = re.sub(r"[\r\n|]", " ", str(item.get("tactic") or "")).strip()
            if not name and not tactic:
                return None
            label = name + (f" ({tactic})" if tactic else "")
            text = record["text"]
            # The ordinary editor bullet format has an unambiguous label. Keep
            # any trailing rationale/citations and all subsequent evidence lines.
            match = re.match(r"(\s*(?:[-*]|\d+[.)])\s+(?:\*\*)?T\d{4}(?:\.\d{3})?(?:\*\*)?\s*[-—–]\s*)([^\n]+)", text)
            if match:
                old_label = match.group(2)
                labelled = re.fullmatch(r"([^\n()]+)\(([^\n()]+)\)(.*)", old_label)
                tactics = {"reconnaissance", "resource development", "initial access", "execution", "persistence",
                           "privilege escalation", "defense evasion", "credential access", "discovery",
                           "lateral movement", "collection", "command and control", "exfiltration", "impact", "unknown"}
                if labelled and labelled.group(2).strip().lower() in tactics:
                    tail = labelled.group(3)
                    citations = re.findall(r"\[[^\]\n]+\](?:\([^\n)]*\))?", labelled.group(1))
                    tail += "".join(" " + citation for citation in citations if citation not in label + tail)
                    return text[:match.start(2)] + label + tail + text[match.end(2):]
            # Ambiguous source prose is evidence, so qualify its old label instead
            # of guessing which words are rationale and silently discarding them.
            technique_id = record["ids"][0].upper()
            source = "\n".join("  > " + line for line in text.splitlines())
            classification = ReportParser._mitre_class_declaration(record)
            return (f"- **{technique_id}** — {label}. Analyst-corrected label. {classification}\n"
                    f"\n  Original supporting rationale (source label superseded):\n{source}\n")
        changed = False
        for index, header in enumerate(record.get("headers") or []):
            key = "name" if header in {"technique_name", "name"} else "tactic" if header == "tactic" else None
            if not key or index >= len(cells) or not isinstance(item.get(key), str) or not item[key].strip():
                continue
            value = re.sub(r"[\r\n|]", " ", item[key]).strip()
            if value == cells[index]:
                continue
            citations = re.findall(r"\[[^\]\n]+\](?:\([^\n)]*\))?", cells[index])
            cells[index] = value + "".join(" " + citation for citation in citations if citation not in value)
            changed = True
        if not changed:
            return None
        ending = "\n" if record["text"].endswith("\n") else ""
        return "| " + " | ".join(cells) + " |" + ending
        
    
    @staticmethod
    def _extract_metadata(markdown: str) -> Dict[str, Any]:
        """Extract metadata from report"""
        metadata = {
            "threat_level": "MEDIUM",
            "total_alerts": 0,
            "generated_at": datetime.now().isoformat(),
            "priority_actions": 0
        }

        metadata["threat_level"] = ReportParser._extract_threat_level(markdown)
        
        alert_patterns = [
            r'(?:total\s+alerts\s+analyzed|alerts\s+analyzed|current\s+alerts\s+analyzed|total\s+alerts)\s*:?\s*(?:\*\*)?\s*(\d+)',
            r'(\d+)\s+(?:current\s+)?alerts\s+analyzed',
            r'(\d+)\s+alerts'
        ]
        for pattern in alert_patterns:
            alert_match = re.search(pattern, markdown, re.IGNORECASE)
            if alert_match:
                metadata["total_alerts"] = int(alert_match.group(1))
                break
        
        metadata["priority_actions"] = len(ReportParser._extract_recommendations(markdown))
        
        return metadata

    @staticmethod
    def _extract_recommendations(markdown: str) -> List[str]:
        """Count only the action section, never findings or appendix bullets."""
        lines = markdown.splitlines()
        collecting = False
        body: List[str] = []
        for line in lines:
            section, inline = ReportParser._detect_section_with_inline_content(line)
            if section == "recommendations":
                collecting = True
                if inline:
                    body.append(inline)
                continue
            if collecting and section:
                break
            if collecting:
                if re.match(r"^\s*(?:#{1,6}\s+|\*\*[^*]+\*\*\s*:?)", line) and line.strip():
                    break
                body.append(line)
        return ReportParser._clean_recommendations(ReportParser._parse_action_list(body))

    @staticmethod
    def _extract_rich_sections(markdown: str) -> str:
        """Preserve analysis sections/tables/citations not represented by form fields."""
        lines = markdown.splitlines()
        heading_re = re.compile(
            r"^\s*(?:#{1,6}\s+.+|\*\*[^*]+\*\*\s*:?.*|[A-Z][A-Za-z0-9 &/—-]{2,80}:\s*)$",
            re.IGNORECASE,
        )
        rich_heading_re = re.compile(
            r"\b(?:incident assessment|attribution assessment|evidence assessment|"
            r"prioritized response plan|investigation plan|hunt hypotheses|"
            r"mitre\s+att(?:&|a)ck|technical summary|limitations|unanswered questions)\b",
            re.IGNORECASE,
        )
        appendix_re = re.compile(
            r"\b(?:report finalization|report qa findings|rag sources used|visual threat analysis)\b",
            re.IGNORECASE,
        )
        top_level_heading_re = re.compile(
            r"\b(?:executive summary|key findings?|incident assessment|attribution assessment|"
            r"top(?:\s+\d+)?\s+.*threats?|mitre\s+att(?:&|a)ck|prioritized response plan|"
            r"immediate actions?(?:\s+required)?|technical summary|analysis complete|"
            r"report finalization|report qa findings|rag sources used|visual threat analysis)\b",
            re.IGNORECASE,
        )
        blocks: List[str] = []
        index = 0
        while index < len(lines):
            line = lines[index]
            if not heading_re.match(line) or not rich_heading_re.search(line):
                index += 1
                continue
            start = index
            index += 1
            while index < len(lines):
                candidate = lines[index]
                if "**Analysis Complete**" in candidate or appendix_re.search(candidate):
                    break
                if heading_re.match(candidate) and top_level_heading_re.search(candidate):
                    break
                index += 1
            block = "\n".join(lines[start:index]).strip()
            if block and block not in blocks:
                blocks.append(block)
        return "\n\n".join(blocks)

    @staticmethod
    def _extract_threat_level(markdown: str) -> str:
        """Extract the overall report threat level from metadata and threat rows."""
        severity_rank = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }
        detected_levels: List[str] = []

        explicit_patterns = [
            r'\*\*\s*Threat\s+Level\s*:\s*\*\*\s*(CRITICAL|HIGH|MEDIUM|LOW)\b',
            r'\bThreat\s+Level\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW)\b',
            r'\bThreat\s+level\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW)\b',
            r'\bResponse\s+Priority\s*:\s*(IMMEDIATE|CRITICAL|HIGH|MEDIUM|LOW)\b'
        ]
        for pattern in explicit_patterns:
            match = re.search(pattern, markdown, re.IGNORECASE)
            if match:
                value = match.group(1).upper()
                detected_levels.append("CRITICAL" if value == "IMMEDIATE" else value)

        title_text = "\n".join(markdown.splitlines()[:12])
        if re.search(r'\bCRITICAL(?:[-\s]+SEVERITY)?\b', title_text, re.IGNORECASE):
            detected_levels.append("CRITICAL")
        if re.search(r'\bHIGH[-\s]+SEVERITY\b', title_text, re.IGNORECASE):
            detected_levels.append("HIGH")

        for threat in ReportParser._parse_threats_table(markdown):
            severity = str(threat.get("severity", "")).strip().upper()
            if severity in severity_rank:
                detected_levels.append(severity)

        if not detected_levels:
            return "MEDIUM"

        return max(detected_levels, key=lambda level: severity_rank.get(level, 0))

    @staticmethod
    def _extract_preserved_appendix(markdown: str) -> str:
        """Keep generated evidence appendices that the form editor does not expose."""
        lines = markdown.splitlines()
        appendix_start = None
        appendix_heading = re.compile(
            r'^\s*##\s+.*(?:Report Finalization|Report QA Findings|RAG Sources Used|Visual Threat Analysis)\s*$',
            re.IGNORECASE
        )

        for index, line in enumerate(lines):
            if appendix_heading.search(line):
                appendix_start = index
                break

        if appendix_start is None:
            return ""

        # Include a preceding horizontal rule if the generator inserted one.
        start = appendix_start
        previous = appendix_start - 1
        while previous >= 0 and not lines[previous].strip():
            previous -= 1
        if previous >= 0 and lines[previous].strip() == "---":
            start = previous

        appendix = "\n".join(lines[start:]).strip()
        return appendix
    
    @staticmethod
    def serialize_to_markdown(report_data: Dict[str, Any]) -> str:
        """
        Convert edited report structure back to markdown
        
        Args:
            report_data: Structured report dictionary
            
        Returns:
            Markdown formatted report
        """
        markdown = []
        
        # Header
        metadata = report_data.get("metadata", {})
        threat_level = metadata.get("threat_level", "MEDIUM")
        total_alerts = metadata.get("total_alerts", 0)
        
        markdown.append(f"#  Security Operations Center - Threat Analysis Report\n")
        markdown.append(f"**Threat Level:** {threat_level} | **Total Alerts:** {total_alerts}\n")
        markdown.append(f"**Generated:** {metadata.get('generated_at', datetime.now().isoformat())}\n\n")
        markdown.append("---\n\n")
        
        markdown.append("## Executive Summary\n\n")
        markdown.append(report_data.get("executive_summary", "No summary provided."))
        markdown.append("\n\n")
        
        findings = report_data.get("key_findings", [])
        if not findings:
            findings = ReportParser._derive_key_findings(report_data)
        markdown.append("## Key Findings\n\n")
        if findings:
            for finding in findings:
                markdown.append(f"- {finding}\n")
        else:
            markdown.append("- No key findings were extracted from the generated draft.\n")
        markdown.append("\n")
        
        threats = report_data.get("threats", [])
        if threats:
            markdown.append("## Top Priority Threats\n\n")
            markdown.append("| IP Address | Type | Country | Direction | Activity | Severity | Confidence | Count |\n")
            markdown.append("|------------|------|---------|-----------|----------|----------|------------|-------|\n")
            
            for threat in threats[:5]:  # Max 5 rows
                markdown.append(
                    f"| {threat.get('ip', '')} "
                    f"| {threat.get('type', 'Not established')} "
                    f"| {threat.get('country', '')} "
                    f"| {threat.get('direction', 'Not established')} "
                    f"| {threat.get('activity', '')} "
                    f"| {threat.get('severity', 'MEDIUM')} "
                    f"| {threat.get('confidence') or 'Not established'} "
                    f"| {threat.get('count', '1')} |\n"
                )
            markdown.append("\n")
        
        rich_sections = str(report_data.get("preserved_rich_sections_markdown") or "").strip()
        rich_sections = ReportParser._reconcile_mitre_mapping(report_data, rich_sections)

        if rich_sections:
            markdown.append(rich_sections)
            markdown.append("\n\n")
        
        recommendations = report_data.get("recommendations", [])
        if recommendations:
            markdown.append("## Immediate Actions Required\n\n")
            for i, rec in enumerate(recommendations, 1):
                markdown.append(f"{i}. {rec}\n")
            markdown.append("\n")
        
        # Footer
        markdown.append("---\n\n")
        markdown.append("**Analysis Complete**\n")
        markdown.append(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        markdown.append(f"Threat level: {threat_level}\n")
        markdown.append(f"Priority actions: {len(recommendations)} identified\n")

        preserved_appendix = (
            report_data.get("preserved_appendix_markdown")
            or report_data.get("appendix_markdown")
            or ""
        ).strip()
        if preserved_appendix:
            markdown.append("\n\n")
            markdown.append(preserved_appendix)
            if not preserved_appendix.endswith("\n"):
                markdown.append("\n")
        
        return "".join(markdown)
    
    @staticmethod
    def validate_report(report_data: Dict[str, Any]) -> tuple[bool, List[str]]:
        """
        Validate report data before approval
        
        Args:
            report_data: Structured report dictionary
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Check executive summary
        summary = report_data.get("executive_summary", "").strip()
        if not summary:
            errors.append("Executive summary is required")
        
        # Check key findings
        findings = report_data.get("key_findings", [])
        if not findings:
            errors.append("At least one key finding is required")
        
        # Check threats
        threats = report_data.get("threats", [])
        if threats:
            for i, threat in enumerate(threats):
                if not threat.get("ip"):
                    errors.append(f"Threat {i+1}: IP address is required")
                if not threat.get("severity"):
                    errors.append(f"Threat {i+1}: Severity is required")
        
        # Check recommendations
        recommendations = report_data.get("recommendations", [])
        if not recommendations:
            recommendations = ReportParser._derive_recommendations(report_data)
            if recommendations:
                report_data["recommendations"] = recommendations
        if not recommendations:
            errors.append("At least one recommendation is required")
        
        # Check metadata
        metadata = report_data.get("metadata", {})
        if not metadata.get("threat_level"):
            errors.append("Threat level must be specified")
        
        return len(errors) == 0, errors
