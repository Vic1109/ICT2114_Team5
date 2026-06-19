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
        skip_header = True 
        
        for line in lines:
            line_stripped = line.strip()
            
            if skip_header:
                if "---" == line_stripped:
                    skip_header = False
                continue
            
            if "**Analysis Complete**" in line:
                break
            
            if "**Executive Summary:**" in line or line_stripped.startswith("## Executive Summary"):
                if current_section == "key_findings" and buffer:
                    report["key_findings"] = ReportParser._parse_bullet_list(buffer)
                current_section = "executive_summary"
                buffer = []
                continue
                
            elif "**Key Findings:**" in line or "**Key Findings**" in line:
                if current_section == "executive_summary" and buffer:
                    report["executive_summary"] = "\n".join(buffer).strip()
                current_section = "key_findings"
                buffer = []
                continue
                
            elif "**Top" in line and "Threats" in line:
                if current_section == "key_findings" and buffer:
                    report["key_findings"] = ReportParser._parse_bullet_list(buffer)
                current_section = "threats_table"
                buffer = []
                continue
                
            elif "**MITRE ATT&CK" in line or "MITRE ATT&CK" in line:
                current_section = "mitre"
                buffer = []
                continue
                
            elif "**Immediate Actions:**" in line or "**Recommendations:**" in line:
                current_section = "recommendations"
                buffer = []
                continue
            
            if current_section and line_stripped:
                buffer.append(line)
        
        if current_section == "executive_summary" and buffer:
            report["executive_summary"] = "\n".join(buffer).strip()
        elif current_section == "key_findings" and buffer:
            report["key_findings"] = ReportParser._parse_bullet_list(buffer)
        elif current_section == "recommendations" and buffer:
            raw_recs = ReportParser._parse_bullet_list(buffer)
            report["recommendations"] = ReportParser._clean_recommendations(raw_recs)
        
        report["metadata"] = ReportParser._extract_metadata(markdown_text)
        report["threats"] = ReportParser._parse_threats_table(markdown_text)
        report["mitre_techniques"] = ReportParser._parse_mitre_techniques(markdown_text)
        
        return report
    
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
    def _parse_threats_table(markdown: str) -> List[Dict[str, str]]:
        """Parse threats from markdown table"""
        threats = []
        
        in_table = False
        headers = []
        
        for line in markdown.split('\n'):
            if '|' in line and 'IP Address' in line:
                headers = [h.strip() for h in line.split('|')[1:-1]]
                in_table = True
                continue
            elif in_table and '|' in line:
                cells = [c.strip() for c in line.split('|')[1:-1]]
                if cells and all(re.fullmatch(r':?-{3,}:?', c.replace(" ", "")) for c in cells):
                    continue
                if len(cells) >= 3 and cells[0]:
                    row = {
                        header.lower().replace(" ", "_").replace("/", "_"): cells[idx]
                        for idx, header in enumerate(headers)
                        if idx < len(cells)
                    }
                    threat = {
                        "ip": row.get("ip_address", cells[0] if len(cells) > 0 else ""),
                        "type": row.get("type", "External"),
                        "country": row.get("country", ""),
                        "direction": row.get("direction", "Inbound"),
                        "activity": row.get("activity", ""),
                        "severity": row.get("severity", "MEDIUM"),
                        "confidence": row.get("confidence", "High"),
                        "count": row.get("count", "1")
                    }
                    threats.append(threat)
            elif in_table and not '|' in line:
                break
        
        return threats[:10]  
    
    @staticmethod
    def _parse_mitre_techniques(markdown: str) -> List[str]:  # Return List[str], not List[Dict]
        """Extract MITRE ATT&CK technique IDs"""
        technique_ids = []
        seen_ids = set()
        
        # Find MITRE section in either bold-heading or markdown-heading form.
        mitre_pattern = r'(\*\*MITRE ATT&CK[^\n]*:\*\*|#{1,3}\s*MITRE ATT&CK[^\n]*)\s*(.*?)(?=\n(\*\*|#{1,3}\s|---)|\Z)'
        mitre_match = re.search(mitre_pattern, markdown, re.DOTALL | re.IGNORECASE)
        mitre_text = mitre_match.group(2) if mitre_match else markdown
        
        # Multiple patterns to catch different formats
        patterns = [
            r'[-*]\s*\*\*([T]\d{4}(?:\.\d{3})?)[:\s-]',  # - **T1071.004: DNS**
            r'[-*]\s*([T]\d{4}(?:\.\d{3})?)\s*[-]',    # - T1071.004 - Name
            r'^[-*\s]*([T]\d{4}(?:\.\d{3})?)\b',         # T1071.004 at start
            r'\|\s*(?:[^|\n]*\|\s*)?([T]\d{4}(?:\.\d{3})?)\s*\|'  # MITRE table cell
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, mitre_text, re.MULTILINE)
            for tech_id in matches:
                tech_id = tech_id.strip()
                if tech_id and tech_id not in seen_ids:
                    seen_ids.add(tech_id)
                    technique_ids.append(tech_id)
        
        # Sort by ID
        technique_ids.sort()
        return technique_ids
        
    
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
        
        recommendations = len(re.findall(r'^[-\*]\s+', markdown, re.MULTILINE))
        metadata["priority_actions"] = min(recommendations, 10)
        
        return metadata

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
            r'^\s*##\s+.*(?:RAG Sources Used|Visual Threat Analysis)\s*$',
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
        if findings:
            markdown.append("## Key Findings\n\n")
            for finding in findings:
                markdown.append(f"- {finding}\n")
            markdown.append("\n")
        
        threats = report_data.get("threats", [])
        if threats:
            markdown.append("## Top Priority Threats\n\n")
            markdown.append("| IP Address | Type | Country | Direction | Activity | Severity | Confidence | Count |\n")
            markdown.append("|------------|------|---------|-----------|----------|----------|------------|-------|\n")
            
            for threat in threats[:5]:  # Max 5 rows
                markdown.append(
                    f"| {threat.get('ip', '')} "
                    f"| {threat.get('type', 'External')} "
                    f"| {threat.get('country', '')} "
                    f"| {threat.get('direction', 'Inbound')} "
                    f"| {threat.get('activity', '')} "
                    f"| {threat.get('severity', 'MEDIUM')} "
                    f"| {threat.get('confidence', 'High')} "
                    f"| {threat.get('count', '1')} |\n"
                )
            markdown.append("\n")
        
        techniques = report_data.get("mitre_techniques", [])
        if techniques:
            markdown.append("## MITRE ATT&CK Mapping\n\n")
            for tech in techniques:
                # Handle both dict objects and plain strings for backward compatibility
                if isinstance(tech, dict):
                    tech_id = tech.get('id', 'Unknown')
                    tech_name = tech.get('name', 'Unknown')
                    tech_tactic = tech.get('tactic', 'Unknown')
                else:
                    # Fallback if somehow a string is passed
                    tech_id = tech
                    tech_name = 'Unknown'
                    tech_tactic = 'Unknown'
                
                markdown.append(f"- **{tech_id}** - {tech_name} ({tech_tactic})\n")
            markdown.append("\n")
        
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
        markdown.append(f"Priority actions: {metadata.get('priority_actions', len(recommendations))} identified\n")

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
            errors.append("At least one recommendation is required")
        
        # Check metadata
        metadata = report_data.get("metadata", {})
        if not metadata.get("threat_level"):
            errors.append("Threat level must be specified")
        
        return len(errors) == 0, errors
