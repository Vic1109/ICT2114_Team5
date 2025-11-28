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
            if line.startswith('-') or line.startswith('•') or line.startswith('*'):
                item = re.sub(r'^[\-\•\*]\s*', '', line).strip()
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
            if all(ch in "-–—*" for ch in stripped):
                continue
            cleaned.append(item)
        return cleaned
    
    @staticmethod
    def _parse_threats_table(markdown: str) -> List[Dict[str, str]]:
        """Parse threats from markdown table"""
        threats = []
        
        table_pattern = r'\|(.+?)\|'
        in_table = False
        headers = []
        
        for line in markdown.split('\n'):
            if '|' in line and 'IP Address' in line:
                headers = [h.strip() for h in line.split('|')[1:-1]]
                in_table = True
                continue
            elif in_table and '|---' in line:
                continue
            elif in_table and '|' in line:
                cells = [c.strip() for c in line.split('|')[1:-1]]
                if len(cells) >= 3 and cells[0]: 
                    threat = {
                        "ip": cells[0] if len(cells) > 0 else "",
                        "type": cells[1] if len(cells) > 1 else "External",
                        "country": cells[2] if len(cells) > 2 else "",
                        "direction": cells[3] if len(cells) > 3 else "Inbound",
                        "activity": cells[4] if len(cells) > 4 else "",
                        "severity": cells[5] if len(cells) > 5 else "MEDIUM",
                        "confidence": cells[6] if len(cells) > 6 else "High",
                        "count": cells[7] if len(cells) > 7 else "1"
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
        
        # Find MITRE section
        mitre_pattern = r'\*\*MITRE ATT&CK.*?:\*\*\s+(.*?)(?=\n\*\*|---|\Z)'
        mitre_match = re.search(mitre_pattern, markdown, re.DOTALL | re.IGNORECASE)
        
        if not mitre_match:
            return technique_ids
        
        mitre_text = mitre_match.group(1)
        
        # Multiple patterns to catch different formats
        patterns = [
            r'[-*]\s*\*\*([T]\d{4}(?:\.\d{3})?)[:\s-]',  # - **T1071.004: DNS**
            r'[-*]\s*([T]\d{4}(?:\.\d{3})?)\s*[-–—]',    # - T1071.004 - Name
            r'^[-*\s]*([T]\d{4}(?:\.\d{3})?)\b'          # T1071.004 at start
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
        
        print(f"✅ Extracted {len(technique_ids)} MITRE techniques: {technique_ids}")
        
        return technique_ids  # Return just the IDs!
    
    @staticmethod
    def _extract_metadata(markdown: str) -> Dict[str, Any]:
        """Extract metadata from report"""
        metadata = {
            "threat_level": "MEDIUM",
            "total_alerts": 0,
            "generated_at": datetime.now().isoformat(),
            "priority_actions": 0
        }
        
        if "CRITICAL" in markdown[:500]:
            metadata["threat_level"] = "CRITICAL"
        elif "HIGH" in markdown[:500]:
            metadata["threat_level"] = "HIGH"
        elif "LOW" in markdown[:500]:
            metadata["threat_level"] = "LOW"
        
        alert_match = re.search(r'(\d+)\s+alerts?', markdown, re.IGNORECASE)
        if alert_match:
            metadata["total_alerts"] = int(alert_match.group(1))
        
        recommendations = len(re.findall(r'^[-\*]\s+', markdown, re.MULTILINE))
        metadata["priority_actions"] = min(recommendations, 10)
        
        return metadata
    
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
        
        markdown.append(f"# 🛡️ Security Operations Center - Threat Analysis Report\n")
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
