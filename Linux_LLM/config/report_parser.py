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
        
        for line in lines:
            line_stripped = line.strip()
            
            # Detect sections
            if "**Executive Summary:**" in line or line_stripped.startswith("## Executive Summary"):
                current_section = "executive_summary"
                continue
            elif "**Key Findings:**" in line or "**Key Findings**" in line:
                if current_section == "executive_summary":
                    report["executive_summary"] = "\n".join(buffer).strip()
                    buffer = []
                current_section = "key_findings"
                continue
            elif "**Top" in line and "Threats" in line:
                if current_section == "key_findings":
                    report["key_findings"] = ReportParser._parse_bullet_list(buffer)
                    buffer = []
                current_section = "threats_table"
                continue
            elif "**MITRE ATT&CK" in line or "MITRE ATT&CK" in line:
                current_section = "mitre"
                buffer = []
                continue
            elif "**Immediate Actions:**" in line or "**Recommendations:**" in line:
                current_section = "recommendations"
                buffer = []
                continue
            elif "**Analysis Complete**" in line or "---" == line_stripped:
                break
            
            # Collect content
            if current_section:
                buffer.append(line)
        
        # Parse final section
        if current_section == "executive_summary" and buffer:
            report["executive_summary"] = "\n".join(buffer).strip()
        elif current_section == "key_findings" and buffer:
            report["key_findings"] = ReportParser._parse_bullet_list(buffer)
        elif current_section == "recommendations" and buffer:
            report["recommendations"] = ReportParser._parse_bullet_list(buffer)
        
        # Extract metadata from content
        report["metadata"] = ReportParser._extract_metadata(markdown_text)
        
        # Parse threats table
        report["threats"] = ReportParser._parse_threats_table(markdown_text)
        
        # Parse MITRE techniques
        report["mitre_techniques"] = ReportParser._parse_mitre_techniques(markdown_text)
        
        return report
    
    @staticmethod
    def _parse_bullet_list(lines: List[str]) -> List[str]:
        """Extract bullet points from lines"""
        items = []
        for line in lines:
            line = line.strip()
            if line.startswith('-') or line.startswith('•') or line.startswith('*'):
                # Remove bullet and clean
                item = re.sub(r'^[\-\•\*]\s*', '', line).strip()
                if item and not item.startswith('**'):  # Skip headers
                    items.append(item)
            elif re.match(r'^\d+\.', line):
                # Numbered list
                item = re.sub(r'^\d+\.\s*', '', line).strip()
                if item:
                    items.append(item)
        return items
    
    @staticmethod
    def _parse_threats_table(markdown: str) -> List[Dict[str, str]]:
        """Parse threats from markdown table"""
        threats = []
        
        # Find table section
        table_pattern = r'\|(.+?)\|'
        in_table = False
        headers = []
        
        for line in markdown.split('\n'):
            if '|' in line and 'IP Address' in line:
                # Found table header
                headers = [h.strip() for h in line.split('|')[1:-1]]
                in_table = True
                continue
            elif in_table and '|---' in line:
                # Skip separator
                continue
            elif in_table and '|' in line:
                # Parse data row
                cells = [c.strip() for c in line.split('|')[1:-1]]
                if len(cells) >= 3 and cells[0]:  # Has IP address
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
                # End of table
                break
        
        return threats[:5]  # Limit to 5 as per report requirements
    
    @staticmethod
    def _parse_mitre_techniques(markdown: str) -> List[Dict[str, str]]:
        """Extract MITRE ATT&CK techniques"""
        techniques = []
        
        # Pattern: T1234 - Technique Name
        pattern = r'(T\d{4}(?:\.\d{3})?)\s*[-–]\s*(.+?)(?:\n|\*\*|$)'
        matches = re.finditer(pattern, markdown)
        
        for match in matches:
            tech_id = match.group(1).strip()
            tech_name = match.group(2).strip()
            
            # Try to extract tactic
            tactic = "Unknown"
            if "Initial Access" in markdown[max(0, match.start()-100):match.end()+100]:
                tactic = "Initial Access"
            elif "Execution" in markdown[max(0, match.start()-100):match.end()+100]:
                tactic = "Execution"
            elif "Persistence" in markdown[max(0, match.start()-100):match.end()+100]:
                tactic = "Persistence"
            elif "Defense Evasion" in markdown[max(0, match.start()-100):match.end()+100]:
                tactic = "Defense Evasion"
            elif "Command and Control" in markdown[max(0, match.start()-100):match.end()+100]:
                tactic = "Command and Control"
            
            techniques.append({
                "id": tech_id,
                "name": tech_name,
                "tactic": tactic
            })
        
        return techniques[:5]  # Limit to top 5
    
    @staticmethod
    def _extract_metadata(markdown: str) -> Dict[str, Any]:
        """Extract metadata from report"""
        metadata = {
            "threat_level": "MEDIUM",
            "total_alerts": 0,
            "generated_at": datetime.now().isoformat(),
            "priority_actions": 0
        }
        
        # Detect threat level
        if "CRITICAL" in markdown[:500]:
            metadata["threat_level"] = "CRITICAL"
        elif "HIGH" in markdown[:500]:
            metadata["threat_level"] = "HIGH"
        elif "LOW" in markdown[:500]:
            metadata["threat_level"] = "LOW"
        
        # Extract alert count
        alert_match = re.search(r'(\d+)\s+alerts?', markdown, re.IGNORECASE)
        if alert_match:
            metadata["total_alerts"] = int(alert_match.group(1))
        
        # Count recommendations as priority actions
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
        
        # Executive Summary
        markdown.append("## Executive Summary\n\n")
        markdown.append(report_data.get("executive_summary", "No summary provided."))
        markdown.append("\n\n")
        
        # Key Findings
        findings = report_data.get("key_findings", [])
        if findings:
            markdown.append("## Key Findings\n\n")
            for finding in findings:
                markdown.append(f"- {finding}\n")
            markdown.append("\n")
        
        # Threats Table
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
        
        # MITRE ATT&CK Techniques
        techniques = report_data.get("mitre_techniques", [])
        if techniques:
            markdown.append("## MITRE ATT&CK Mapping\n\n")
            for tech in techniques:
                markdown.append(f"- **{tech.get('id')}** - {tech.get('name')} ({tech.get('tactic', 'Unknown')})\n")
            markdown.append("\n")
        
        # Recommendations
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
        elif len(summary.split()) > 200:
            errors.append("Executive summary exceeds 200 words")
        
        # Check key findings
        findings = report_data.get("key_findings", [])
        if not findings:
            errors.append("At least one key finding is required")
        elif len(findings) > 5:
            errors.append("Maximum 5 key findings allowed")
        
        # Check threats
        threats = report_data.get("threats", [])
        if threats:
            if len(threats) > 5:
                errors.append("Maximum 5 threats allowed in table")
            
            for i, threat in enumerate(threats):
                if not threat.get("ip"):
                    errors.append(f"Threat {i+1}: IP address is required")
                if not threat.get("severity"):
                    errors.append(f"Threat {i+1}: Severity is required")
        
        # Check MITRE techniques
        techniques = report_data.get("mitre_techniques", [])
        if not techniques:
            errors.append("At least one MITRE ATT&CK technique should be identified")
        
        # Check recommendations
        recommendations = report_data.get("recommendations", [])
        if not recommendations:
            errors.append("At least one recommendation is required")
        elif len(recommendations) > 10:
            errors.append("Maximum 10 recommendations allowed")
        
        # Check metadata
        metadata = report_data.get("metadata", {})
        if not metadata.get("threat_level"):
            errors.append("Threat level must be specified")
        
        return len(errors) == 0, errors
