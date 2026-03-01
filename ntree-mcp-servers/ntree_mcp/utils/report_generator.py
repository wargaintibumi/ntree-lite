"""
NTREE Report Generator
JSON-based report generation with HTML template rendering.

Saves all pentest data to JSON, then generates HTML reports from templates.
This approach allows:
- Consistent report format across pentests
- Easy customization of HTML templates
- Reusable JSON data for other purposes (API, dashboards, etc.)
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import defaultdict
import html

from .logger import get_logger
from .evidence_validator import get_evidence_quality_summary, validate_evidence

logger = get_logger(__name__)


# Default HTML template for reports
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}} - NTREE Security Report</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --border-color: #0f3460;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }

        header {
            background: linear-gradient(135deg, var(--bg-card), #1a1a3e);
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
        }

        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .meta-item {
            background: rgba(255,255,255,0.05);
            padding: 15px;
            border-radius: 8px;
        }

        .meta-item label {
            color: var(--text-secondary);
            font-size: 0.85em;
            display: block;
        }

        .meta-item span {
            font-size: 1.1em;
            font-weight: 600;
        }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: var(--bg-card);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid var(--border-color);
            transition: transform 0.2s;
        }

        .summary-card:hover { transform: translateY(-5px); }

        .summary-card .number {
            font-size: 3em;
            font-weight: bold;
            display: block;
        }

        .summary-card.critical .number { color: var(--critical); }
        .summary-card.high .number { color: var(--high); }
        .summary-card.medium .number { color: var(--medium); }
        .summary-card.low .number { color: var(--low); }
        .summary-card.info .number { color: var(--info); }

        section {
            background: var(--bg-card);
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
        }

        section h2 {
            font-size: 1.5em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
        }

        .finding {
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid var(--info);
        }

        .finding.critical { border-left-color: var(--critical); }
        .finding.high { border-left-color: var(--high); }
        .finding.medium { border-left-color: var(--medium); }
        .finding.low { border-left-color: var(--low); }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }

        .finding h3 {
            font-size: 1.2em;
            flex: 1;
        }

        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }

        .severity-badge.critical { background: var(--critical); }
        .severity-badge.high { background: var(--high); color: #000; }
        .severity-badge.medium { background: var(--medium); color: #000; }
        .severity-badge.low { background: var(--low); }
        .severity-badge.info { background: var(--info); }

        .finding-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }

        .finding-details .detail {
            background: rgba(0,0,0,0.2);
            padding: 10px 15px;
            border-radius: 5px;
        }

        .finding-details label {
            color: var(--text-secondary);
            font-size: 0.8em;
            display: block;
            margin-bottom: 3px;
        }

        .evidence {
            background: #0d1117;
            border-radius: 5px;
            padding: 15px;
            margin-top: 15px;
            overflow-x: auto;
        }

        .evidence pre {
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85em;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .evidence-warning {
            background: rgba(253, 126, 20, 0.1);
            border: 1px solid var(--high);
            padding: 10px 15px;
            border-radius: 5px;
            margin-top: 10px;
            font-size: 0.9em;
        }

        .remediation {
            background: rgba(40, 167, 69, 0.1);
            border: 1px solid var(--low);
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }

        .remediation h4 {
            color: var(--low);
            margin-bottom: 10px;
        }

        .host-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 5px;
        }

        .host-tag {
            background: rgba(0,212,255,0.2);
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.85em;
            font-family: monospace;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background: rgba(0,0,0,0.3);
            font-weight: 600;
        }

        tr:hover { background: rgba(255,255,255,0.03); }

        .risk-matrix {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            max-width: 500px;
        }

        .risk-cell {
            padding: 15px;
            text-align: center;
            border-radius: 5px;
            font-weight: bold;
        }

        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9em;
        }

        footer a {
            color: #00d4ff;
            text-decoration: none;
        }

        .collapsible {
            cursor: pointer;
            user-select: none;
        }

        .collapsible:after {
            content: ' [+]';
            color: var(--text-secondary);
        }

        .collapsible.active:after {
            content: ' [-]';
        }

        .content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }

        .content.show {
            max-height: none;
        }

        @media print {
            body { background: white; color: black; }
            .container { max-width: 100%; }
            section { break-inside: avoid; }
            .finding { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{title}}</h1>
            <p>{{description}}</p>
            <div class="meta-info">
                <div class="meta-item">
                    <label>Assessment ID</label>
                    <span>{{assessment_id}}</span>
                </div>
                <div class="meta-item">
                    <label>Date</label>
                    <span>{{date}}</span>
                </div>
                <div class="meta-item">
                    <label>Duration</label>
                    <span>{{duration}}</span>
                </div>
                <div class="meta-item">
                    <label>Hosts Tested</label>
                    <span>{{hosts_count}}</span>
                </div>
            </div>
        </header>

        <div class="summary-cards">
            <div class="summary-card critical">
                <span class="number">{{critical_count}}</span>
                <span>Critical</span>
            </div>
            <div class="summary-card high">
                <span class="number">{{high_count}}</span>
                <span>High</span>
            </div>
            <div class="summary-card medium">
                <span class="number">{{medium_count}}</span>
                <span>Medium</span>
            </div>
            <div class="summary-card low">
                <span class="number">{{low_count}}</span>
                <span>Low</span>
            </div>
            <div class="summary-card info">
                <span class="number">{{info_count}}</span>
                <span>Info</span>
            </div>
        </div>

        <section id="executive-summary">
            <h2>Executive Summary</h2>
            {{executive_summary}}
        </section>

        <section id="scope">
            <h2>Scope</h2>
            <h4>In-Scope Targets</h4>
            <div class="host-list">
                {{scope_targets}}
            </div>
            {{scope_exclusions}}
        </section>

        <section id="findings">
            <h2>Findings ({{total_findings}})</h2>
            {{findings_html}}
        </section>

        <section id="hosts">
            <h2>Discovered Hosts</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>Open Ports</th>
                        <th>Findings</th>
                    </tr>
                </thead>
                <tbody>
                    {{hosts_table}}
                </tbody>
            </table>
        </section>

        <section id="methodology">
            <h2>Methodology</h2>
            <p>This assessment followed the PTES (Penetration Testing Execution Standard) methodology:</p>
            <ol>
                <li><strong>Reconnaissance</strong> - Network discovery and host enumeration</li>
                <li><strong>Enumeration</strong> - Service identification and version detection</li>
                <li><strong>Vulnerability Assessment</strong> - Automated and manual vulnerability scanning</li>
                <li><strong>Exploitation</strong> - Safe validation of vulnerabilities</li>
                <li><strong>Post-Exploitation</strong> - Privilege escalation and lateral movement analysis</li>
                <li><strong>Reporting</strong> - Documentation and remediation recommendations</li>
            </ol>
            <h4>Tools Used</h4>
            <div class="host-list">
                {{tools_used}}
            </div>
        </section>

        <footer>
            <p>Generated by <a href="https://github.com/anthropics/claude-code">NTREE</a> (Neura Tactical Red-Team Exploitation Engine)</p>
            <p>Report generated: {{generated_at}}</p>
        </footer>
    </div>

    <script>
        // Collapsible sections
        document.querySelectorAll('.collapsible').forEach(item => {
            item.addEventListener('click', function() {
                this.classList.toggle('active');
                const content = this.nextElementSibling;
                content.classList.toggle('show');
            });
        });
    </script>
</body>
</html>
'''


class ReportGenerator:
    """
    Generates JSON and HTML reports from assessment data.
    """

    def __init__(self, assessment_id: str, base_dir: Optional[str] = None):
        """
        Initialize report generator.

        Args:
            assessment_id: Assessment identifier
            base_dir: Base directory for assessments
        """
        self.assessment_id = assessment_id
        self.base_dir = Path(base_dir or os.path.expanduser("~/ntree/assessments"))
        self.assessment_dir = self.base_dir / assessment_id
        self.reports_dir = self.assessment_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_json_report(
        self,
        findings: List[Dict],
        hosts: List[Dict],
        services: List[Dict],
        state: Dict,
        metadata: Optional[Dict] = None
    ) -> Path:
        """
        Generate comprehensive JSON report.

        Args:
            findings: List of finding dictionaries
            hosts: List of discovered hosts
            services: List of discovered services
            state: Assessment state dictionary
            metadata: Additional metadata

        Returns:
            Path to generated JSON file
        """
        # Calculate statistics
        severity_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            severity_counts[severity] += 1

        # Extract RoE flags for context-aware evidence validation
        roe_flags = state.get("roe_flags", {})

        # Validate evidence quality (RoE-aware)
        evidence_summary = get_evidence_quality_summary(findings, roe_flags=roe_flags)

        # Extract duration from nested structure if available
        duration_seconds = state.get("duration_seconds", 0)
        if not duration_seconds and "risk_assessment" in state:
            perf = state.get("risk_assessment", {}).get("metrics", {}).get("performance", {})
            duration_seconds = perf.get("assessment_duration", {}).get("total_seconds", 0)

        # If still no duration, calculate from timestamps
        if not duration_seconds:
            started = state.get("created", state.get("created_at", ""))
            completed = state.get("completed", state.get("completed_at", ""))
            if started and completed:
                try:
                    # datetime is already imported at module level
                    start_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                    end_dt = datetime.fromisoformat(completed.replace("Z", "+00:00"))
                    duration_seconds = (end_dt - start_dt).total_seconds()
                except Exception as e:
                    logger.debug(f"Could not calculate duration from timestamps: {e}")

        # Get scope targets from scope file or discovered hosts
        scope_targets = state.get("scope_targets", [])
        if not scope_targets:
            # Try to read from scope file
            scope_file = state.get("scope_file", "")
            if scope_file and Path(scope_file).exists():
                scope_targets = self._parse_scope_file(scope_file)
            # Fallback to discovered hosts
            if not scope_targets:
                scope_targets = state.get("discovered_assets", {}).get("hosts", [])

        # Extract tools used from command metrics
        tools_used = state.get("tools_used", [])
        if not tools_used and "risk_assessment" in state:
            cmd_metrics = state.get("risk_assessment", {}).get("metrics", {}).get("performance", {}).get("command_metrics", {})
            tools_used = list(cmd_metrics.get("breakdown", {}).keys())

        # If still no tools, try to extract from performance metrics file
        if not tools_used:
            try:
                perf_file = self.assessment_dir / "performance_metrics.json"
                if perf_file.exists():
                    with open(perf_file) as f:
                        perf_data = json.load(f)
                        # Extract unique tool names from commands
                        cmds = perf_data.get("commands", {})
                        tools_set = set()
                        for cmd_str in cmds.keys():
                            # Extract first word (the tool name) from command
                            tool = cmd_str.split()[0] if cmd_str else ""
                            # Common security tools
                            if tool in ["nmap", "masscan", "nuclei", "nikto", "gobuster",
                                       "ffuf", "hydra", "crackmapexec", "enum4linux",
                                       "smbclient", "rpcclient", "ldapsearch", "dig",
                                       "airodump-ng", "aircrack-ng", "curl", "ssh", "telnet"]:
                                tools_set.add(tool)
                        tools_used = sorted(list(tools_set))
            except Exception as e:
                logger.debug(f"Could not extract tools from performance metrics: {e}")

        # Final fallback to common tools if list is still empty
        if not tools_used:
            tools_used = ["nmap"]

        # Build report structure
        report = {
            "report_version": "2.0",
            "generated_at": datetime.now().isoformat(),
            "generator": "NTREE Report Generator v2.1",

            "assessment": {
                "id": self.assessment_id,
                "title": state.get("title", self.assessment_id),
                "description": state.get("description", "Automated penetration test"),
                "started_at": state.get("created_at", state.get("created", "")),
                "completed_at": state.get("completed_at", state.get("completed", datetime.now().isoformat())),
                "duration_seconds": duration_seconds,
                "status": state.get("status", "complete"),
                "phase": state.get("phase", "COMPLETE"),
            },

            "scope": {
                "targets": scope_targets,
                "exclusions": state.get("scope_exclusions", []),
                "rules_of_engagement": state.get("roe_summary", ""),
            },

            "summary": {
                "total_findings": len(findings),
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("informational", 0) + severity_counts.get("info", 0),
                "hosts_discovered": len(hosts),
                "services_discovered": len(services),
                "evidence_quality": evidence_summary,
            },

            "risk_score": self._calculate_risk_score(findings),

            "findings": self._enrich_findings(findings, roe_flags=roe_flags),

            "hosts": hosts,

            "services": services,

            "tools_used": tools_used,

            "methodology": {
                "standard": "PTES",
                "phases_completed": state.get("phase_history", []),
            },

            "metadata": metadata or {},
        }

        # Generate executive summary
        report["executive_summary"] = self._generate_executive_summary(report)

        # Save JSON
        json_path = self.reports_dir / f"report_{self.assessment_id}.json"
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"JSON report saved: {json_path}")
        return json_path

    def generate_html_report(
        self,
        json_path: Optional[Path] = None,
        template_path: Optional[Path] = None
    ) -> Path:
        """
        Generate HTML report from JSON data.

        Args:
            json_path: Path to JSON report (auto-detect if not provided)
            template_path: Custom HTML template path

        Returns:
            Path to generated HTML file
        """
        # Load JSON data
        if json_path is None:
            json_path = self.reports_dir / f"report_{self.assessment_id}.json"

        if not json_path.exists():
            raise FileNotFoundError(f"JSON report not found: {json_path}")

        with open(json_path, 'r') as f:
            report = json.load(f)

        # Load template
        if template_path and template_path.exists():
            with open(template_path, 'r') as f:
                template = f.read()
        else:
            template = HTML_TEMPLATE

        # Render HTML
        html_content = self._render_template(template, report)

        # Save HTML
        html_path = self.reports_dir / f"report_{self.assessment_id}.html"
        with open(html_path, 'w') as f:
            f.write(html_content)

        logger.info(f"HTML report saved: {html_path}")
        return html_path

    def _parse_scope_file(self, scope_file: str) -> List[str]:
        """Parse scope file to extract target list."""
        targets = []
        try:
            with open(scope_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    # Skip EXCLUDE lines
                    if line.upper().startswith('EXCLUDE'):
                        continue
                    targets.append(line)
        except Exception as e:
            logger.warning(f"Could not parse scope file {scope_file}: {e}")
        return targets

    def _enrich_findings(self, findings: List[Dict], roe_flags: Optional[Dict[str, str]] = None) -> List[Dict]:
        """Add validation and enrichment to findings."""
        enriched = []
        for i, finding in enumerate(findings, 1):
            # Add ID if not present
            if "id" not in finding:
                finding["id"] = f"FINDING-{i:03d}"

            # Validate evidence (RoE-aware)
            evidence = finding.get("evidence", "")
            validation = validate_evidence(
                evidence,
                finding_type=finding.get("title", ""),
                severity=finding.get("severity", "medium"),
                roe_flags=roe_flags
            )

            finding["evidence_quality"] = {
                "level": validation.quality.value,
                "score": validation.score,
                "issues": validation.issues,
                "suggestions": validation.suggestions,
            }

            enriched.append(finding)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
        enriched.sort(key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))

        return enriched

    def _calculate_risk_score(self, findings: List[Dict]) -> Dict:
        """Calculate overall risk score."""
        weights = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 1, "informational": 1}

        total_score = 0
        max_possible = 0

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            cvss = finding.get("cvss_score", 0)

            # Use CVSS if available, otherwise use weight
            if cvss:
                total_score += cvss
            else:
                total_score += weights.get(severity, 1)

            max_possible += 10  # Max CVSS

        # Normalize to 0-100
        if max_possible > 0:
            normalized = min(100, (total_score / max_possible) * 100)
        else:
            normalized = 0

        # Determine risk level
        if normalized >= 70 or any(f.get("severity", "").lower() == "critical" for f in findings):
            level = "Critical"
        elif normalized >= 50:
            level = "High"
        elif normalized >= 25:
            level = "Medium"
        elif normalized > 0:
            level = "Low"
        else:
            level = "Informational"

        return {
            "score": round(normalized, 1),
            "level": level,
            "raw_score": total_score,
        }

    def _generate_executive_summary(self, report: Dict) -> str:
        """Generate executive summary text."""
        summary = report["summary"]
        risk = report["risk_score"]

        lines = []

        # Opening
        lines.append(
            f"A penetration test was conducted against the target environment, "
            f"discovering {summary['hosts_discovered']} hosts with "
            f"{summary['services_discovered']} services."
        )

        if summary["total_findings"] == 0:
            # No findings — still provide useful context
            lines.append(
                "No exploitable vulnerabilities were identified during this assessment. "
                "This may indicate a strong security posture, or that the target services "
                "were limited in exposure. Review the methodology section below for "
                "full details of testing performed."
            )
        else:
            # Risk summary
            lines.append(
                f"The overall security posture is assessed as **{risk['level']}** "
                f"with a risk score of {risk['score']}/100."
            )

            # Finding summary
            if summary["critical"] > 0:
                lines.append(
                    f"**{summary['critical']} CRITICAL** vulnerabilities were identified "
                    f"requiring immediate attention."
                )

            if summary["high"] > 0:
                lines.append(
                    f"{summary['high']} high-severity issues were found that should be "
                    f"addressed in the near term."
                )

            total_actionable = summary["critical"] + summary["high"] + summary["medium"]
            if total_actionable > 0:
                lines.append(
                    f"A total of {total_actionable} actionable findings require remediation."
                )

            # Evidence quality warning
            eq = summary.get("evidence_quality", {})
            if eq.get("needs_improvement", 0) > 0:
                lines.append(
                    f"Note: {eq['needs_improvement']} findings have evidence that may need "
                    f"additional validation."
                )

        return " ".join(lines)

    def _render_template(self, template: str, report: Dict) -> str:
        """Render HTML template with report data."""
        summary = report["summary"]
        assessment = report["assessment"]

        # Calculate duration
        duration_seconds = assessment.get("duration_seconds", 0)
        if duration_seconds:
            minutes = int(duration_seconds // 60)
            hours = duration_seconds / 3600
            if hours >= 1:
                duration = f"{minutes} minutes ({hours:.2f} hours)"
            else:
                duration = f"{minutes} minutes"
        else:
            duration = "N/A"

        # Build replacements
        replacements = {
            "{{title}}": html.escape(assessment.get("title", "Security Assessment")),
            "{{description}}": html.escape(assessment.get("description", "")),
            "{{assessment_id}}": html.escape(assessment.get("id", "")),
            "{{date}}": assessment.get("started_at", "")[:10],
            "{{duration}}": duration,
            "{{hosts_count}}": str(summary.get("hosts_discovered", 0)),
            "{{critical_count}}": str(summary.get("critical", 0)),
            "{{high_count}}": str(summary.get("high", 0)),
            "{{medium_count}}": str(summary.get("medium", 0)),
            "{{low_count}}": str(summary.get("low", 0)),
            "{{info_count}}": str(summary.get("info", 0)),
            "{{total_findings}}": str(summary.get("total_findings", 0)),
            "{{generated_at}}": report.get("generated_at", ""),
        }

        # Executive summary
        replacements["{{executive_summary}}"] = f"<p>{html.escape(report.get('executive_summary', ''))}</p>"

        # Scope targets
        scope_targets = report.get("scope", {}).get("targets", [])
        replacements["{{scope_targets}}"] = "".join(
            f'<span class="host-tag">{html.escape(str(t))}</span>' for t in scope_targets
        )

        # Scope exclusions
        exclusions = report.get("scope", {}).get("exclusions", [])
        if exclusions:
            excl_html = "<h4>Exclusions</h4><div class='host-list'>"
            excl_html += "".join(f'<span class="host-tag">{html.escape(str(e))}</span>' for e in exclusions)
            excl_html += "</div>"
            replacements["{{scope_exclusions}}"] = excl_html
        else:
            replacements["{{scope_exclusions}}"] = ""

        # Findings
        replacements["{{findings_html}}"] = self._render_findings_html(report.get("findings", []))

        # Hosts table
        replacements["{{hosts_table}}"] = self._render_hosts_table(report.get("hosts", []), report.get("findings", []))

        # Tools used
        tools = report.get("tools_used", ["nmap", "nuclei", "nikto"])
        replacements["{{tools_used}}"] = "".join(
            f'<span class="host-tag">{html.escape(str(t))}</span>' for t in tools
        )

        # Apply replacements
        result = template
        for key, value in replacements.items():
            result = result.replace(key, value)

        return result

    def _render_findings_html(self, findings: List[Dict]) -> str:
        """Render findings as HTML."""
        if not findings:
            return (
                '<div class="finding info">'
                '<div class="finding-header">'
                '<h3>No Vulnerabilities Identified</h3>'
                '<span class="severity-badge info">INFO</span>'
                '</div>'
                '<p>No exploitable vulnerabilities were discovered during this assessment. '
                'This does not guarantee the absence of vulnerabilities — it reflects the '
                'scope, depth, and duration of testing performed.</p>'
                '<p>Review the <strong>Methodology</strong> section below for details '
                'on the reconnaissance, enumeration, and testing activity conducted.</p>'
                '</div>'
            )

        html_parts = []

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            html_parts.append(f'''
            <div class="finding {severity}">
                <div class="finding-header">
                    <h3>{html.escape(finding.get("title", "Untitled Finding"))}</h3>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                </div>

                <div class="finding-details">
                    <div class="detail">
                        <label>CVSS Score</label>
                        <span>{finding.get("cvss_score", "N/A")}</span>
                    </div>
                    <div class="detail">
                        <label>Finding ID</label>
                        <span>{html.escape(finding.get("id", "N/A"))}</span>
                    </div>
                    <div class="detail">
                        <label>Evidence Quality</label>
                        <span>{finding.get("evidence_quality", {}).get("level", "N/A")}</span>
                    </div>
                </div>

                <p><strong>Description:</strong> {html.escape(finding.get("description", "No description provided."))}</p>

                <p><strong>Affected Hosts:</strong></p>
                <div class="host-list">
                    {"".join(f'<span class="host-tag">{html.escape(str(h))}</span>' for h in finding.get("affected_hosts", []))}
                </div>

                <div class="evidence">
                    <h4 class="collapsible">Evidence</h4>
                    <div class="content">
                        <pre>{html.escape(finding.get("evidence", "No evidence provided.")[:5000])}</pre>
                    </div>
                </div>

                {self._render_evidence_warning(finding)}

                <div class="remediation">
                    <h4>Remediation</h4>
                    <p>{html.escape(finding.get("remediation", "Consult vendor documentation for remediation steps."))}</p>
                </div>
            </div>
            ''')

        return "\n".join(html_parts)

    def _render_evidence_warning(self, finding: Dict) -> str:
        """Render evidence quality warning if needed."""
        eq = finding.get("evidence_quality", {})
        if eq.get("level") in ("weak", "insufficient"):
            suggestions = eq.get("suggestions", [])
            suggestion_text = suggestions[0] if suggestions else "Consider adding exploitation proof."
            return f'''
            <div class="evidence-warning">
                <strong>Evidence Quality Warning:</strong> {html.escape(suggestion_text)}
            </div>
            '''
        return ""

    def _render_hosts_table(self, hosts: List[Dict], findings: List[Dict]) -> str:
        """Render hosts table as HTML."""
        if not hosts:
            return "<tr><td colspan='5'>No hosts discovered.</td></tr>"

        # Count findings per host
        findings_per_host = defaultdict(int)
        for finding in findings:
            for host in finding.get("affected_hosts", []):
                findings_per_host[str(host)] += 1

        rows = []
        for host in hosts:
            ip = host.get("ip", host.get("address", "Unknown"))
            hostname = host.get("hostname", "-")
            os_info = host.get("os", host.get("os_match", "-"))
            ports = host.get("ports", host.get("open_ports", []))
            if isinstance(ports, list):
                ports_str = ", ".join(str(p) for p in ports[:10])
                if len(ports) > 10:
                    ports_str += f" (+{len(ports) - 10} more)"
            else:
                ports_str = str(ports)

            finding_count = findings_per_host.get(ip, 0)

            rows.append(f'''
            <tr>
                <td>{html.escape(str(ip))}</td>
                <td>{html.escape(str(hostname))}</td>
                <td>{html.escape(str(os_info))}</td>
                <td>{html.escape(ports_str)}</td>
                <td>{finding_count}</td>
            </tr>
            ''')

        return "\n".join(rows)

    # Removed in lite version: _render_scan_annex, _load_conversation_from_audit_log,
    # _render_ai_conversation, _render_credentials_section, _render_evidence_screenshots,
    # _render_roe_section, _load_credentials, _load_performance_metrics, _render_performance_section


# --- KEEP MARKER: standalone function below ---


def generate_report(
    assessment_id: str,
    findings: List[Dict],
    hosts: List[Dict],
    services: List[Dict],
    state: Dict,
    formats: List[str] = None
) -> Dict[str, Path]:
    """
    Convenience function to generate reports in multiple formats.

    Args:
        assessment_id: Assessment identifier
        findings: List of findings
        hosts: List of hosts
        services: List of services
        state: Assessment state
        formats: List of formats to generate (default: ["json", "html"])

    Returns:
        Dictionary mapping format to file path
    """
    if formats is None:
        formats = ["json", "html"]

    generator = ReportGenerator(assessment_id)
    results = {}

    if "json" in formats:
        results["json"] = generator.generate_json_report(findings, hosts, services, state)

    if "html" in formats:
        # HTML depends on JSON, so generate JSON first if needed
        if "json" not in results:
            generator.generate_json_report(findings, hosts, services, state)
        results["html"] = generator.generate_html_report()

    return results
