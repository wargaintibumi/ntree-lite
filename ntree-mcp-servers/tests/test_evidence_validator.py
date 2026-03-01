"""
Tests for NTREE Evidence Quality Validator.

Validates that the scoring formula, exploitation patterns, and RoE-aware
thresholds produce correct quality ratings for real-world pentest evidence.
"""

import pytest

from ntree_mcp.utils.evidence_validator import (
    EvidenceQuality,
    validate_evidence,
    get_evidence_quality_summary,
    enrich_finding_with_validation,
)


class TestExploitationPatterns:
    """Tests for exploitation pattern recognition."""

    def test_vsftpd_backdoor_evidence(self):
        """vsftpd backdoor: uid=0 + root prompt → GOOD+."""
        evidence = (
            "$ echo 'id' | nc -w 5 192.168.1.10 6200\n"
            "uid=0(root) gid=0(root) groups=0(root)\n"
            "$ echo 'whoami' | nc -w 5 192.168.1.10 6200\n"
            "root\n"
            "shell obtained on port 6200\n"
            "command executed successfully\n"
        )
        result = validate_evidence(evidence, finding_type="rce", severity="critical")
        assert result.quality in (EvidenceQuality.EXCELLENT, EvidenceQuality.GOOD)
        assert result.score >= 45
        assert len(result.exploitation_indicators) >= 2

    def test_mysql_root_access(self):
        """MySQL root access: login successful + privileged access → GOOD."""
        evidence = (
            "login successful to MySQL as root@localhost\n"
            "root@localhost MySQL access granted\n"
            "password: root\n"
            "session established with full privileges\n"
            "default credentials work for root/root\n"
        )
        result = validate_evidence(evidence, finding_type="default_credentials", severity="high")
        assert result.quality in (EvidenceQuality.EXCELLENT, EvidenceQuality.GOOD)
        assert result.score >= 45
        assert len(result.exploitation_indicators) >= 2

    def test_webdav_rce(self):
        """WebDAV RCE: file uploaded + uid extracted → GOOD+."""
        evidence = (
            "file uploaded successfully to /webdav/shell.php\n"
            "command executed: id\n"
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            "shell obtained via webshell\n"
        )
        result = validate_evidence(evidence, finding_type="rce", severity="critical")
        assert result.quality in (EvidenceQuality.EXCELLENT, EvidenceQuality.GOOD)
        assert result.score >= 45
        assert len(result.exploitation_indicators) >= 2

    def test_nfs_export(self):
        """NFS misconfiguration: file read + /etc/passwd access → ACCEPTABLE+."""
        evidence = (
            "$ mount -t nfs 192.168.1.10:/ /tmp/nfs_mount\n"
            "file read from NFS export\n"
            "contents of /etc/passwd retrieved\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"
        )
        result = validate_evidence(evidence, finding_type="misconfiguration", severity="high")
        assert result.quality in (EvidenceQuality.EXCELLENT, EvidenceQuality.GOOD, EvidenceQuality.ACCEPTABLE)
        assert result.score >= 25

    def test_anonymous_smb(self):
        """Anonymous SMB login successful + listing → GOOD."""
        evidence = (
            "$ smbclient -L //192.168.1.10 -N\n"
            "anonymous login successful\n"
            "\n"
            "\tSharename       Type      Comment\n"
            "\t---------       ----      -------\n"
            "\tprint$          Disk      Printer Drivers\n"
            "\ttmp             Disk      oh noes!\n"
            "\topt             Disk      \n"
            "\tIPC$            IPC       IPC Service (metasploitable server)\n"
            "\tADMIN$          IPC       IPC Service (metasploitable server)\n"
            "These are over 500 characters of SMB listing output to trigger the length bonus...\n"
            "More listing data continues here with additional share information and details.\n"
            "Even more content to ensure we pass the 500 character threshold for the length bonus.\n"
        )
        result = validate_evidence(evidence, finding_type="smb", severity="medium")
        assert result.quality in (EvidenceQuality.EXCELLENT, EvidenceQuality.GOOD)
        assert result.score >= 45

    def test_default_credentials(self):
        """Default credentials confirmed → ACCEPTABLE+."""
        evidence = (
            "Tested default credentials for Tomcat manager:\n"
            "default credentials work for tomcat/tomcat\n"
            "admin interface accessible at /manager/html\n"
        )
        result = validate_evidence(evidence, finding_type="default_credentials", severity="high")
        assert result.quality in (EvidenceQuality.EXCELLENT, EvidenceQuality.GOOD, EvidenceQuality.ACCEPTABLE)
        assert result.score >= 25


class TestRoEAwareness:
    """Tests for RoE-aware validation behavior."""

    def test_roe_no_exploitation(self):
        """When exploitation NOT authorized: no 'Actually exploit' suggestions."""
        evidence = (
            "Nmap scan report for 192.168.1.10\n"
            "PORT   STATE SERVICE VERSION\n"
            "21/tcp open  ftp     vsftpd 2.3.4\n"
            "version: 2.3.4\n"
        )
        roe_flags = {"ALLOW_EXPLOITATION": "false"}
        result = validate_evidence(evidence, finding_type="backdoor", severity="critical", roe_flags=roe_flags)

        # Should NOT suggest "Actually exploit"
        for suggestion in result.suggestions:
            assert "actually exploit" not in suggestion.lower()

        # Should NOT have "No proof of exploitation found" as an issue
        # (should say exploitation not authorized instead)
        for issue in result.issues:
            if "exploitation" in issue.lower() and "not authorized" not in issue.lower():
                assert "no proof" not in issue.lower(), f"Unexpected issue: {issue}"

    def test_roe_exploitation_allowed(self):
        """When exploitation IS authorized: standard thresholds apply."""
        evidence = (
            "uid=0(root) gid=0(root) groups=0(root)\n"
            "shell obtained on target\n"
            "command executed: id\n"
        )
        roe_flags = {"ALLOW_EXPLOITATION": "true"}
        result = validate_evidence(evidence, finding_type="rce", severity="critical", roe_flags=roe_flags)
        assert result.quality in (EvidenceQuality.EXCELLENT, EvidenceQuality.GOOD)
        assert result.score >= 45

    def test_roe_no_exploitation_relaxed_thresholds(self):
        """RoE no-exploitation: relaxed thresholds give higher quality for same evidence."""
        evidence = (
            "vsftpd 2.3.4 detected — known backdoor vulnerability CVE-2011-2523\n"
            "vulnerable to backdoor command injection\n"
            "default credentials noted in configuration\n"
        )
        # With exploitation authorized
        result_exploit = validate_evidence(evidence, severity="high",
                                           roe_flags={"ALLOW_EXPLOITATION": "true"})
        # Without exploitation authorized (relaxed thresholds)
        result_no_exploit = validate_evidence(evidence, severity="high",
                                              roe_flags={"ALLOW_EXPLOITATION": "false"})
        # Relaxed thresholds should give same or better quality
        quality_order = {
            EvidenceQuality.INSUFFICIENT: 0,
            EvidenceQuality.WEAK: 1,
            EvidenceQuality.ACCEPTABLE: 2,
            EvidenceQuality.GOOD: 3,
            EvidenceQuality.EXCELLENT: 4,
        }
        assert quality_order[result_no_exploit.quality] >= quality_order[result_exploit.quality]


class TestEdgeCases:
    """Tests for edge cases and backward compatibility."""

    def test_empty_evidence(self):
        """Empty evidence → INSUFFICIENT, score 0."""
        result = validate_evidence("")
        assert result.quality == EvidenceQuality.INSUFFICIENT
        assert result.score == 0
        assert "Evidence is empty" in result.issues

    def test_scan_only_penalty(self):
        """nmap output only gets penalized."""
        evidence = (
            "Starting Nmap 7.94 ( https://nmap.org )\n"
            "Nmap scan report for 192.168.1.10\n"
            "Host is up (0.0010s latency).\n"
            "PORT   STATE SERVICE\n"
            "22/tcp open  ssh\n"
            "80/tcp open  http\n"
        )
        result = validate_evidence(evidence, severity="medium")
        assert result.score < 20
        assert any("scan" in i.lower() for i in result.issues)

    def test_backward_compat(self):
        """No roe_flags param works same as before (backward compatible)."""
        evidence = "uid=0(root) gid=0(root) groups=0(root)"
        # Call without roe_flags (should use default exploitation_authorized=True)
        result = validate_evidence(evidence, finding_type="rce", severity="critical")
        assert result.quality in (EvidenceQuality.EXCELLENT, EvidenceQuality.GOOD, EvidenceQuality.ACCEPTABLE)
        assert result.score > 0

    def test_enrich_finding_with_roe_flags(self):
        """enrich_finding_with_validation accepts roe_flags."""
        finding = {
            "evidence": "anonymous login successful\nConnected to 192.168.1.10",
            "severity": "medium",
            "title": "Anonymous FTP",
        }
        enriched = enrich_finding_with_validation(finding, roe_flags={"ALLOW_EXPLOITATION": "false"})
        assert "evidence_validation" in enriched
        assert enriched["evidence_validation"]["quality"] in [q.value for q in EvidenceQuality]

    def test_get_evidence_quality_summary_with_roe(self):
        """get_evidence_quality_summary accepts roe_flags."""
        findings = [
            {"evidence": "uid=0(root)", "severity": "critical"},
            {"evidence": "Nmap scan report", "severity": "low"},
        ]
        summary = get_evidence_quality_summary(findings, roe_flags={"ALLOW_EXPLOITATION": "true"})
        assert summary["total_findings"] == 2
        assert "quality_distribution" in summary
