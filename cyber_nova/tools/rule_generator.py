"""Defensive Rule Synthesis Tool.

Generates production-grade Web Application Firewall (WAF), YARA, and Sigma rules
to provide immediate perimeter defense-in-depth while code patches are reviewed and deployed.
"""

from typing import Dict, Any, List
from .base import BaseTool


class RuleGeneratorTool(BaseTool):
    """Synthesizes WAF, YARA, and Sigma rules for threat detection and active blocking."""

    name = "defense_rule_generator"
    description = (
        "Generates production security rules including ModSecurity WAF rules, "
        "YARA file/memory scanning signatures, and Sigma SIEM detection rules."
    )
    parameters = {
        "vulnerability_type": "Vulnerability or attack class (e.g. 'SQL_INJECTION', 'OS_COMMAND_INJECTION', 'SSRF', 'PATH_TRAVERSAL')",
        "incident_id": "Incident case ID (e.g. 'INC-1001')",
        "target_endpoint": "Optional endpoint path (e.g. '/api/v1/orders')",
        "ioc_values": "Optional list of extracted IOCs or payloads to include in signatures"
    }

    def execute(
        self,
        vulnerability_type: str = "SQL_INJECTION",
        incident_id: str = "INC-1001",
        target_endpoint: str = "/api/v1/resource",
        ioc_values: List[str] = None
    ) -> Dict[str, Any]:
        ioc_values = ioc_values or []
        vuln_upper = vulnerability_type.upper()

        waf_rule = self._generate_waf(vuln_upper, incident_id, target_endpoint, ioc_values)
        yara_rule = self._generate_yara(vuln_upper, incident_id, ioc_values)
        sigma_rule = self._generate_sigma(vuln_upper, incident_id, target_endpoint, ioc_values)

        return {
            "incident_id": incident_id,
            "vulnerability_type": vulnerability_type,
            "rules": [
                {
                    "rule_type": "WAF",
                    "title": f"ModSecurity WAF Filter - {incident_id}",
                    "rule_content": waf_rule,
                    "target_system": "NGINX / Cloudflare / Apache ModSecurity"
                },
                {
                    "rule_type": "YARA",
                    "title": f"YARA Endpoint Detection - {incident_id}",
                    "rule_content": yara_rule,
                    "target_system": "Endpoint Detection & Response (EDR) / ClamAV"
                },
                {
                    "rule_type": "SIGMA",
                    "title": f"Sigma SIEM Log Detection - {incident_id}",
                    "rule_content": sigma_rule,
                    "target_system": "Splunk / Elastic SIEM / Microsoft Sentinel"
                }
            ]
        }

    def _generate_waf(self, vuln_type: str, inc_id: str, endpoint: str, iocs: List[str]) -> str:
        rule_id = 900000 + abs(hash(inc_id)) % 99999

        if "SQL" in vuln_type or "89" in vuln_type:
            pattern = r"(?i)(union\s+(?:all\s+)?select|'\s*or\s*'?\d+'?\s*=\s*'?\d+|;\s*drop\s+table|information_schema)"
            msg = "Cyber-Nova: SQL Injection Exploitation Attempt Blocked"
        elif "COMMAND" in vuln_type or "78" in vuln_type:
            pattern = r"(?i)(;\s*(?:cat|ls|id|whoami|sh|bash|curl|wget)\b|\|\s*(?:bash|sh)|\$\([^)]+\)|`[^`]+`)"
            msg = "Cyber-Nova: OS Command Injection Remote Code Execution Blocked"
        elif "SSRF" in vuln_type or "918" in vuln_type:
            pattern = r"(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|127\.0\.0\.1|localhost)"
            msg = "Cyber-Nova: Server-Side Request Forgery (SSRF) Cloud Metadata Blocked"
        elif "TRAVERSAL" in vuln_type or "22" in vuln_type:
            pattern = r"(?i)(\.\./|\.\.\\|/etc/passwd|windows/win\.ini)"
            msg = "Cyber-Nova: Directory Traversal Path Climb Blocked"
        else:
            pattern = r"(?i)(<\s*script|eval\(|base64_decode)"
            msg = "Cyber-Nova: Generic Web Exploit Vector Blocked"

        return (
            f"# Cyber-Nova ModSecurity WAF Rule\n"
            f"# Incident: {inc_id} | Defense-in-Depth Virtual Patch\n"
            f'SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx {pattern}" \\\n'
            f'    "id:{rule_id},\\\n'
            f'    phase:2,\\\n'
            f'    deny,\\\n'
            f'    status:403,\\\n'
            f'    log,\\\n'
            f'    msg:\'{msg}\',\\\n'
            f'    tag:\'cyber-nova/incident-{inc_id}\',\\\n'
            f'    tag:\'attack-{vuln_type.lower()}\',\\\n'
            f'    severity:\'CRITICAL\'"'
        )

    def _generate_yara(self, vuln_type: str, inc_id: str, iocs: List[str]) -> str:
        clean_id = inc_id.replace("-", "_")
        return (
            f"rule CyberNova_{clean_id}_Detection {{\n"
            f"    meta:\n"
            f"        description = \"Detects malicious payloads, webshells, and exploit artifacts\"\n"
            f"        author = \"Cyber-Nova Autonomous Defense Swarm\"\n"
            f"        incident = \"{inc_id}\"\n"
            f"        threat_type = \"{vuln_type}\"\n"
            f"        date = \"2026-11-23\"\n"
            f"    strings:\n"
            f"        $sql_inj1 = \"UNION SELECT\" nocase\n"
            f"        $sql_inj2 = \"information_schema\" nocase\n"
            f"        $cmd_inj1 = \"/bin/bash -i\" nocase\n"
            f"        $cmd_inj2 = \"subprocess.check_output\" nocase\n"
            f"        $c2_ioc = \"198.51.100.42\" ascii\n"
            f"    condition:\n"
            f"        2 of them\n"
            f"}}"
        )

    def _generate_sigma(self, vuln_type: str, inc_id: str, endpoint: str, iocs: List[str]) -> str:
        return (
            f"title: Cyber-Nova {inc_id} Exploitation Activity Detected\n"
            f"id: {inc_id.lower()}-sigma-rule\n"
            f"status: experimental\n"
            f"description: Detects inbound exploitation attempts matching incident {inc_id} ({vuln_type})\n"
            f"references:\n"
            f"    - internal://cyber-nova/incidents/{inc_id}\n"
            f"author: Cyber-Nova Automated Incident Response\n"
            f"date: 2026/11/23\n"
            f"logsource:\n"
            f"    category: webserver\n"
            f"    service: nginx, apache, caddy\n"
            f"detection:\n"
            f"    selection:\n"
            f"        cs-method:\n"
            f"            - 'GET'\n"
            f"            - 'POST'\n"
            f"        cs-uri-stem|contains:\n"
            f"            - '{endpoint}'\n"
            f"        c-useragent|contains:\n"
            f"            - 'sqlmap'\n"
            f"            - 'hydra'\n"
            f"            - 'nmap'\n"
            f"    condition: selection\n"
            f"falsepositives:\n"
            f"    - Authorized penetration testing scans\n"
            f"level: critical\n"
            f"tags:\n"
            f"    - attack.initial_access\n"
            f"    - attack.t1190"
        )
