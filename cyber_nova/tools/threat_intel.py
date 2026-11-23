"""Threat Intelligence and MITRE ATT&CK Enrichment Tool."""

import re
from typing import Dict, List, Any
from .base import BaseTool


class ThreatIntelTool(BaseTool):
    """Enriches threat indicators (IOCs) and maps attack vectors to MITRE ATT&CK Enterprise Matrix."""

    name = "threat_intel_enricher"
    description = (
        "Parses Indicators of Compromise (IOCs: IPs, domains, hashes, CVEs) from logs or telemetry, "
        "scores malicious reputation, and maps tactics/techniques to the MITRE ATT&CK framework."
    )
    parameters = {
        "telemetry_text": "Raw log data, incident report text, or alert traces",
        "cwe_id": "Optional CWE identifier to map directly to MITRE ATT&CK techniques"
    }

    # MITRE ATT&CK Enterprise Mapping
    ATTACK_TECHNIQUES: Dict[str, Dict[str, str]] = {
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1190/",
            "mitigation": "Web Application Firewall (WAF), input validation, rapid patch deployment."
        },
        "T1059.004": {
            "name": "Command and Scripting Interpreter: Unix Shell",
            "tactic": "Execution",
            "url": "https://attack.mitre.org/techniques/T1059/004/",
            "mitigation": "Disable shell access for web daemon, implement strict process sandboxing and SELinux/AppArmor."
        },
        "T1552": {
            "name": "Unsecured Credentials",
            "tactic": "Credential Access",
            "url": "https://attack.mitre.org/techniques/T1552/",
            "mitigation": "Secrets rotation, hardware security modules, vault storage."
        },
        "T1041": {
            "name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "url": "https://attack.mitre.org/techniques/T1041/",
            "mitigation": "Egress firewall filtering, DNS inspection, proxy authorization."
        },
        "T1083": {
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "url": "https://attack.mitre.org/techniques/T1083/",
            "mitigation": "Restrict directory permissions, disable directory indexing, implement chroot."
        },
        "T1505.003": {
            "name": "Server Software Component: Web Shell",
            "tactic": "Persistence",
            "url": "https://attack.mitre.org/techniques/T1505/003/",
            "mitigation": "File integrity monitoring (FIM), read-only web server root filesystems."
        }
    }

    def execute(self, telemetry_text: str, cwe_id: str = "") -> Dict[str, Any]:
        iocs = self._extract_iocs(telemetry_text)
        techniques = self._map_mitre_techniques(telemetry_text, cwe_id)

        # Calculate overall threat severity rating based on IOC count and MITRE tactics
        threat_level = "ELEVATED"
        if any(ioc.get("reputation_score", 0) >= 0.85 for ioc in iocs) or len(techniques) >= 2:
            threat_level = "CRITICAL"
        elif len(iocs) == 0:
            threat_level = "MODERATE"

        return {
            "threat_level": threat_level,
            "extracted_iocs_count": len(iocs),
            "iocs": iocs,
            "mitre_techniques": techniques,
            "tactics_covered": list(set(t["tactic"] for t in techniques))
        }

    def _extract_iocs(self, text: str) -> List[Dict[str, Any]]:
        iocs = []
        seen = set()

        # 1. IP Addresses (IPv4)
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for match in re.finditer(ip_pattern, text):
            ip = match.group()
            if ip in seen or ip in ("127.0.0.1", "0.0.0.0"):
                continue
            seen.add(ip)

            # Score reputation
            rep = 0.5
            context = "External IP observed in network telemetry"
            if ip.startswith("169.254."):
                rep = 0.95
                context = "AWS / Cloud Metadata Service IP (SSRF Target)"
            elif ip.startswith("198.51.100.") or ip.startswith("203.0.113."):
                rep = 0.90
                context = "Known Malicious C2 / Exfiltration IP"
            elif ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
                rep = 0.40
                context = "Internal RFC1918 Private Subnet IP"
            else:
                rep = 0.75
                context = "Suspicious public IPv4 origin"

            iocs.append({
                "type": "ipv4",
                "value": ip,
                "reputation_score": rep,
                "context": context
            })

        # 2. CVE tags
        cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
        for match in re.finditer(cve_pattern, text, re.IGNORECASE):
            cve = match.group().upper()
            if cve in seen:
                continue
            seen.add(cve)
            iocs.append({
                "type": "cve",
                "value": cve,
                "reputation_score": 0.95,
                "context": f"Public Vulnerability Identifier {cve}"
            })

        # 3. SHA-256 / MD5 hashes
        hash_pattern = r'\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{32}\b'
        for match in re.finditer(hash_pattern, text):
            h = match.group().lower()
            if h in seen:
                continue
            seen.add(h)
            iocs.append({
                "type": "hash",
                "value": h,
                "reputation_score": 0.85,
                "context": f"File artifact cryptographic hash ({'SHA-256' if len(h)==64 else 'MD5'})"
            })

        # 4. Malicious Payloads / Tools
        keywords = [
            ("sqlmap", "Automated SQL Injection tool user-agent", 0.95),
            ("/bin/bash", "Command shell execution string", 0.90),
            ("union select", "SQL Injection data exfiltration signature", 0.90),
            ("../..", "Path Traversal directory climb sequence", 0.85),
            ("curl -X POST", "Outbound exfiltration transfer command", 0.80),
        ]
        text_lower = text.lower()
        for kw, desc, rep in keywords:
            if kw in text_lower and kw not in seen:
                seen.add(kw)
                iocs.append({
                    "type": "attack_pattern",
                    "value": kw,
                    "reputation_score": rep,
                    "context": desc
                })

        return iocs

    def _map_mitre_techniques(self, text: str, cwe_id: str) -> List[Dict[str, Any]]:
        techniques = []
        text_lower = text.lower()

        # CWE to MITRE mapping
        cwe_clean = (cwe_id or "").upper()
        if cwe_clean in ("CWE-89", "CWE-78", "CWE-918", "CWE-22"):
            techniques.append(dict(self.ATTACK_TECHNIQUES["T1190"], technique_id="T1190"))
        if cwe_clean == "CWE-78" or "bash" in text_lower or "os.system" in text_lower or "cmd" in text_lower:
            techniques.append(dict(self.ATTACK_TECHNIQUES["T1059.004"], technique_id="T1059.004"))
        if cwe_clean == "CWE-798" or "credential" in text_lower or "api_key" in text_lower or "secret" in text_lower:
            techniques.append(dict(self.ATTACK_TECHNIQUES["T1552"], technique_id="T1552"))
        if "exfiltration" in text_lower or "198.51.100." in text_lower or "curl" in text_lower:
            techniques.append(dict(self.ATTACK_TECHNIQUES["T1041"], technique_id="T1041"))
        if cwe_clean == "CWE-22" or "traversal" in text_lower or "passwd" in text_lower:
            techniques.append(dict(self.ATTACK_TECHNIQUES["T1083"], technique_id="T1083"))

        # Deduplicate by technique_id
        seen_t = set()
        deduped = []
        for t in techniques:
            tid = t.get("technique_id")
            if tid not in seen_t:
                seen_t.add(tid)
                deduped.append(t)

        return deduped
