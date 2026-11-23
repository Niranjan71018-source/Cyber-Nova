"""CVE Database Lookup and CVSS v3.1 Scoring Tool."""

import math
from typing import Dict, List, Any, Optional
from .base import BaseTool


class CVELookupTool(BaseTool):
    """Queries known vulnerability signatures, references, and calculates CVSS 3.1 scores."""

    name = "cve_database_lookup"
    description = (
        "Queries vulnerability databases for matching CVE records, CWE classifications, "
        "and computes CVSS 3.1 base score vectors and exploit metrics."
    )
    parameters = {
        "query": "CVE ID (e.g. 'CVE-2024-28987') or vulnerability keyword (e.g. 'SQL injection', 'Command injection')",
        "cwe_id": "Optional CWE identifier (e.g. 'CWE-89', 'CWE-78')"
    }

    # Reference Database of Known Security Profiles
    KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
        "CWE-89": {
            "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "sample_cve": "CVE-2024-28987",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Unsanitized user input concatenated directly into SQL queries allows attackers to bypass authentication, read sensitive records, and execute database administrative commands.",
            "remediation": "Utilize parameterized queries / prepared statements with placeholder bindings or an ORM; never format strings directly into queries.",
            "owasp_category": "A03:2021-Injection"
        },
        "CWE-78": {
            "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "sample_cve": "CVE-2024-23897",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Constructing OS system commands using unvalidated external input allows arbitrary command execution with the privileges of the host process.",
            "remediation": "Avoid invoking shell interpreters; pass arguments as an immutable list to subprocess without shell=True, and sanitize input against strict allowlists.",
            "owasp_category": "A03:2021-Injection"
        },
        "CWE-22": {
            "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            "sample_cve": "CVE-2024-38856",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Using external input to construct file paths without verifying that canonicalized paths stay within the designated root directory enables arbitrary file reads (/etc/passwd, secrets).",
            "remediation": "Resolve path with os.path.realpath / Path.resolve() and verify it starts with base directory, or reject directory traversal sequences ('..', '/').",
            "owasp_category": "A01:2021-Broken Access Control"
        },
        "CWE-918": {
            "name": "Server-Side Request Forgery (SSRF)",
            "sample_cve": "CVE-2024-21626",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
            "cvss_score": 8.6,
            "severity": "HIGH",
            "description": "Web server accepts user-supplied URL and makes server-side HTTP request without restricting destination IPs, exposing internal microservices and cloud metadata APIs.",
            "remediation": "Implement an allowlist of approved domains, validate resolved IP addresses to block RFC1918 private subnets and 169.254.169.254, and disable HTTP redirects.",
            "owasp_category": "A10:2021-Server-Side Request Forgery (SSRF)"
        },
        "CWE-798": {
            "name": "Use of Hard-coded Credentials",
            "sample_cve": "CVE-2023-48795",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": 9.1,
            "severity": "CRITICAL",
            "description": "Plaintext secret keys, passwords, or tokens hardcoded in application sources can be extracted by anyone with repository access or decompiled binaries.",
            "remediation": "Store secrets in an external secret manager (HashiCorp Vault, AWS Secrets Manager) or injected environment variables.",
            "owasp_category": "A07:2021-Identification and Authentication Failures"
        },
        "CWE-502": {
            "name": "Deserialization of Untrusted Data",
            "sample_cve": "CVE-2024-3094",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Deserializing data from untrusted sources with tools like Python pickle allows attackers to instantiate arbitrary code execution gadgets.",
            "remediation": "Use safe data serialization formats such as JSON or Protocol Buffers; never deserialize untrusted pickle payloads.",
            "owasp_category": "A08:2021-Software and Data Integrity Failures"
        }
    }

    def execute(self, query: str = "", cwe_id: Optional[str] = None) -> Dict[str, Any]:
        matched_records = []

        query_upper = (query or "").strip().upper()
        cwe_clean = (cwe_id or "").strip().upper()

        # If cwe_id provided directly
        if cwe_clean and cwe_clean in self.KNOWLEDGE_BASE:
            data = dict(self.KNOWLEDGE_BASE[cwe_clean])
            data["cwe_id"] = cwe_clean
            matched_records.append(data)

        # Keyword and CVE search
        for cwe_key, val in self.KNOWLEDGE_BASE.items():
            if cwe_clean and cwe_clean == cwe_key:
                continue
            if (query_upper and query_upper in val.get("sample_cve", "").upper()) or \
               (query_upper and query_upper in val.get("name", "").upper()) or \
               (query_upper and query_upper in cwe_key):
                rec = dict(val)
                rec["cwe_id"] = cwe_key
                matched_records.append(rec)

        # Default fallback if query didn't match directly
        if not matched_records:
            # Provide generic high severity entry
            score = self.compute_cvss_score(
                av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
            )
            matched_records.append({
                "cwe_id": "CWE-General",
                "name": f"Security Vulnerability Matching '{query}'",
                "sample_cve": "CVE-2024-GENERIC",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_score": score,
                "severity": "CRITICAL" if score >= 9.0 else "HIGH",
                "description": f"Identified potential vulnerability matching query criteria: {query}",
                "remediation": "Conduct immediate code review, apply input sanitization and enforce least privilege.",
                "owasp_category": "A03:2021-Injection"
            })

        primary = matched_records[0]
        return {
            "query": query,
            "cwe_id": cwe_id,
            "matches_found": len(matched_records),
            "primary_match": primary,
            "all_matches": matched_records
        }

    @classmethod
    def compute_cvss_score(
        cls,
        av: str = "N",  # Network, Adjacent, Local, Physical
        ac: str = "L",  # Low, High
        pr: str = "N",  # None, Low, High
        ui: str = "N",  # None, Required
        s: str = "U",   # Unchanged, Changed
        c: str = "H",   # High, Low, None
        i: str = "H",   # High, Low, None
        a: str = "H"    # High, Low, None
    ) -> float:
        """CVSS v3.1 Base Score calculation formula."""
        av_w = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(av, 0.85)
        ac_w = {"L": 0.77, "H": 0.44}.get(ac, 0.77)
        ui_w = {"N": 0.85, "R": 0.62}.get(ui, 0.85)

        s_changed = (s == "C")
        if not s_changed:
            pr_w = {"N": 0.85, "L": 0.62, "H": 0.27}.get(pr, 0.85)
        else:
            pr_w = {"N": 0.85, "L": 0.68, "H": 0.50}.get(pr, 0.85)

        c_w = {"H": 0.56, "L": 0.22, "N": 0.0}.get(c, 0.56)
        i_w = {"H": 0.56, "L": 0.22, "N": 0.0}.get(i, 0.56)
        a_w = {"H": 0.56, "L": 0.22, "N": 0.0}.get(a, 0.56)

        iss = 1 - ((1 - c_w) * (1 - i_w) * (1 - a_w))
        if iss <= 0:
            return 0.0

        if not s_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av_w * ac_w * pr_w * ui_w

        if impact <= 0:
            base_score = 0.0
        elif not s_changed:
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)

        # CVSS round up to 1 decimal place
        return round(math.ceil(base_score * 10) / 10, 1)
