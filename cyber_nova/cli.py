"""Command Line Interface for Cyber-Nova."""

import sys
import argparse
import json
import time
from .orchestrator import Orchestrator
from .scenarios.presets import get_scenario_presets
from .models import Incident, IncidentSeverity, IncidentStatus


def main():
    parser = argparse.ArgumentParser(
        description="Cyber-Nova: Autonomous Multi-Agent Cybersecurity Mesh"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: list-scenarios
    subparsers.add_parser("list-scenarios", help="List available preset threat scenarios")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Run multi-agent swarm on a scenario")
    run_parser.add_argument(
        "--scenario", "-s", default="sql_injection_portal",
        help="Scenario key (default: 'sql_injection_portal')"
    )
    run_parser.add_argument(
        "--output", "-o", default=None,
        help="Optional path to write generated Markdown incident dossier"
    )

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Audit and patch a local Python file")
    audit_parser.add_argument(
        "--file", "-f", required=True,
        help="Path to Python file to audit"
    )
    audit_parser.add_argument(
        "--output", "-o", default=None,
        help="Optional path to write generated patch diff"
    )

    # Command: server
    server_parser = subparsers.add_parser("server", help="Launch the SOC Command Center Web UI")
    server_parser.add_argument(
        "--port", "-p", type=int, default=8080,
        help="HTTP/WebSocket port (default: 8080)"
    )

    args = parser.parse_args()

    if args.command == "list-scenarios":
        presets = get_scenario_presets()
        print("\nAvailable Cyber-Nova Preset Scenarios:")
        print("=" * 70)
        for key, p in presets.items():
            print(f"- {key:<30} | {p['cve']:<15} | Severity: {p['severity'].value}")
            print(f"  Name: {p['name']}")
            print(f"  Desc: {p['description'][:80]}...\n")

    elif args.command == "run":
        print(f"\n[*] Cyber-Nova initializing swarm for scenario: {args.scenario}")
        orc = Orchestrator()
        try:
            orc.load_preset(args.scenario)
        except Exception as e:
            print(f"[-] Error loading scenario: {e}")
            sys.exit(1)

        inc = orc.blackboard.incident
        print(f"[*] Incident ID: {inc.id} | Initial Severity: {inc.severity.value}")
        print(f"[*] Telemetry Lines: {len(inc.telemetry_logs)} | Target Files: {list(inc.source_files.keys())}")
        print("[*] Executing multi-agent pipeline...\n")

        start = time.perf_counter()
        results = orc.run_all()
        elapsed = round((time.perf_counter() - start) * 1000, 2)

        print("=" * 70)
        print(f"[+] Multi-Agent Execution Completed in {elapsed}ms ({len(results)} steps)")
        print(f"[+] Final Status: {inc.status.value}")
        print(f"[+] Indicators of Compromise (IOCs): {len(inc.iocs)}")
        print(f"[+] Identified Vulnerabilities: {len(inc.vulnerabilities)}")
        for v in inc.vulnerabilities:
            print(f"    - [{v.cwe_id}] {v.name} (CVSS {v.cvss_score}) in {v.file_path}:{v.line_number}")

        print(f"[+] Patches Synthesized: {len(inc.patches)}")
        if inc.verification:
            v = inc.verification
            print(f"[+] Sandbox Verification: {'PASSED' if v.success else 'FAILED'} (Exploit Blocked: {v.exploit_blocked}, Regressions: {v.regression_tests_passed})")

        print(f"[+] Defensive Rules Generated: {len(inc.defense_rules)} (WAF, YARA, Sigma)")
        if inc.audit_report:
            print(f"[+] Auditor Signature: {inc.audit_report.auditor_signature}")
            print("\nExecutive Summary:")
            print(inc.audit_report.executive_summary)

        if args.output:
            with open(args.output, "w") as f:
                f.write(orc.blackboard.export_markdown_report())
            print(f"\n[+] Incident dossier saved to: {args.output}")

    elif args.command == "audit":
        with open(args.file, "r") as f:
            code = f.read()

        custom_inc = Incident(
            id=f"INC-AUDIT-{int(time.time())}",
            title=f"Security Audit for {args.file}",
            description=f"Automated static audit and patch synthesis on {args.file}",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.NEW,
            telemetry_logs=[f"Auditing local file {args.file}"],
            source_files={args.file: code}
        )

        orc = Orchestrator()
        orc.initialize_incident(custom_inc)
        results = orc.run_all()

        inc = orc.blackboard.incident
        print(f"[+] Audit completed: Status={inc.status.value}, Vulns={len(inc.vulnerabilities)}")
        if inc.patches:
            print("\nSynthesized Patch Diff:")
            print(inc.patches[-1].diff)
            if args.output:
                with open(args.output, "w") as f:
                    f.write(inc.patches[-1].diff)
                print(f"[+] Patch diff saved to {args.output}")

    elif args.command == "server":
        from .server.app import start_server
        start_server(args.port)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
