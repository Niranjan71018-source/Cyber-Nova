"""Static Code Analysis Tool using Python AST and security pattern matching."""

import ast
import re
from typing import Dict, List, Any
from .base import BaseTool


class CodeAnalyzerTool(BaseTool):
    """Performs static code auditing on provided source code snippets or files."""

    name = "code_analyzer"
    description = (
        "Analyzes source code using AST parsing and semantic pattern recognition "
        "to discover vulnerabilities (SQLi, Command Injection, Path Traversal, SSRF, Hardcoded Secrets)."
    )
    parameters = {
        "code": "Source code text to analyze",
        "file_name": "Optional filename/path for context (default: 'app.py')"
    }

    def execute(self, code: str, file_name: str = "app.py") -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        lines = code.split("\n")

        # 1. AST-based analysis
        try:
            tree = ast.parse(code)
            ast_findings = self._analyze_ast(tree, lines, file_name)
            findings.extend(ast_findings)
        except SyntaxError as syn_err:
            findings.append({
                "type": "SYNTAX_PARSE_ERROR",
                "cwe": "CWE-20",
                "severity": "LOW",
                "file": file_name,
                "line": syn_err.lineno or 1,
                "snippet": lines[syn_err.lineno - 1] if syn_err.lineno and syn_err.lineno <= len(lines) else "",
                "description": f"Syntax error during AST parse: {syn_err.msg}"
            })

        # 2. Regex / Semantic analysis for patterns that span strings or dynamic constructs
        regex_findings = self._analyze_patterns(code, lines, file_name)
        # Avoid duplicate reports if AST already found it on the exact line
        existing_lines = {(f["line"], f["cwe"]) for f in findings}
        for rf in regex_findings:
            if (rf["line"], rf["cwe"]) not in existing_lines:
                findings.append(rf)

        # 3. Overall security score calculation (100 is cleanest, decreases with findings)
        risk_deduction = 0
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev == "CRITICAL":
                risk_deduction += 40
            elif sev == "HIGH":
                risk_deduction += 25
            elif sev == "MEDIUM":
                risk_deduction += 10
            else:
                risk_deduction += 5
        health_score = max(0, 100 - risk_deduction)

        return {
            "file_name": file_name,
            "total_lines": len(lines),
            "findings_count": len(findings),
            "findings": findings,
            "code_health_score": health_score,
            "has_critical_vulnerabilities": any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings)
        }

    def _analyze_ast(self, tree: ast.AST, lines: List[str], file_name: str) -> List[Dict[str, Any]]:
        findings = []

        # Taint tracking: track variable assignments that construct dynamic interpolated strings
        dynamic_vars = set()
        for assign_node in ast.walk(tree):
            if isinstance(assign_node, ast.Assign):
                if isinstance(assign_node.value, (ast.JoinedStr, ast.BinOp)):
                    for target in assign_node.targets:
                        if isinstance(target, ast.Name):
                            dynamic_vars.add(target.id)

        for node in ast.walk(tree):
            # Check 1: Command Injection via os.system or subprocess with shell=True
            if isinstance(node, ast.Call):
                func_name = self._get_call_func_name(node.func)

                if func_name in ("os.system", "os.popen", "posix.system"):
                    line_num = getattr(node, "lineno", 1)
                    snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                    findings.append({
                        "type": "OS_COMMAND_INJECTION",
                        "cwe": "CWE-78",
                        "severity": "CRITICAL",
                        "file": file_name,
                        "line": line_num,
                        "snippet": snippet,
                        "description": (
                            f"Direct execution of shell command via '{func_name}' without parameterization. "
                            "Remote attackers can append shell metacharacters (; | &&) to achieve arbitrary code execution."
                        )
                    })

                elif func_name.startswith("subprocess."):
                    # Check if shell=True is passed or string formatting in command
                    shell_true = any(
                        isinstance(kw, ast.keyword) and kw.arg == "shell" and
                        isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in node.keywords
                    )
                    has_formatted_arg = False
                    for arg in node.args:
                        if isinstance(arg, (ast.JoinedStr, ast.BinOp)) or (isinstance(arg, ast.Name) and arg.id in dynamic_vars):
                            has_formatted_arg = True
                            break

                    if shell_true or (has_formatted_arg and func_name in ("subprocess.check_output", "subprocess.run", "subprocess.Popen")):
                        line_num = getattr(node, "lineno", 1)
                        snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                        findings.append({
                            "type": "SUBPROCESS_SHELL_INJECTION",
                            "cwe": "CWE-78",
                            "severity": "CRITICAL",
                            "file": file_name,
                            "line": line_num,
                            "snippet": snippet,
                            "description": (
                                f"Insecure subprocess invocation '{func_name}' with shell=True or dynamically formatted command. "
                                "Allows arbitrary command injection."
                            )
                        })

                # Check 2: SQL Injection via cursor.execute / db.execute with formatted strings
                elif func_name.endswith(".execute") or func_name.endswith(".executescript"):
                    is_dynamic = False
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                            is_dynamic = True
                        elif isinstance(first_arg, ast.Name) and first_arg.id in dynamic_vars:
                            is_dynamic = True

                    if is_dynamic:
                        line_num = getattr(node, "lineno", 1)
                        snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                        findings.append({
                            "type": "SQL_INJECTION",
                            "cwe": "CWE-89",
                            "severity": "CRITICAL",
                            "file": file_name,
                            "line": line_num,
                            "snippet": snippet,
                            "description": (
                                "SQL query constructed with dynamic string interpolation (f-string or % formatting). "
                                "Enables unauthenticated SQL injection to extract, modify, or drop database records."
                            )
                        })

                # Check 3: Insecure Deserialization (pickle.loads, yaml.load without safe loader)
                elif func_name in ("pickle.loads", "_pickle.loads", "pickle.load"):
                    line_num = getattr(node, "lineno", 1)
                    snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                    findings.append({
                        "type": "INSECURE_DESERIALIZATION",
                        "cwe": "CWE-502",
                        "severity": "CRITICAL",
                        "file": file_name,
                        "line": line_num,
                        "snippet": snippet,
                        "description": (
                            f"Unsafe deserialization using '{func_name}'. "
                            "Arbitrary python object instantiations allow remote code execution."
                        )
                    })

                elif func_name == "yaml.load":
                    # Check if Loader is SafeLoader
                    has_safe_loader = any(
                        isinstance(kw, ast.keyword) and kw.arg == "Loader" and "Safe" in ast.unparse(kw.value)
                        for kw in node.keywords
                    )
                    if not has_safe_loader:
                        line_num = getattr(node, "lineno", 1)
                        snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                        findings.append({
                            "type": "INSECURE_YAML_DESERIALIZATION",
                            "cwe": "CWE-502",
                            "severity": "HIGH",
                            "file": file_name,
                            "line": line_num,
                            "snippet": snippet,
                            "description": "yaml.load called without SafeLoader, leading to code execution via PyYAML tags."
                        })

                # Check 4: Unvalidated Server-Side Request Forgery (SSRF)
                elif func_name in ("requests.get", "requests.post", "urllib.request.urlopen", "httpx.get", "httpx.post"):
                    # Check if url argument is an unvalidated variable
                    if node.args and isinstance(node.args[0], (ast.Name, ast.JoinedStr, ast.BinOp)):
                        line_num = getattr(node, "lineno", 1)
                        snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                        findings.append({
                            "type": "SSRF_UNVALIDATED_REQUEST",
                            "cwe": "CWE-918",
                            "severity": "HIGH",
                            "file": file_name,
                            "line": line_num,
                            "snippet": snippet,
                            "description": (
                                f"Outbound HTTP request via '{func_name}' with dynamic target URL. "
                                "If URL is derived from user input without strict internal IP/domain allowlisting, "
                                "attackers can access internal cloud metadata (e.g. 169.254.169.254) or intranet services."
                            )
                        })

        return findings

    def _analyze_patterns(self, code: str, lines: List[str], file_name: str) -> List[Dict[str, Any]]:
        findings = []

        # Pattern: Hardcoded Secret / Token / Private Key
        secret_patterns = [
            (r'(?i)(?:api_key|secret_key|aws_access_key_id|access_token|password)\s*=\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']', "HARDCODED_SECRET", "CWE-798", "HIGH", "Hardcoded credential or API secret exposed directly in source code."),
            (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "EXPOSED_PRIVATE_KEY", "CWE-798", "CRITICAL", "Raw RSA Private Key embedded directly into source code."),
        ]

        for pattern, name, cwe, sev, desc in secret_patterns:
            for match in re.finditer(pattern, code):
                # calculate line number
                line_idx = code[:match.start()].count("\n")
                snippet = lines[line_idx].strip() if line_idx < len(lines) else ""
                findings.append({
                    "type": name,
                    "cwe": cwe,
                    "severity": sev,
                    "file": file_name,
                    "line": line_idx + 1,
                    "snippet": snippet,
                    "description": desc
                })

        # Pattern: Path Traversal / Arbitrary File Read
        path_traversal_pattern = r'(?:os\.path\.join\([^)]*(?:requested|file|user|param|path)|open\s*\(\s*(?:os\.path\.join|f["\']|[a-zA-Z_]+\s*\+\s*[a-zA-Z_]+|file_path))'
        for match in re.finditer(path_traversal_pattern, code, re.IGNORECASE):
            line_idx = code[:match.start()].count("\n")
            snippet = lines[line_idx].strip() if line_idx < len(lines) else ""
            findings.append({
                "type": "PATH_TRAVERSAL",
                "cwe": "CWE-22",
                "severity": "HIGH",
                "file": file_name,
                "line": line_idx + 1,
                "snippet": snippet,
                "description": "File open operation uses unconstrained user-controlled path or string concatenation without filepath canonicalization."
            })

        return findings

    def _get_call_func_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_call_func_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""
