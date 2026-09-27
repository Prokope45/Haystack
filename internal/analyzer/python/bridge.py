#!/usr/bin/env python3
import sys
import os
import ast
import json
import re

SECRET_REGEX = re.compile(r'(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|passwd|password|private[_-]?key)')

def get_call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        val = get_call_name(node.value)
        return f"{val}.{node.attr}" if val else node.attr
    return ""

def get_node_source_name(node):
    if isinstance(node, ast.Call):
        return get_call_name(node.func)
    elif isinstance(node, ast.Subscript):
        val = get_call_name(node.value)
        return f"{val}[...]" if val else "subscript"
    elif isinstance(node, ast.Attribute):
        return get_call_name(node)
    elif isinstance(node, ast.Name):
        return node.id
    return ""

def is_source_node(node):
    name = get_node_source_name(node)
    call_name = get_call_name(node.func) if isinstance(node, ast.Call) else ""
    
    # HTTP inputs
    if any(s in name for s in ["request.args", "request.form", "request.values", "request.json", "request.GET", "request.POST"]):
        return {
            "type": "http_input",
            "name": name,
            "detail": "Flask/Django HTTP request input"
        }
    
    # CLI / Env inputs
    if "sys.argv" in name:
        return {
            "type": "cli_input",
            "name": "sys.argv",
            "detail": "Command line argument"
        }
    if "os.environ" in name or call_name in ["os.getenv", "os.environ.get"]:
        return {
            "type": "environment",
            "name": call_name or name,
            "detail": "Environment variable"
        }
    if call_name == "input":
        return {
            "type": "cli_input",
            "name": "input()",
            "detail": "User console input"
        }
    
    return None

def is_sink_node(node):
    if not isinstance(node, ast.Call):
        return None, []
    
    call_name = get_call_name(node.func)
    
    # Shell sinks
    if call_name in [
        "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output",
        "os.system", "os.popen", "eval", "exec"
    ]:
        return {
            "type": "shell_execution",
            "name": call_name,
            "detail": "Shell/subprocess execution sink"
        }, node.args

    # SQL sinks
    if call_name.endswith(".execute") or call_name.endswith(".executemany"):
        if node.args:
            return {
                "type": "sql_execution",
                "name": call_name,
                "detail": "Database execution sink"
            }, [node.args[0]]

    # Filesystem sinks
    if call_name in ["open", "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"]:
        if node.args:
            return {
                "type": "filesystem_access",
                "name": call_name,
                "detail": "Filesystem operation sink"
            }, [node.args[0]]

    # Deserialization sinks
    if call_name in ["pickle.loads", "pickle.load", "_pickle.loads", "yaml.load"]:
        if node.args:
            return {
                "type": "deserialization",
                "name": call_name,
                "detail": "Unsafe deserialization sink"
            }, [node.args[0]]

    return None, []

def collect_referenced_vars(node):
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            names.add(child.id)
    return names

def analyze_scope(statements, file_path, source_lines):
    evidences = []
    # Map var_name -> {"source": ..., "flow_steps": [...], "operations": [...]}
    taints = {}

    for stmt in statements:
        # Check hardcoded secrets in assignments
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    target_name = target.id
                    if SECRET_REGEX.search(target_name) and isinstance(stmt.value, ast.Constant):
                        val = str(stmt.value.value)
                        if len(val) >= 6 and " " not in val and "%" not in val:
                            line_no = stmt.lineno
                            code = source_lines[line_no - 1].strip() if line_no <= len(source_lines) else ""
                            evidences.append({
                                "file": file_path,
                                "line": line_no,
                                "column": stmt.col_offset + 1,
                                "language": "python",
                                "source": {
                                    "type": "hardcoded_secret",
                                    "name": target_name,
                                    "line": line_no,
                                    "column": stmt.col_offset + 1,
                                    "detail": "Hardcoded secret string assigned to variable"
                                },
                                "sink": {
                                    "type": "shell_execution",
                                    "name": target_name,
                                    "line": line_no,
                                    "column": stmt.col_offset + 1,
                                    "detail": "Secret in source code"
                                },
                                "flow_steps": [f"Hardcoded secret literal assigned to {target_name}"],
                                "code": code
                            })

                    # Check if assigned value is a direct source
                    src = is_source_node(stmt.value)
                    if src:
                        src["line"] = stmt.lineno
                        src["column"] = stmt.col_offset + 1
                        taints[target_name] = {
                            "source": src,
                            "operations": [],
                            "flow_steps": [f"source: {src['name']} ({src['type']})"]
                        }
                    else:
                        # Check propagation
                        ref_vars = collect_referenced_vars(stmt.value)
                        for rv in ref_vars:
                            if rv in taints:
                                t_info = taints[rv]
                                op_type = "assignment"
                                if isinstance(stmt.value, ast.BinOp):
                                    op_type = "concatenation"
                                elif isinstance(stmt.value, ast.JoinedStr): # f-string
                                    op_type = "format_string"
                                elif isinstance(stmt.value, ast.Call):
                                    op_type = "function_call"

                                new_ops = list(t_info["operations"])
                                new_ops.append({
                                    "type": op_type,
                                    "detail": ast.unparse(stmt.value) if hasattr(ast, "unparse") else op_type,
                                    "line": stmt.lineno
                                })
                                new_steps = list(t_info["flow_steps"])
                                new_steps.append(f"{op_type} ({ast.unparse(stmt.value) if hasattr(ast, 'unparse') else target_name})")
                                taints[target_name] = {
                                    "source": t_info["source"],
                                    "operations": new_ops,
                                    "flow_steps": new_steps
                                }
                                break

        # Check call sinks
        for node in ast.walk(stmt):
            sink_info, args = is_sink_node(node)
            if sink_info:
                sink_info["line"] = node.lineno
                sink_info["column"] = node.col_offset + 1
                for arg in args:
                    # Check direct source
                    src = is_source_node(arg)
                    line_no = node.lineno
                    code = source_lines[line_no - 1].strip() if line_no <= len(source_lines) else ""
                    if src:
                        src["line"] = arg.lineno
                        src["column"] = arg.col_offset + 1
                        evidences.append({
                            "file": file_path,
                            "line": sink_info["line"],
                            "column": sink_info["column"],
                            "language": "python",
                            "source": src,
                            "sink": sink_info,
                            "operations": [],
                            "flow_steps": [
                                f"source: {src['name']} ({src['type']})",
                                f"sink: {sink_info['name']} ({sink_info['type']})"
                            ],
                            "code": code
                        })
                        break

                    # Check tainted var
                    ref_vars = collect_referenced_vars(arg)
                    for rv in ref_vars:
                        if rv in taints:
                            t_info = taints[rv]
                            steps = list(t_info["flow_steps"])
                            steps.append(f"sink: {sink_info['name']} ({sink_info['type']})")
                            evidences.append({
                                "file": file_path,
                                "line": sink_info["line"],
                                "column": sink_info["column"],
                                "language": "python",
                                "source": t_info["source"],
                                "sink": sink_info,
                                "operations": t_info["operations"],
                                "flow_steps": steps,
                                "code": code
                            })
                            break
    return evidences

def main():
    if len(sys.argv) < 2:
        file_path = "<stdin>"
        content = sys.stdin.read()
    else:
        file_path = sys.argv[1]
        if os.path.isfile(file_path):
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        else:
            content = sys.stdin.read()

    source_lines = content.splitlines()

    try:
        tree = ast.parse(content, filename=file_path)
    except Exception as e:
        sys.stderr.write(f"Syntax error parsing {file_path}: {e}\n")
        sys.exit(3)

    evidences = []
    # Module-level statements
    evidences.extend(analyze_scope(tree.body, file_path, source_lines))

    # Function definitions
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            evidences.extend(analyze_scope(node.body, file_path, source_lines))

    # Deduplicate evidences by (line, column, sink.type)
    seen = set()
    deduped = []
    for ev in evidences:
        key = (ev["line"], ev["column"], ev["sink"]["type"])
        if key not in seen:
            seen.add(key)
            deduped.append(ev)

    json.dump(deduped, sys.stdout)

if __name__ == "__main__":
    main()
