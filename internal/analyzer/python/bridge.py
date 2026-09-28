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

def node_text(node):
    return ast.unparse(node) if hasattr(ast, "unparse") else ast.dump(node)

def taint_from_source(source, node):
    return {
        "source": dict(source, line=getattr(node, "lineno", 0), column=getattr(node, "col_offset", 0) + 1),
        "operations": [],
        "flow_steps": [f"source: {source['name']} ({source['type']})"],
        "crossed": False,
    }

def taint_operation(taint, kind, detail, node, crossed=False):
    result = {
        "source": taint["source"],
        "operations": list(taint["operations"]),
        "flow_steps": list(taint["flow_steps"]),
        "crossed": taint["crossed"] or crossed,
    }
    result["operations"].append({
        "type": kind,
        "detail": detail,
        "line": getattr(node, "lineno", 0),
    })
    result["flow_steps"].append(f"{kind} ({detail})")
    return result

def local_call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""

def analyze_interprocedural(tree, file_path, source_lines, max_depth):
    functions = {}
    all_functions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, []).append(node)
            all_functions.append(node)

    def resolve(call):
        if not isinstance(call, ast.Call):
            return None
        matches = functions.get(local_call_name(call.func), [])
        return matches[0] if len(matches) == 1 else None

    source_functions = set()
    callers = {}
    for fn in all_functions:
        args = list(fn.args.posonlyargs) + list(fn.args.args)
        if any(arg.arg in ("request", "req") for arg in args):
            # Include common request handlers as roots; matched source expressions
            # introduce taint with their precise source location during analysis.
            source_functions.add(fn)
        for node in ast.walk(fn):
            if is_source_node(node):
                source_functions.add(fn)
            if isinstance(node, ast.Call):
                callee = resolve(node)
                if callee is not None:
                    callers.setdefault(callee, set()).add(fn)

    roots = set(source_functions)
    queue = list(source_functions)
    while queue:
        fn = queue.pop()
        for caller in callers.get(fn, ()):
            if caller not in roots:
                roots.add(caller)
                queue.append(caller)

    evidences = []
    seen = set()
    invocation_count = [0]

    def add_evidence(sink, taint, call):
        line = getattr(call, "lineno", 0)
        column = getattr(call, "col_offset", 0) + 1
        source = taint["source"]
        key = (source.get("name"), source.get("line"), line, column, sink["type"])
        if key in seen:
            return
        seen.add(key)
        code = source_lines[line - 1].strip() if 0 < line <= len(source_lines) else node_text(call)
        steps = list(taint["flow_steps"])
        steps.append(f"sink: {sink['name']} ({sink['type']})")
        evidences.append({
            "file": file_path,
            "line": line,
            "column": column,
            "language": "python",
            "source": source,
            "sink": dict(sink, line=line, column=column),
            "operations": list(taint["operations"]),
            "flow_steps": steps,
            "code": code,
        })

    def eval_expr(node, state, depth, stack):
        if node is None or invocation_count[0] >= 500:
            return None
        source = is_source_node(node)
        if source:
            return taint_from_source(source, node)
        if isinstance(node, ast.Name):
            return state.get(node.id)
        if isinstance(node, ast.Attribute):
            return state.get(node_text(node)) or eval_expr(node.value, state, depth, stack)
        if isinstance(node, ast.Subscript):
            return eval_expr(node.value, state, depth, stack) or eval_expr(node.slice, state, depth, stack)
        if isinstance(node, ast.Call):
            sink, args = is_sink_node(node)
            if sink:
                for arg in args:
                    taint = eval_expr(arg, state, depth, stack)
                    if taint and taint["crossed"]:
                        add_evidence(sink, taint, node)
                        break
                return None

            callee = resolve(node)
            if callee is not None and depth < max_depth:
                call_inputs = {}
                params = list(callee.args.posonlyargs) + list(callee.args.args) + list(callee.args.kwonlyargs)
                actuals = list(node.args)
                if isinstance(node.func, ast.Attribute) and params and params[0].arg in ("self", "cls"):
                    actuals.insert(0, node.func.value)
                for index, param in enumerate(params):
                    actual = actuals[index] if index < len(actuals) else None
                    taint = eval_expr(actual, state, depth, stack)
                    if taint:
                        call_inputs[param.arg] = taint_operation(
                            taint, "argument_passing", f"{local_call_name(node.func)} -> {param.arg}", node, True
                        )
                        prefix = node_text(actual) + "."
                        for name, field_taint in state.items():
                            if name.startswith(prefix):
                                call_inputs[param.arg + name[len(node_text(actual)):]] = taint_operation(
                                    field_taint, "argument_passing", f"{local_call_name(node.func)} -> {param.arg}", node, True
                                )
                for keyword in node.keywords:
                    if keyword.arg:
                        taint = eval_expr(keyword.value, state, depth, stack)
                        if taint:
                            call_inputs[keyword.arg] = taint_operation(
                                taint, "argument_passing", f"{local_call_name(node.func)} -> {keyword.arg}", node, True
                            )
                result = invoke(callee, call_inputs, depth + 1, stack)
                if result:
                    return taint_operation(
                        result, "return_value", f"{callee.name} returns to {local_call_name(node.func)}", node, True
                    )
                return None

            result = None
            for arg in node.args:
                taint = eval_expr(arg, state, depth, stack)
                if taint and result is None:
                    result = taint
            if result:
                return taint_operation(result, "function_call", node_text(node), node)
            return None
        if isinstance(node, ast.BinOp):
            left = eval_expr(node.left, state, depth, stack)
            right = eval_expr(node.right, state, depth, stack)
            taint = left or right
            return taint_operation(taint, "concatenation", node_text(node), node) if taint else None
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                taint = eval_expr(value, state, depth, stack)
                if taint:
                    return taint_operation(taint, "format_string", node_text(node), node)
        if isinstance(node, ast.FormattedValue):
            return eval_expr(node.value, state, depth, stack)
        if isinstance(node, (ast.UnaryOp, ast.Await, ast.Starred)):
            return eval_expr(node.operand if hasattr(node, "operand") else node.value, state, depth, stack)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for item in node.elts:
                taint = eval_expr(item, state, depth, stack)
                if taint:
                    return taint_operation(taint, "composite_value", node_text(node), node)
        if isinstance(node, ast.Dict):
            for item in node.values:
                taint = eval_expr(item, state, depth, stack)
                if taint:
                    return taint_operation(taint, "composite_value", node_text(node), node)
        return None

    def assign_target(target, taint, state):
        if isinstance(target, ast.Name):
            state.pop(target.id, None)
            if taint:
                state[target.id] = taint
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            name = node_text(target)
            state.pop(name, None)
            if taint:
                state[name] = taint
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                assign_target(item, taint, state)

    def process_block(statements, state, depth, stack, returns):
        for stmt in statements:
            if invocation_count[0] >= 500:
                return
            if isinstance(stmt, ast.Assign):
                taint = eval_expr(stmt.value, state, depth, stack)
                for target in stmt.targets:
                    assign_target(target, taint, state)
            elif isinstance(stmt, ast.AnnAssign):
                assign_target(stmt.target, eval_expr(stmt.value, state, depth, stack), state)
            elif isinstance(stmt, ast.AugAssign):
                taint = eval_expr(stmt.value, state, depth, stack) or eval_expr(stmt.target, state, depth, stack)
                assign_target(stmt.target, taint, state)
            elif isinstance(stmt, ast.Expr):
                eval_expr(stmt.value, state, depth, stack)
            elif isinstance(stmt, ast.Return):
                taint = eval_expr(stmt.value, state, depth, stack)
                if taint:
                    returns.append(taint)
            elif isinstance(stmt, ast.If):
                eval_expr(stmt.test, state, depth, stack)
                left, right = dict(state), dict(state)
                process_block(stmt.body, left, depth, stack, returns)
                process_block(stmt.orelse, right, depth, stack, returns)
                state.update(left)
                state.update(right)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(stmt, ast.While):
                    eval_expr(stmt.test, state, depth, stack)
                else:
                    eval_expr(stmt.iter, state, depth, stack)
                process_block(stmt.body, state, depth, stack, returns)
                process_block(stmt.orelse, state, depth, stack, returns)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    taint = eval_expr(item.context_expr, state, depth, stack)
                    if item.optional_vars:
                        assign_target(item.optional_vars, taint, state)
                process_block(stmt.body, state, depth, stack, returns)
            elif isinstance(stmt, ast.Try):
                process_block(stmt.body, state, depth, stack, returns)
                for handler in stmt.handlers:
                    process_block(handler.body, state, depth, stack, returns)
                process_block(stmt.orelse, state, depth, stack, returns)
                process_block(stmt.finalbody, state, depth, stack, returns)
            elif isinstance(stmt, ast.Match):
                eval_expr(stmt.subject, state, depth, stack)
                for case in stmt.cases:
                    process_block(case.body, state, depth, stack, returns)

    def invoke(fn, inputs, depth, stack):
        if depth > max_depth or fn in stack or invocation_count[0] >= 500:
            return None
        invocation_count[0] += 1
        stack.add(fn)
        state = dict(inputs)
        returns = []
        process_block(fn.body, state, depth, stack, returns)
        stack.remove(fn)
        return returns[0] if returns else None

    for fn in all_functions:
        if fn in roots and invocation_count[0] < 500:
            invoke(fn, {}, 0, set())
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

    max_interprocedural_depth = 5
    if len(sys.argv) > 2:
        try:
            max_interprocedural_depth = max(0, int(sys.argv[2]))
        except ValueError:
            pass
    evidences.extend(analyze_interprocedural(tree, file_path, source_lines, max_interprocedural_depth))

    # Deduplicate evidences by (line, column, sink.type)
    seen = set()
    deduped = []
    for ev in evidences:
        key = (ev["line"], ev["column"], ev["sink"]["type"])
        if key not in seen:
            seen.add(key)
            deduped.append(ev)
        else:
            for index, previous in enumerate(deduped):
                previous_key = (previous["line"], previous["column"], previous["sink"]["type"])
                if previous_key == key and len(ev.get("operations", [])) > len(previous.get("operations", [])):
                    deduped[index] = ev
                    break

    json.dump(deduped, sys.stdout)

if __name__ == "__main__":
    main()
