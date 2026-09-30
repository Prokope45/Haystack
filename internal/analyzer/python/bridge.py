#!/usr/bin/env python3
import sys
import os
import ast
import json
import re

SECRET_REGEX = re.compile(r'(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|passwd|password|private[_-]?key)')

def get_call_name(node):
    """Return the dotted callable name represented by an AST node."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        val = get_call_name(node.value)
        return f"{val}.{node.attr}" if val else node.attr
    return ""

def get_node_source_name(node):
    """Return the display name used when an AST node is recognized as a source."""
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
    """Classify recognized HTTP, CLI, and environment expressions as input sources."""
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
    """Classify a call as a sink and return only the arguments relevant to that sink."""
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
    """Collect loaded variable names referenced by an expression."""
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            names.add(child.id)
    return names

def hardcoded_secret_evidence(stmt, target_name, file_path, source_lines):
    """Build evidence for a qualifying secret-like name assigned a string constant."""
    if not SECRET_REGEX.search(target_name) or not isinstance(stmt.value, ast.Constant):
        return None
    value = str(stmt.value.value)
    if len(value) < 6 or " " in value or "%" in value:
        return None

    line_no = stmt.lineno
    column = stmt.col_offset + 1
    code = source_lines[line_no - 1].strip() if line_no <= len(source_lines) else ""
    return {
        "file": file_path,
        "line": line_no,
        "column": column,
        "language": "python",
        "source": {
            "type": "hardcoded_secret",
            "name": target_name,
            "line": line_no,
            "column": column,
            "detail": "Hardcoded secret string assigned to variable"
        },
        "sink": {
            "type": "shell_execution",
            "name": target_name,
            "line": line_no,
            "column": column,
            "detail": "Secret in source code"
        },
        "flow_steps": [f"Hardcoded secret literal assigned to {target_name}"],
        "code": code
    }

def analyze_assignment(stmt, target_name, taints):
    """Update one scope's taint map from a direct source or a propagated assignment."""
    source = is_source_node(stmt.value)
    if source:
        source["line"] = stmt.lineno
        source["column"] = stmt.col_offset + 1
        taints[target_name] = {
            "source": source,
            "operations": [],
            "flow_steps": [f"source: {source['name']} ({source['type']})"]
        }
        return

    ref_vars = collect_referenced_vars(stmt.value)
    for ref_var in ref_vars:
        if ref_var not in taints:
            continue
        taint = taints[ref_var]
        operation_type = "assignment"
        if isinstance(stmt.value, ast.BinOp):
            operation_type = "concatenation"
        elif isinstance(stmt.value, ast.JoinedStr): # f-string
            operation_type = "format_string"
        elif isinstance(stmt.value, ast.Call):
            operation_type = "function_call"

        operations = list(taint["operations"])
        operations.append({
            "type": operation_type,
            "detail": ast.unparse(stmt.value) if hasattr(ast, "unparse") else operation_type,
            "line": stmt.lineno
        })
        flow_steps = list(taint["flow_steps"])
        flow_steps.append(f"{operation_type} ({ast.unparse(stmt.value) if hasattr(ast, 'unparse') else target_name})")
        taints[target_name] = {
            "source": taint["source"],
            "operations": operations,
            "flow_steps": flow_steps
        }
        break

def analyze_sink_flows(stmt, taints, file_path, source_lines, evidences):
    """Find sinks inside a statement and append direct-source or tracked-taint evidence."""
    for node in ast.walk(stmt):
        sink_info, args = is_sink_node(node)
        if not sink_info:
            continue
        sink_info["line"] = node.lineno
        sink_info["column"] = node.col_offset + 1
        for arg in args:
            source = is_source_node(arg)
            line_no = node.lineno
            code = source_lines[line_no - 1].strip() if line_no <= len(source_lines) else ""
            if source:
                source["line"] = arg.lineno
                source["column"] = arg.col_offset + 1
                evidences.append({
                    "file": file_path,
                    "line": sink_info["line"],
                    "column": sink_info["column"],
                    "language": "python",
                    "source": source,
                    "sink": sink_info,
                    "operations": [],
                    "flow_steps": [
                        f"source: {source['name']} ({source['type']})",
                        f"sink: {sink_info['name']} ({sink_info['type']})"
                    ],
                    "code": code
                })
                break

            ref_vars = collect_referenced_vars(arg)
            for ref_var in ref_vars:
                if ref_var not in taints:
                    continue
                taint = taints[ref_var]
                steps = list(taint["flow_steps"])
                steps.append(f"sink: {sink_info['name']} ({sink_info['type']})")
                evidences.append({
                    "file": file_path,
                    "line": sink_info["line"],
                    "column": sink_info["column"],
                    "language": "python",
                    "source": taint["source"],
                    "sink": sink_info,
                    "operations": taint["operations"],
                    "flow_steps": steps,
                    "code": code
                })
                break

def analyze_scope(statements, file_path, source_lines):
    """Run the intraprocedural assignment and sink checks with an isolated taint map."""
    evidences = []
    # Map var_name -> {"source": ..., "flow_steps": [...], "operations": [...]}
    taints = {}

    for stmt in statements:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    target_name = target.id
                    secret = hardcoded_secret_evidence(stmt, target_name, file_path, source_lines)
                    if secret:
                        evidences.append(secret)
                    analyze_assignment(stmt, target_name, taints)

        analyze_sink_flows(stmt, taints, file_path, source_lines, evidences)
    return evidences

def node_text(node):
    """Render an AST node as source-like text, with an AST dump fallback."""
    return ast.unparse(node) if hasattr(ast, "unparse") else ast.dump(node)

def taint_from_source(source, node):
    """Initialize interprocedural taint state and its source location from an AST node."""
    return {
        "source": dict(source, line=getattr(node, "lineno", 0), column=getattr(node, "col_offset", 0) + 1),
        "operations": [],
        "flow_steps": [f"source: {source['name']} ({source['type']})"],
        "crossed": False,
    }

def taint_operation(taint, kind, detail, node, crossed=False):
    """Copy a taint trace and append an operation, optionally marking a function boundary."""
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
    """Return the local function or method name used for interprocedural matching."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""

class InterproceduralAnalyzer:
    """Interpret same-file function calls while carrying source taint between scopes."""

    def __init__(self, tree, file_path, source_lines, max_depth):
        """Index functions and initialize traversal, evidence, and resource-limit state."""
        self.file_path = file_path
        self.source_lines = source_lines
        self.max_depth = max_depth
        self.functions = {}
        self.all_functions = []
        self.evidences = []
        self.seen = set()
        self.invocation_count = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, []).append(node)
                self.all_functions.append(node)
        self.roots = self.discover_roots()

    def analyze(self):
        """Invoke discovered roots within the budget and return accumulated evidence."""
        for fn in self.all_functions:
            if fn in self.roots and self.invocation_count < 500:
                self.invoke(fn, {}, 0, set())
        return self.evidences

    def resolve_call(self, call):
        """Resolve a call only when its local function name identifies one declaration."""
        if not isinstance(call, ast.Call):
            return None
        matches = self.functions.get(local_call_name(call.func), [])
        return matches[0] if len(matches) == 1 else None

    def discover_roots(self):
        """Find source-bearing functions and callers that can reach those functions."""
        source_functions = set()
        callers = {}
        for fn in self.all_functions:
            args = list(fn.args.posonlyargs) + list(fn.args.args)
            if any(arg.arg in ("request", "req") for arg in args):
                # Request handlers are roots; matched expressions add precise taint later.
                source_functions.add(fn)
            for node in ast.walk(fn):
                if is_source_node(node):
                    source_functions.add(fn)
                if isinstance(node, ast.Call):
                    callee = self.resolve_call(node)
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
        return roots

    def add_evidence(self, sink, taint, call):
        """Deduplicate a cross-function sink flow and append its evidence record."""
        line = getattr(call, "lineno", 0)
        column = getattr(call, "col_offset", 0) + 1
        source = taint["source"]
        key = (source.get("name"), source.get("line"), line, column, sink["type"])
        if key in self.seen:
            return
        self.seen.add(key)
        code = self.source_lines[line - 1].strip() if 0 < line <= len(self.source_lines) else node_text(call)
        steps = list(taint["flow_steps"])
        steps.append(f"sink: {sink['name']} ({sink['type']})")
        self.evidences.append({
            "file": self.file_path,
            "line": line,
            "column": column,
            "language": "python",
            "source": source,
            "sink": dict(sink, line=line, column=column),
            "operations": list(taint["operations"]),
            "flow_steps": steps,
            "code": code,
        })

    def eval_expr(self, node, state, depth, stack):
        """Interpret an expression, propagating taint and emitting crossed sink flows."""
        if node is None or self.invocation_count >= 500:
            return None
        source = is_source_node(node)
        if source:
            return taint_from_source(source, node)
        if isinstance(node, ast.Name):
            return state.get(node.id)
        if isinstance(node, ast.Attribute):
            return state.get(node_text(node)) or self.eval_expr(node.value, state, depth, stack)
        if isinstance(node, ast.Subscript):
            return self.eval_expr(node.value, state, depth, stack) or self.eval_expr(node.slice, state, depth, stack)
        if isinstance(node, ast.Call):
            sink, args = is_sink_node(node)
            if sink:
                for arg in args:
                    taint = self.eval_expr(arg, state, depth, stack)
                    if taint and taint["crossed"]:
                        self.add_evidence(sink, taint, node)
                        break
                return None

            callee = self.resolve_call(node)
            if callee is not None and depth < self.max_depth:
                call_inputs = self.map_call_arguments(node, callee, state, depth, stack)
                result = self.invoke(callee, call_inputs, depth + 1, stack)
                if result:
                    return taint_operation(
                        result, "return_value", f"{callee.name} returns to {local_call_name(node.func)}", node, True
                    )
                return None

            result = None
            for arg in node.args:
                taint = self.eval_expr(arg, state, depth, stack)
                if taint and result is None:
                    result = taint
            if result:
                return taint_operation(result, "function_call", node_text(node), node)
            return None
        if isinstance(node, ast.BinOp):
            left = self.eval_expr(node.left, state, depth, stack)
            right = self.eval_expr(node.right, state, depth, stack)
            taint = left or right
            return taint_operation(taint, "concatenation", node_text(node), node) if taint else None
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                taint = self.eval_expr(value, state, depth, stack)
                if taint:
                    return taint_operation(taint, "format_string", node_text(node), node)
        if isinstance(node, ast.FormattedValue):
            return self.eval_expr(node.value, state, depth, stack)
        if isinstance(node, (ast.UnaryOp, ast.Await, ast.Starred)):
            return self.eval_expr(node.operand if hasattr(node, "operand") else node.value, state, depth, stack)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for item in node.elts:
                taint = self.eval_expr(item, state, depth, stack)
                if taint:
                    return taint_operation(taint, "composite_value", node_text(node), node)
        if isinstance(node, ast.Dict):
            for item in node.values:
                taint = self.eval_expr(item, state, depth, stack)
                if taint:
                    return taint_operation(taint, "composite_value", node_text(node), node)
        return None

    def map_call_arguments(self, call, callee, state, depth, stack):
        """Map tainted positional, receiver, field, and keyword inputs to callee parameters."""
        call_inputs = {}
        params = list(callee.args.posonlyargs) + list(callee.args.args) + list(callee.args.kwonlyargs)
        actuals = list(call.args)
        if isinstance(call.func, ast.Attribute) and params and params[0].arg in ("self", "cls"):
            actuals.insert(0, call.func.value)
        for index, param in enumerate(params):
            actual = actuals[index] if index < len(actuals) else None
            taint = self.eval_expr(actual, state, depth, stack)
            if taint:
                detail = f"{local_call_name(call.func)} -> {param.arg}"
                call_inputs[param.arg] = taint_operation(taint, "argument_passing", detail, call, True)
                prefix = node_text(actual) + "."
                for name, field_taint in state.items():
                    if name.startswith(prefix):
                        call_inputs[param.arg + name[len(node_text(actual)):]] = taint_operation(
                            field_taint, "argument_passing", detail, call, True
                        )
        for keyword in call.keywords:
            if keyword.arg:
                taint = self.eval_expr(keyword.value, state, depth, stack)
                if taint:
                    detail = f"{local_call_name(call.func)} -> {keyword.arg}"
                    call_inputs[keyword.arg] = taint_operation(taint, "argument_passing", detail, call, True)
        return call_inputs

    def assign_target(self, target, taint, state):
        """Bind or clear taint for a supported name, attribute, subscript, or tuple target."""
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
                self.assign_target(item, taint, state)

    def process_block(self, statements, state, depth, stack, returns):
        """Interpret supported statements in order, updating state and collecting returns."""
        for stmt in statements:
            if self.invocation_count >= 500:
                return
            if isinstance(stmt, ast.Assign):
                taint = self.eval_expr(stmt.value, state, depth, stack)
                for target in stmt.targets:
                    self.assign_target(target, taint, state)
            elif isinstance(stmt, ast.AnnAssign):
                self.assign_target(stmt.target, self.eval_expr(stmt.value, state, depth, stack), state)
            elif isinstance(stmt, ast.AugAssign):
                taint = self.eval_expr(stmt.value, state, depth, stack) or self.eval_expr(stmt.target, state, depth, stack)
                self.assign_target(stmt.target, taint, state)
            elif isinstance(stmt, ast.Expr):
                self.eval_expr(stmt.value, state, depth, stack)
            elif isinstance(stmt, ast.Return):
                taint = self.eval_expr(stmt.value, state, depth, stack)
                if taint:
                    returns.append(taint)
            elif isinstance(stmt, ast.If):
                self.eval_expr(stmt.test, state, depth, stack)
                left, right = dict(state), dict(state)
                self.process_block(stmt.body, left, depth, stack, returns)
                self.process_block(stmt.orelse, right, depth, stack, returns)
                state.update(left)
                state.update(right)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(stmt, ast.While):
                    self.eval_expr(stmt.test, state, depth, stack)
                else:
                    self.eval_expr(stmt.iter, state, depth, stack)
                self.process_block(stmt.body, state, depth, stack, returns)
                self.process_block(stmt.orelse, state, depth, stack, returns)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    taint = self.eval_expr(item.context_expr, state, depth, stack)
                    if item.optional_vars:
                        self.assign_target(item.optional_vars, taint, state)
                self.process_block(stmt.body, state, depth, stack, returns)
            elif isinstance(stmt, ast.Try):
                self.process_block(stmt.body, state, depth, stack, returns)
                for handler in stmt.handlers:
                    self.process_block(handler.body, state, depth, stack, returns)
                self.process_block(stmt.orelse, state, depth, stack, returns)
                self.process_block(stmt.finalbody, state, depth, stack, returns)
            elif isinstance(stmt, ast.Match):
                self.eval_expr(stmt.subject, state, depth, stack)
                for case in stmt.cases:
                    self.process_block(case.body, state, depth, stack, returns)

    def invoke(self, fn, inputs, depth, stack):
        """Interpret one function invocation if its depth, cycle, and budget limits permit it."""
        if depth > self.max_depth or fn in stack or self.invocation_count >= 500:
            return None
        self.invocation_count += 1
        stack.add(fn)
        state = dict(inputs)
        returns = []
        self.process_block(fn.body, state, depth, stack, returns)
        stack.remove(fn)
        return returns[0] if returns else None

def analyze_interprocedural(tree, file_path, source_lines, max_depth):
    """Run the stateful interprocedural interpreter for a parsed module."""
    return InterproceduralAnalyzer(tree, file_path, source_lines, max_depth).analyze()

def main():
    """Read bridge input, run both analysis passes, deduplicate findings, and emit JSON."""
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
