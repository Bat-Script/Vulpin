#!/usr/bin/env python3

#TODO: CHECK OUT LICENCE AND HISTORY

from __future__ import annotations
import ast
import dataclasses
import importlib
import io
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "0.5"

DEBUG = False

TOKEN_RE = re.compile(r'\d+\.\d+|\d+|\$[A-Za-z_]\w*|"[^"]*"|<=|>=|<>|\.|[+\-*/%()\[\],=<>]|[A-Za-z_]\w*')
IDENT_RE = re.compile(r'^[A-Za-z_]\w*$')
ASSIGN_RE = re.compile(r'^([A-Za-z_]\w*)\s*=\s*(.+)$')
ARITH_RE = re.compile(r'^A\s*"([^"]*)"\s*([+\-*/])\s*(.*)$')
REPLACE_RE = re.compile(r'^S\s*"([^"]*)"\s*"([^"]*)"\s*"([^"]*)"$')
DELVAR_RE = re.compile(r'^D\s*"([^"]*)"\s*$')
SLEEP_RE = re.compile(r'^D\s*(\d.*)$')
INPUT_RE = re.compile(r'^K\s*"([^"]*)"\s*"([^"]*)"(?:\s*"([^"]*)")?\s*$')
FUNC_RE = re.compile(r'^F\s*([A-Za-z_]\w*)\s*\(([^)]*)\)\s*$')
LABEL_RE = re.compile(r'^L\s+(.+)$')
JUMP_RE = re.compile(r'^J\s+(\S+)\s*$')
IFJUMP_RE = re.compile(r'^\?\s*(.+?)\s+J\s+(\S+)\s*$')
WHILE_RE = re.compile(r'^@\s*(.*)$')
FOR_RE = re.compile(r'^O\s*([A-Za-z_]\w*)\s+(.*)$')
CATCH_RE = re.compile(r'^C(?:\s*"([^"]*)")?\s*$')
SWITCH_RE = re.compile(r'^W\s*(.*)$')
CASE_RE = re.compile(r'^[VN](?:\s.*)?$')
EXPR_CALL_RE = re.compile(r'^\$[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\(.*\)\s*$')


class VulError(Exception):
    def __init__(self, message: str, line: Optional[int] = None, tip: Optional[str] = None):
        self.message = message
        self.line = line
        self.tip = tip
    def __str__(self) -> str:
        s = f"Vul Error (line {self.line}): {self.message}" if self.line else f"Vul Error: {self.message}"
        if self.tip:
            s += f"\nTip: {self.tip}"
        return s
STRING_SHORTCUTS = {'U': 'upper', 'L': 'lower', 'S': 'strip', 'T': 'title', 'C': 'capitalize'}
def tokenize(s: str, line_no: int) -> List[str]:
    tokens: List[str] = []
    pos = 0
    s = s.strip()
    while pos < len(s):
        if s[pos] in ' \t':
            pos += 1
            continue
        m = TOKEN_RE.match(s, pos)
        if not m:
            raise VulError(
                f"Unexpected character '{s[pos]}' in '{s}'",
                line=line_no,
                tip="Check for invalid symbols, missing quotes, or unsupported Unicode.",
            )
        tokens.append(m.group(0))
        pos = m.end()
    return tokens
@dataclass(slots=True)
class Expr:
    kind: str
    value: Any = None
    left: Optional["Expr"] = None
    right: Optional["Expr"] = None
    items: Optional[List["Expr"]] = None
    extra: Any = None
class ExprParser:
    def __init__(self, text: str, line_no: int = 0):
        self.text = text
        self.line_no = line_no
        self.tokens = tokenize(text, line_no)
        self.pos = 0
    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None
    def consume(self, expected: Optional[str] = None) -> str:
        tok = self.peek()
        if tok is None:
            raise VulError("Unexpected end of expression", line=self.line_no, tip="The expression seems incomplete.")
        if expected is not None and tok != expected:
            raise VulError(f"Expected '{expected}' but got '{tok}'", line=self.line_no, tip="Check syntax around this token.")
        self.pos += 1
        return tok
    def parse(self) -> Expr:
        expr = self.parse_comparison()
        if self.peek() is not None:
            raise VulError(f"Unexpected token '{self.peek()}'", line=self.line_no)
        return expr

    def parse_comparison(self) -> Expr:
        left = self.parse_addition()
        ops: List[str] = []
        exprs: List[Expr] = [left]
        while (op := self.peek()) in ('=', '<', '>', '<=', '>=', '<>'):
            self.consume()
            ops.append(op)
            exprs.append(self.parse_addition())
        if not ops:
            return left
        return Expr("cmp", value=ops, items=exprs)

    def parse_addition(self) -> Expr:
        left = self.parse_multiplication()
        while (op := self.peek()) in ('+', '-'):
            self.consume()
            right = self.parse_multiplication()
            left = Expr("bin", value=op, left=left, right=right)
        return left

    def parse_multiplication(self) -> Expr:
        left = self.parse_unary()
        while (op := self.peek()) in ('*', '/', '%'):
            self.consume()
            right = self.parse_unary()
            left = Expr("bin", value=op, left=left, right=right)
        return left

    def parse_unary(self) -> Expr:
        if self.peek() == '-':
            self.consume('-')
            return Expr("neg", left=self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> Expr:
        tok = self.peek()
        if tok is None:
            raise VulError("Unexpected end of expression", line=self.line_no, tip="The expression is empty.")

        if tok[0].isdigit():
            self.consume()
            return Expr("num", float(tok) if '.' in tok else int(tok))

        if tok.startswith('"'):
            self.consume()
            return Expr("str", tok[1:-1])

        if tok.startswith('$'):
            self.consume()
            return self.parse_postfix(Expr("var", tok[1:]))

        if tok == '[':
            return self.parse_list()

        if tok == '(':
            self.consume('(')
            first = self.parse_comparison()
            if self.peek() == ',':
                self.consume(',')
                items = [first]
                items.append(self.parse_comparison())
                while self.peek() == ',':
                    self.consume(',')
                    items.append(self.parse_comparison())
                self.consume(')')
                return Expr("tuple", items=items)
            self.consume(')')
            return self.parse_postfix(first)

        raise VulError(f"Unexpected token '{tok}'", line=self.line_no, tip="You might have used an undefined variable. Put strings in quotes.")

    def parse_list(self) -> Expr:
        self.consume('[')
        items: List[Expr] = []
        if self.peek() != ']':
            items.append(self.parse_comparison())
            while self.peek() == ',':
                self.consume(',')
                items.append(self.parse_comparison())
        self.consume(']')
        return self.parse_postfix(Expr("list", items=items))

    def parse_postfix(self, base: Expr) -> Expr:
        while True:
            t = self.peek()
            if t == '.':
                self.consume('.')
                attr = self.consume()
                if not IDENT_RE.match(attr):
                    raise VulError(f"Invalid attribute name '{attr}'", line=self.line_no)
                base = Expr("attr", left=base, value=attr)
            elif t == '[':
                self.consume('[')
                idx = self.parse_comparison()
                self.consume(']')
                base = Expr("index", left=base, right=idx)
            elif t == '(':
                self.consume('(')
                args: List[Expr] = []
                if self.peek() != ')':
                    args.append(self.parse_comparison())
                    while self.peek() == ',':
                        self.consume(',')
                        args.append(self.parse_comparison())
                self.consume(')')
                base = Expr("call", left=base, items=args)
            else:
                break
        return base


def eval_expr(node: Expr, ctx: "Context", line_no: int = 0) -> Any:
    kind = node.kind

    if kind == "num":
        return node.value
    if kind == "str":
        return node.value
    if kind == "var":
        val = ctx.get_var(node.value)
        if DEBUG:
            print(f"[DEBUG] ${node.value} = {val!r}", file=sys.stderr)
        return val
    if kind == "list":
        return [eval_expr(i, ctx, line_no) for i in (node.items or [])]
    if kind == "tuple":
        return tuple(eval_expr(i, ctx, line_no) for i in (node.items or []))
    if kind == "neg":
        val = eval_expr(node.left, ctx, line_no)
        if isinstance(val, str):
            raise TypeError("Cannot negate a string")
        return -val
    if kind == "bin":
        left = eval_expr(node.left, ctx, line_no)
        right = eval_expr(node.right, ctx, line_no)
        op = node.value
        if op == '+':
            return str(left) + str(right) if isinstance(left, str) or isinstance(right, str) else left + right
        if op == '-':
            if isinstance(left, str) or isinstance(right, str):
                raise TypeError("Cannot subtract strings")
            return left - right
        if op == '*':
            if isinstance(left, str) or isinstance(right, str):
                raise TypeError("Operator '*' not supported for strings")
            return left * right
        if op == '/':
            if isinstance(left, str) or isinstance(right, str):
                raise TypeError("Operator '/' not supported for strings")
            return left / right
        if op == '%':
            if isinstance(left, str) or isinstance(right, str):
                raise TypeError("Operator '%' not supported for strings")
            return left % right
        raise VulError(f"Unknown operator '{op}'", line=line_no)
    if kind == "cmp":
        ops = node.value
        exprs = node.items or []
        vals = [eval_expr(e, ctx, line_no) for e in exprs]
        for i, op in enumerate(ops):
            a = vals[i]
            b = vals[i + 1]
            if isinstance(a, str) or isinstance(b, str):
                a, b = str(a), str(b)
            if op == '=' and not (a == b):
                return 0
            if op == '<' and not (a < b):
                return 0
            if op == '>' and not (a > b):
                return 0
            if op == '<=' and not (a <= b):
                return 0
            if op == '>=' and not (a >= b):
                return 0
            if op == '<>' and not (a != b):
                return 0
        return 1
    if kind == "attr":
        val = eval_expr(node.left, ctx, line_no)
        attr = node.value
        if DEBUG:
            print(f"[DEBUG] Dot access: {type(val).__name__}.{attr}", file=sys.stderr)
        if attr in STRING_SHORTCUTS and isinstance(val, str):
            return getattr(val, STRING_SHORTCUTS[attr])()
        return getattr(val, attr)
    if kind == "index":
        val = eval_expr(node.left, ctx, line_no)
        idx = eval_expr(node.right, ctx, line_no)
        return val[idx]
    if kind == "call":
        fn = eval_expr(node.left, ctx, line_no)
        args = [eval_expr(a, ctx, line_no) for a in (node.items or [])]
        if not callable(fn):
            raise TypeError(f"'{fn}' is not callable")
        return fn(*args)
    raise VulError(f"Unknown expression node '{kind}'", line=line_no)


class ExprCache:
    def __init__(self):
        self.cache: Dict[str, Expr] = {}

    def compile(self, expr: str, line_no: int) -> Expr:
        expr = expr.strip()
        if not expr:
            return Expr("str", "")
        node = self.cache.get(expr)
        if node is None:
            node = ExprParser(expr, line_no).parse()
            self.cache[expr] = node
        return node

class Context:
    def __init__(self, parent: Optional["Context"] = None):
        self.vars: Dict[str, Any] = {}
        self.parent = parent
        self.returned = False
        self.return_val = None

    def get_var(self, name: str) -> Any:
        if name in self.vars:
            return self.vars[name]
        if self.parent:
            return self.parent.get_var(name)
        raise NameError(f"Variable '{name}' not defined")

    def set_var(self, name: str, value: Any) -> None:
        self.vars[name] = value

    def del_var(self, name: str) -> None:
        if name in self.vars:
            del self.vars[name]
        else:
            raise NameError(f"Variable '{name}' not defined")


@dataclass(slots=True)
class Stmt:
    op: str
    line_no: int
    raw: str = ""
    a: Any = None
    b: Any = None
    c: Any = None
    d: Any = None
    e: Any = None


@dataclass
class FunctionDef:
    name: str
    params: List[str]
    body: List[Stmt]


class VulFunction:
    def __init__(self, fdef: FunctionDef, interpreter: "VulInterpreter"):
        self.name = fdef.name
        self.params = fdef.params
        self.body = fdef.body
        self.interpreter = interpreter

    def __call__(self, *args):
        if len(args) != len(self.params):
            raise TypeError(f"Function '{self.name}' expects {len(self.params)} arguments, got {len(args)}")
        local_ctx = Context(parent=self.interpreter.global_ctx)
        for p, a in zip(self.params, args):
            local_ctx.set_var(p, a)
        self.interpreter.run_block(self.body, local_ctx)
        return local_ctx.return_val if local_ctx.returned else None


class Compiler:
    def __init__(self, expr_cache: ExprCache):
        self.expr_cache = expr_cache

    def strip_comment(self, line: str) -> str:
        return line.split('#', 1)[0].strip()

    def split_lines(self, source: str) -> List[Tuple[int, str]]:
        out = []
        for i, raw in enumerate(source.splitlines(), 1):
            line = self.strip_comment(raw)
            if line:
                out.append((i, line))
        return out

    def compile_block(self, lines: List[Tuple[int, str]], start: int = 0, stop: Optional[int] = None) -> List[Stmt]:
        if stop is None:
            stop = len(lines)
        stmts: List[Stmt] = []
        i = start
        while i < stop:
            line_no, line = lines[i]
            op = self.compile_line(lines, i, stop, stmts)
            if op is None:
                i += 1
                continue
            if isinstance(op, int):
                i = op
            else:
                i += 1
        return stmts

    def compile_line(self, lines: List[Tuple[int, str]], i: int, stop: int, stmts: List[Stmt]) -> Optional[int]:
        line_no, line = lines[i]

        if line.startswith('!'):
            code_lines = [line[1:]]
            j = i + 1
            while j < stop and lines[j][1].startswith('!'):
                code_lines.append(lines[j][1][1:])
                j += 1
            stmts.append(Stmt("PY", line_no, "\n".join(code_lines)))
            return j

        m = ASSIGN_RE.match(line)
        if m and not line.startswith(('?', '@', 'O', 'W', 'A', 'S', 'D', 'K', 'F', 'J', 'L', 'R', 'G', 'P', 'U', 'E', 'X', 'C', 'Y', 'V', 'N')):
            var_name, expr = m.group(1), m.group(2).strip()
            stmts.append(Stmt("ASSIGN", line_no, line, var_name, self.expr_cache.compile(expr, line_no)))
            return None

        if m := LABEL_RE.match(line):
            stmts.append(Stmt("LABEL", line_no, line, m.group(1).strip()))
            return None

        if m := JUMP_RE.match(line):
            stmts.append(Stmt("JUMP", line_no, line, m.group(1)))
            return None

        if m := IFJUMP_RE.match(line):
            cond, label = m.group(1).strip(), m.group(2)
            stmts.append(Stmt("IFJUMP", line_no, line, self.expr_cache.compile(cond, line_no), label))
            return None

        if line.startswith('?'):
            cond = line[1:].strip()
            stmts.append(Stmt("IF", line_no, line, self.expr_cache.compile(cond, line_no)))
            return None

        if line == ':':
            stmts.append(Stmt("ELSE", line_no, line))
            return None

        if line == ';':
            stmts.append(Stmt("ENDIF", line_no, line))
            return None

        if m := WHILE_RE.match(line):
            stmts.append(Stmt("WHILE", line_no, line, self.expr_cache.compile(m.group(1).strip(), line_no)))
            return None

        if line == '&':
            stmts.append(Stmt("ENDLOOP", line_no, line))
            return None

        if line.startswith('R'):
            stmts.append(Stmt("RETURN", line_no, line, self.expr_cache.compile(line[1:].strip(), line_no)))
            return None

        if m := FUNC_RE.match(line):
            fname = m.group(1)
            params = [p.strip() for p in m.group(2).split(',') if p.strip()]
            body_lines: List[Tuple[int, str]] = []
            j = i + 1
            while j < stop and lines[j][1] != '~':
                body_lines.append(lines[j])
                j += 1
            if j >= stop:
                raise VulError(f"Function '{fname}' not terminated with '~'", line=line_no)
            body = self.compile_block(body_lines)
            stmts.append(Stmt("FUNC", line_no, line, FunctionDef(fname, params, body)))
            return j + 1

        if line == '~':
            stmts.append(Stmt("ENDFUNC", line_no, line))
            return None

        if line.startswith('U'):
            mod = line[1:].strip()
            if mod.startswith('"') and mod.endswith('"'):
                mod = mod[1:-1]
            stmts.append(Stmt("IMPORT", line_no, line, mod))
            return None

        if m := ARITH_RE.match(line):
            var_name, op, expr = m.group(1), m.group(2), m.group(3).strip()
            stmts.append(Stmt("ARITH", line_no, line, var_name, op, self.expr_cache.compile(expr, line_no)))
            return None

        if m := REPLACE_RE.match(line):
            stmts.append(Stmt("REPLACE", line_no, line, m.group(1), m.group(2), m.group(3)))
            return None

        if m := DELVAR_RE.match(line):
            stmts.append(Stmt("DELVAR", line_no, line, m.group(1)))
            return None

        if m := SLEEP_RE.match(line):
            stmts.append(Stmt("SLEEP", line_no, line, self.expr_cache.compile(m.group(1).strip(), line_no)))
            return None

        if m := INPUT_RE.match(line):
            stmts.append(Stmt("INPUT", line_no, line, m.group(1), m.group(2), m.group(3)))
            return None

        if line.startswith('X'):
            stmts.append(Stmt("SPAWN", line_no, line, line[1:].strip().strip('"')))
            return None

        if line == 'Q':
            stmts.append(Stmt("QUIT", line_no, line))
            return None

        if line.startswith('E'):
            stmts.append(Stmt("ERROR", line_no, line, line[1:].strip()))
            return None

        if line.startswith('P'):
            stmts.append(Stmt("PRINT", line_no, line, self.expr_cache.compile(line[1:].strip(), line_no), False))
            return None

        if line.startswith('G'):
            stmts.append(Stmt("PRINT", line_no, line, self.expr_cache.compile(line[1:].strip(), line_no), True))
            return None

        if line.startswith('T') and line.strip() == 'T':
            stmts.append(Stmt("TRY", line_no, line))
            return None

        if m := CATCH_RE.match(line):
            stmts.append(Stmt("CATCH", line_no, line, m.group(1)))
            return None

        if line.strip() == 'Y':
            stmts.append(Stmt("FINALLY", line_no, line))
            return None

        if m := SWITCH_RE.match(line):
            stmts.append(Stmt("SWITCH", line_no, line, self.expr_cache.compile(m.group(1).strip(), line_no)))
            return None

        if CASE_RE.match(line) and (line.startswith('V') or line.startswith('N')):
            if line.startswith('V'):
                stmts.append(Stmt("CASE", line_no, line, self.expr_cache.compile(line[1:].strip(), line_no)))
            else:
                stmts.append(Stmt("DEFAULT", line_no, line))
            return None

        if line == 'Z':
            stmts.append(Stmt("ENDSWITCH", line_no, line))
            return None

        if m := FOR_RE.match(line):
            var_name = m.group(1)
            rest = m.group(2).strip().split()
            if len(rest) < 2:
                raise VulError("For loop requires start and end", line=line_no)
            start_expr = self.expr_cache.compile(rest[0], line_no)
            end_expr = self.expr_cache.compile(rest[1], line_no)
            step_expr = self.expr_cache.compile(rest[2], line_no) if len(rest) > 2 else self.expr_cache.compile('1', line_no)
            stmts.append(Stmt("FOR", line_no, line, var_name, start_expr, end_expr, step_expr))
            return None

        if EXPR_CALL_RE.match(line):
            stmts.append(Stmt("EXPR", line_no, line, self.expr_cache.compile(line, line_no)))
            return None

        raise VulError(
            f"Unknown command: {line}",
            line=line_no,
            tip="Valid: G P A S D K X Q E U ? : ; @ & L J F R ~ T C Y O W V N Z",
        )


class VulInterpreter:
    def __init__(self):
        self.global_ctx = Context()
        self.expr_cache = ExprCache()
        self.compiler = Compiler(self.expr_cache)
        self.labels: Dict[str, int] = {}
        self.try_blocks: Dict[int, Tuple[Optional[int], Optional[int]]] = {}
        self.switch_blocks: Dict[int, Tuple[int, set[int]]] = {}
        self.current_line = 0
        self.dispatch: Dict[str, Callable[[Stmt, int, List[Stmt], Context, List[Any], List[int]], int]] = {
            "PY": self._op_py,
            "ASSIGN": self._op_assign,
            "LABEL": self._op_label,
            "JUMP": self._op_jump,
            "IFJUMP": self._op_ifjump,
            "IF": self._op_if,
            "ELSE": self._op_else,
            "ENDIF": self._op_endif,
            "WHILE": self._op_while,
            "ENDLOOP": self._op_endloop,
            "RETURN": self._op_return,
            "FUNC": self._op_func,
            "ENDFUNC": self._op_endfunc,
            "IMPORT": self._op_import,
            "ARITH": self._op_arith,
            "REPLACE": self._op_replace,
            "DELVAR": self._op_delvar,
            "SLEEP": self._op_sleep,
            "INPUT": self._op_input,
            "SPAWN": self._op_spawn,
            "QUIT": self._op_quit,
            "ERROR": self._op_error,
            "PRINT": self._op_print,
            "TRY": self._op_try,
            "CATCH": self._op_catch,
            "FINALLY": self._op_finally,
            "SWITCH": self._op_switch,
            "CASE": self._op_case,
            "DEFAULT": self._op_default,
            "ENDSWITCH": self._op_endswitch,
            "FOR": self._op_for,
            "EXPR": self._op_expr,
        }
        self.program_text: str = ""

    def interpret(self, source: str):
        self.program_text = source
        raw_lines = self.compiler.split_lines(source)
        program = self.compiler.compile_block(raw_lines)
        self._build_maps(program)
        self.run_block(program, self.global_ctx)

    def _build_maps(self, program: List[Stmt]):
        self.labels = {}
        self.try_blocks = {}
        self.switch_blocks = {}

        try_stack: List[int] = []
        switch_stack: List[int] = []

        for idx, st in enumerate(program):
            if st.op == "LABEL":
                label = st.a
                if label in self.labels:
                    raise VulError(f"Duplicate label '{label}'", line=st.line_no)
                self.labels[label] = idx

            if st.op == "TRY":
                try_stack.append(idx)
            elif st.op == "CATCH":
                if not try_stack:
                    raise VulError("C without T", line=st.line_no)
                self.try_blocks[try_stack[-1]] = (idx, self.try_blocks.get(try_stack[-1], (None, None))[1])
            elif st.op == "FINALLY":
                if not try_stack:
                    raise VulError("Y without T", line=st.line_no)
                start_ip = try_stack.pop()
                catch_ip, _ = self.try_blocks.get(start_ip, (None, None))
                self.try_blocks[start_ip] = (catch_ip, idx)

            if st.op == "SWITCH":
                switch_stack.append(idx)
            elif st.op == "ENDSWITCH":
                if not switch_stack:
                    raise VulError("Z without W", line=st.line_no)
                start_ip = switch_stack.pop()
                self.switch_blocks[start_ip] = (idx, set())

        if try_stack:
            raise VulError("T without Y")
        if switch_stack:
            raise VulError("W without Z")
        for start_ip, (end_ip, _) in list(self.switch_blocks.items()):
            delimiters: set[int] = set()
            i = start_ip + 1
            while i < end_ip:
                op = program[i].op
                if op in ("CASE", "DEFAULT"):
                    delimiters.add(i)
                i += 1
            self.switch_blocks[start_ip] = (end_ip, delimiters)

    def run_block(self, lines: List[Stmt], ctx: Context, start: int = 0):
        ip = start
        control_stack: List[Tuple[str, Any]] = []
        try_stack: List[int] = []
        in_switch: Optional [Tuple[int, set[int]]] = None
        python_block: List[str] = []

        while ip < len(lines):
            st = lines[ip]
            self.current_line = st.line_no
            try:
                if st.op == "PY":
                    if not python_block:
                        python_block = [st.raw]
                    else:
                        python_block.append(st.raw)
                    ip += 1
                    if ip < len(lines) and lines[ip].op == "PY":
                        continue
                    code = "\n".join(python_block)
                    python_block = []
                    try:
                        exec(code, {"__builtins__": __builtins__}, ctx.vars)
                    except Exception as e:
                        raise VulError(f"Python error: {e}", line=self.current_line)
                    continue

                if in_switch is not None:
                    end_ip, delimiters = in_switch
                    if ip in delimiters:
                        ip = end_ip + 1
                        in_switch = None
                        continue

                handler = self.dispatch.get(st.op)
                if handler is None:
                    raise VulError(f"Internal error: no handler for '{st.op}'", line=st.line_no)
                ip = handler(st, ip, lines, ctx, control_stack, try_stack, in_switch)
            except Exception as e:
                if not try_stack:
                    raise
                handled = False
                for start_ip in reversed(try_stack):
                    catch_ip, _ = self.try_blocks.get(start_ip, (None, None))
                    if catch_ip is not None:
                        catch_stmt = lines[catch_ip]
                        if catch_stmt.op == "CATCH" and catch_stmt.a:
                            ctx.set_var(catch_stmt.a, str(e))
                        ip = catch_ip + 1
                        handled = True
                        break
                if not handled:
                    raise

    def _op_py(self, st: Stmt, ip: int, lines: List[Stmt], ctx: Context, control_stack, try_stack, in_switch):
        return ip + 1

    def _op_assign(self, st: Stmt, ip: int, lines, ctx, control_stack, try_stack, in_switch):
        ctx.set_var(st.a, eval_expr(st.b, ctx, st.line_no))
        return ip + 1

    def _op_label(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        return ip + 1

    def _op_jump(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        target = st.a
        if target not in self.labels:
            raise VulError(f"Undefined label '{target}'", line=st.line_no)
        return self.labels[target]

    def _op_ifjump(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        cond, label = st.a, st.b
        if label not in self.labels:
            raise VulError(f"Undefined label '{label}'", line=st.line_no)
        if eval_expr(cond, ctx, st.line_no):
            return self.labels[label]
        return ip + 1

    def _skip_to(self, lines: List[Stmt], ip: int, stop_ops: Tuple[str, ...]) -> int:
        depth = 1
        ip += 1
        while ip < len(lines) and depth > 0:
            cur = lines[ip]
            if cur.op == lines[ip - 1].op and False:
                pass
            if cur.op in ("IF", "WHILE", "FOR"):
                depth += 1
            elif cur.op in stop_ops:
                depth -= 1
            if depth == 0:
                break
            ip += 1
        return ip

    def _op_if(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        if eval_expr(st.a, ctx, st.line_no):
            control_stack.append(("if", None))
            return ip + 1
        depth = 1
        ip += 1
        while ip < len(lines) and depth > 0:
            cur = lines[ip]
            if cur.op == "IF":
                depth += 1
            elif cur.op == "ENDIF":
                depth -= 1
            elif cur.op == "ELSE" and depth == 1:
                break
            ip += 1
        if depth == 0:
            return ip
        control_stack.append(("if", None))
        return ip + 1

    def _op_else(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        depth = 1
        ip += 1
        while ip < len(lines) and depth > 0:
            cur = lines[ip]
            if cur.op == "IF":
                depth += 1
            elif cur.op == "ENDIF":
                depth -= 1
            ip += 1
        return ip

    def _op_endif(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        if control_stack and control_stack[-1][0] == "if":
            control_stack.pop()
        return ip + 1

    def _op_while(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        cond = eval_expr(st.a, ctx, st.line_no)
        if not cond:
            depth = 1
            ip += 1
            while ip < len(lines) and depth > 0:
                cur = lines[ip]
                if cur.op == "WHILE":
                    depth += 1
                elif cur.op == "ENDLOOP":
                    depth -= 1
                ip += 1
            return ip
        control_stack.append(("while", ip))
        return ip + 1

    def _op_endloop(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        if not control_stack:
            raise VulError("& without @ or O", line=st.line_no)
        typ, data = control_stack[-1]
        if typ == "while":
            return data
        if typ == "for":
            start_ip, var, end_val, step = data
            cur_val = ctx.get_var(var)
            new_val = cur_val + step
            ctx.set_var(var, new_val)
            if (step > 0 and new_val < end_val) or (step < 0 and new_val > end_val):
                return start_ip + 1
            control_stack.pop()
            return ip + 1
        raise VulError("Unknown loop type", line=st.line_no)

    def _op_return(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        ctx.returned = True
        ctx.return_val = eval_expr(st.a, ctx, st.line_no)
        return len(lines)

    def _op_func(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        fdef: FunctionDef = st.a
        ctx.set_var(fdef.name, VulFunction(fdef, self))
        return ip + 1

    def _op_endfunc(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        return ip + 1

    def _op_import(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        name = st.a
        if name.endswith('.vul'):
            try:
                with open(name, 'r', encoding='utf-8') as f:
                    source = f.read()
            except FileNotFoundError:
                raise VulError(f"Vul file '{name}' not found", line=st.line_no, tip="Make sure the .vul file is in the same folder.")
            sub = VulInterpreter()
            sub.global_ctx = ctx
            sub.interpret(source)
        else:
            try:
                mod = importlib.import_module(name)
                ctx.set_var(name, mod)
            except ImportError:
                raise VulError(f"Python module '{name}' not found", line=st.line_no, tip="Install it with pip.")
        return ip + 1

    def _op_arith(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        old = ctx.get_var(st.a)
        val = eval_expr(st.c, ctx, st.line_no)
        if st.b == '+':
            new = old + val
        elif st.b == '-':
            new = old - val
        elif st.b == '*':
            new = old * val
        elif st.b == '/':
            new = old / val
        else:
            raise VulError(f"Unknown arithmetic op '{st.b}'", line=st.line_no)
        ctx.set_var(st.a, new)
        return ip + 1

    def _op_replace(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        cur = str(ctx.get_var(st.a))
        ctx.set_var(st.a, cur.replace(st.b, st.c))
        return ip + 1

    def _op_delvar(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        ctx.del_var(st.a)
        return ip + 1

    def _op_sleep(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        time.sleep(eval_expr(st.a, ctx, st.line_no))
        return ip + 1

    def _op_input(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        var_name, prompt, kind = st.a, st.b, st.c
        raw = input(prompt)
        if kind is None:
            ctx.set_var(var_name, raw)
            return ip + 1

        default = 0 if kind in ("I", "F", "N") else ""
        try:
            if kind == "I":
                val = int(raw)
            elif kind == "F":
                val = float(raw)
            elif kind == "N":
                val = float(raw)
                if val == int(val):
                    val = int(val)
            elif kind == "L":
                if len(raw) == 1 and raw.isalpha():
                    val = raw
                else:
                    raise ValueError
            elif kind == "W":
                if raw.isalpha():
                    val = raw
                else:
                    raise ValueError
            elif kind == "E":
                if raw.isalpha() and raw == raw.lower():
                    val = raw
                else:
                    raise ValueError
            elif kind == "U":
                if raw.isalpha() and raw == raw.upper():
                    val = raw
                else:
                    raise ValueError
            elif kind == "A":
                if all(ch.isalpha() or ch.isspace() for ch in raw) and raw.strip():
                    val = raw
                else:
                    raise ValueError
            elif kind == "P":
                if all(ch.isalnum() or ch.isspace() for ch in raw) and raw.strip():
                    val = raw
                else:
                    raise ValueError
            else:
                raise VulError(f"Unknown type character '{kind}'", line=st.line_no)
            ctx.set_var(var_name, val)
        except ValueError:
            ctx.set_var(var_name, default)
        return ip + 1

    def _op_spawn(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        filename = st.a
        subprocess.Popen([sys.executable, filename])
        return ip + 1

    def _op_quit(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        raise SystemExit(0)

    def _op_error(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        print(f"Error: {st.a}")
        raise SystemExit(1)

    def _op_print(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        val = eval_expr(st.a, ctx, st.line_no)
        if st.b:
            print(val, flush=True)
        else:
            print(val, end='', flush=True)
        return ip + 1

    def _op_try(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        try_stack.append(ip)
        return ip + 1

    def _op_catch(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        return ip + 1

    def _op_finally(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        if try_stack:
            try_stack.pop()
        return ip + 1

    def _op_switch(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        switch_val = eval_expr(st.a, ctx, st.line_no)
        end_ip, delimiters = self.switch_blocks[ip]
        i = ip + 1
        matched = False
        while i < end_ip:
            cur = lines[i]
            if cur.op == "CASE":
                case_val = eval_expr(cur.a, ctx, cur.line_no)
                if case_val == switch_val:
                    in_switch = (end_ip, delimiters)
                    matched = True
                    return i + 1
            elif cur.op == "DEFAULT":
                in_switch = (end_ip, delimiters)
                matched = True
                return i + 1
            i += 1
        if not matched:
            return end_ip + 1
        return ip + 1

    def _op_case(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        return ip + 1

    def _op_default(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        return ip + 1

    def _op_endswitch(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        return ip + 1

    def _op_for(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        var_name = st.a
        start_val = eval_expr(st.b, ctx, st.line_no)
        end_val = eval_expr(st.c, ctx, st.line_no)
        step_val = eval_expr(st.d, ctx, st.line_no)
        ctx.set_var(var_name, start_val)
        if (step_val > 0 and start_val < end_val) or (step_val < 0 and start_val > end_val):
            control_stack.append(("for", (ip, var_name, end_val, step_val)))
            return ip + 1
        depth = 1
        ip += 1
        while ip < len(lines) and depth > 0:
            cur = lines[ip]
            if cur.op == "FOR":
                depth += 1
            elif cur.op == "ENDLOOP":
                depth -= 1
            ip += 1
        return ip

    def _op_expr(self, st, ip, lines, ctx, control_stack, try_stack, in_switch):
        eval_expr(st.a, ctx, st.line_no)
        return ip + 1

    def do_import(self, name: str, ctx: Context):
        if name.endswith('.vul'):
            with open(name, 'r', encoding='utf-8') as f:
                source = f.read()
            sub = VulInterpreter()
            sub.global_ctx = ctx
            sub.interpret(source)
        else:
            mod = importlib.import_module(name)
            ctx.set_var(name, mod)

    def bench(self, source: str, rounds: int = 1) -> Tuple[float, float]:
        import tracemalloc
        tracemalloc.start()
        t0 = time.perf_counter()
        for _ in range(rounds):
            self.interpret(source)
        elapsed = time.perf_counter() - t0
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return elapsed, peak / (1024 * 1024)


def make_benchmark_program(n: int = 10000) -> str:
    return f"""
a = 0
O i 0 {n} 1
A "a" + 1
&
""".strip()


def main():
    global DEBUG
    if '--debug' in sys.argv:
        DEBUG = True
        sys.argv.remove('--debug')

    if '--selftest' in sys.argv:
        vi = VulInterpreter()
        vi.interpret('U"os"\nG $os.name\n')
        return

    if '--bench' in sys.argv:
        n = 10000
        if len(sys.argv) > sys.argv.index('--bench') + 1 and sys.argv[sys.argv.index('--bench') + 1].isdigit():
            n = int(sys.argv[sys.argv.index('--bench') + 1])
        prog = make_benchmark_program(n)
        vi = VulInterpreter()
        elapsed, peak = vi.bench(prog, 1)
        print(f"Vulpin optimized benchmark ({n} iterations)")
        print(f"Time: {elapsed:.6f}s")
        print(f"Peak memory: {peak:.2f} MiB")
        print("Note: compare against your old interpreter by running the same program there.")
        return

    if len(sys.argv) > 1 and sys.argv[1].lower() == "version":
        print(f"Vul {VERSION}")
        return

    filename = sys.argv[1] if len(sys.argv) > 1 else 'app.vul'
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source = f.read()
        interpreter = VulInterpreter()
        interpreter.interpret(source)
    except FileNotFoundError:
        print(f"Error: '{filename}' not found.")
    except VulError as e:
        print(e)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
