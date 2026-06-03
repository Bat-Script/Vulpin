import sys, os, argparse, subprocess, base64
VUL_CODE = r'''
import re, sys, importlib, subprocess, time, os
VERSION = "0.2"
class VulError(Exception):
    def __init__(self, message, line=None, tip=None):
        self.message = message; self.line = line; self.tip = tip
    def __str__(self):
        s = f"Vul Error (line {self.line}): {self.message}" if self.line else f"Vul Error: {self.message}"
        if self.tip: s += f"\nTip: {self.tip}"
        return s
TOKEN_RE = re.compile(r'\d+\.\d+|\d+|\$[A-Za-z_]\w*|"[^"]*"|<=|>=|<>|\.|[+\-*/%()\[\],=<>]|[A-Za-z_]\w*')
def tokenize(s, line_no):
    tokens = []
    pos = 0
    s = s.strip()
    while pos < len(s):
        if s[pos] in ' \t': pos += 1; continue
        m = TOKEN_RE.match(s, pos)
        if not m: raise VulError(f"Unexpected character '{s[pos]}' in '{s}'", line=line_no, tip="Check for invalid symbols, missing quotes, or unsupported Unicode.")
        tokens.append(m.group(0)); pos = m.end()
    return tokens
class Context:
    def __init__(self, parent=None): self.vars = {}; self.parent = parent; self.returned = False; self.return_val = None
    def get_var(self, name):
        if name in self.vars: return self.vars[name]
        if self.parent: return self.parent.get_var(name)
        raise NameError(f"Variable '{name}' not defined")
    def set_var(self, name, value): self.vars[name] = value
    def del_var(self, name):
        if name in self.vars: del self.vars[name]
        else: raise NameError(f"Variable '{name}' not defined")
class VulFunction:
    def __init__(self, name, params, body_lines, interpreter):
        self.name = name; self.params = params; self.body = body_lines; self.interpreter = interpreter
    def __call__(self, *args):
        if len(args) != len(self.params): raise TypeError(f"Function '{self.name}' expects {len(self.params)} arguments, got {len(args)}")
        local_ctx = Context(parent=self.interpreter.global_ctx)
        for p, a in zip(self.params, args): local_ctx.set_var(p, a)
        self.interpreter.run_block(self.body, local_ctx)
        return local_ctx.return_val if local_ctx.returned else None
STRING_SHORTCUTS = {'U':'upper','L':'lower','S':'strip','T':'title','C':'capitalize'}
class ExprEvaluator:
    def __init__(self, context): self.ctx = context; self.line_no = 0
    def eval(self, expr_str):
        if not expr_str.strip(): return None
        self.tokens = tokenize(expr_str, self.line_no)
        self.pos = 0
        return self.parse_comparison()
    def peek(self): return self.tokens[self.pos] if self.pos < len(self.tokens) else None
    def consume(self, expected=None):
        tok = self.peek()
        if tok is None: raise VulError("Unexpected end of expression", line=self.line_no, tip="The expression seems incomplete.")
        if expected is not None and tok != expected: raise VulError(f"Expected '{expected}' but got '{tok}'", line=self.line_no, tip="Check syntax around this token.")
        self.pos += 1; return tok
    def parse_comparison(self):
        left = self.parse_addition()
        while (op := self.peek()) in ('=', '<', '>', '<=', '>=', '<>'):
            self.consume(); right = self.parse_addition()
            if isinstance(left, str) or isinstance(right, str):
                l, r = str(left), str(right)
                left = 1 if ((op=='=' and l==r) or (op=='<' and l<r) or (op=='>' and l>r) or (op=='<=' and l<=r) or (op=='>=' and l>=r) or (op=='<>' and l!=r)) else 0
            else:
                left = 1 if ((op=='=' and left==right) or (op=='<' and left<right) or (op=='>' and left>right) or (op=='<=' and left<=right) or (op=='>=' and left>=right) or (op=='<>' and left!=right)) else 0
        return left
    def parse_addition(self):
        left = self.parse_multiplication()
        while (op := self.peek()) in ('+', '-'):
            self.consume(); right = self.parse_multiplication()
            if op == '+': left = str(left)+str(right) if isinstance(left, str) or isinstance(right, str) else left+right
            else:
                if isinstance(left, str) or isinstance(right, str): raise TypeError("Cannot subtract strings")
                left -= right
        return left
    def parse_multiplication(self):
        left = self.parse_unary()
        while (op := self.peek()) in ('*', '/', '%'):
            self.consume(); right = self.parse_unary()
            if isinstance(left, str) or isinstance(right, str): raise TypeError(f"Operator '{op}' not supported for strings")
            if op == '*': left *= right
            elif op == '/': left /= right
            else: left %= right
        return left
    def parse_unary(self):
        if self.peek() == '-':
            self.consume(); val = self.parse_primary()
            if isinstance(val, str): raise TypeError("Cannot negate a string")
            return -val
        return self.parse_primary()
    def parse_primary(self):
        tok = self.peek()
        if tok is None: raise VulError("Unexpected end of expression", line=self.line_no, tip="The expression is empty.")
        if re.match(r'^\d', tok):
            self.consume(); return float(tok) if '.' in tok else int(tok)
        elif tok.startswith('"'):
            self.consume(); return tok[1:-1]
        elif tok.startswith('$'):
            self.consume(); var_name = tok[1:]; return self.ctx.get_var(var_name)
        elif tok == '[': return self.parse_list()
        elif tok == '(':
            self.consume('('); val = self.parse_comparison()
            if self.peek() == ',':
                self.consume(','); rest = self.parse_rest_tuple(); val = (val,) + rest
            self.consume(')'); return val
        else:
            raise VulError(f"Unexpected token '{tok}'", line=self.line_no, tip="You might have used an undefined variable. Put strings in quotes.")
        while True:
            t = self.peek()
            if t == '.':
                self.consume('.'); attr = self.consume()
                if not attr.isidentifier(): raise VulError(f"Invalid attribute name '{attr}'", line=self.line_no)
                if attr in STRING_SHORTCUTS and isinstance(val, str):
                    val = getattr(val, STRING_SHORTCUTS[attr])()
                else:
                    val = getattr(val, attr)
            elif t == '[':
                self.consume('['); idx = self.parse_comparison(); self.consume(']'); val = val[idx]
            elif t == '(':
                self.consume('('); args = []
                if self.peek() != ')':
                    args.append(self.parse_comparison())
                    while self.peek() == ',': self.consume(','); args.append(self.parse_comparison())
                self.consume(')')
                if not callable(val): raise TypeError(f"'{val}' is not callable")
                val = val(*args)
            else: break
        return val
    def parse_list(self):
        self.consume('['); elems = []
        if self.peek() != ']':
            elems.append(self.parse_comparison())
            while self.peek() == ',': self.consume(','); elems.append(self.parse_comparison())
        self.consume(']'); return elems
    def parse_rest_tuple(self):
        rest = [self.parse_comparison()]
        while self.peek() == ',': self.consume(','); rest.append(self.parse_comparison())
        return tuple(rest)
class VulInterpreter:
    def __init__(self):
        self.global_ctx = Context()
        self.labels = {}; self.try_blocks = {}; self.switch_blocks = {}; self.current_line = 0
    def interpret(self, source):
        lines = source.splitlines(); program = []
        for raw in lines:
            line = raw.split('#', 1)[0].strip()
            if line: program.append(line)
        self.labels = {}; self.try_blocks = {}; self.switch_blocks = {}
        try_stack = []; switch_stack = []
        for idx, line in enumerate(program):
            if re.match(r'^L\s+', line):
                label = line[2:].strip()
                if label in self.labels: raise VulError(f"Duplicate label '{label}'", line=idx+1)
                self.labels[label] = idx
            if re.match(r'^T\s*$', line): try_stack.append(idx)
            elif re.match(r'^C', line):
                if not try_stack: raise VulError("C without T", line=idx+1)
                start_ip = try_stack[-1]; self.try_blocks[start_ip] = [idx, None]
            elif re.match(r'^Y\s*$', line):
                if not try_stack: raise VulError("Y without T", line=idx+1)
                start_ip = try_stack.pop()
                if start_ip in self.try_blocks: self.try_blocks[start_ip][1] = idx
                else: self.try_blocks[start_ip] = [None, idx]
            if line.startswith('W'): switch_stack.append(idx)
            elif line == 'Z':
                if not switch_stack: raise VulError("Z without W", line=idx+1)
                start_ip = switch_stack.pop(); self.switch_blocks[start_ip] = [idx, set()]
        if try_stack: raise VulError("T without Y")
        if switch_stack: raise VulError("W without Z")
        for start_ip, (end_ip, case_ips) in self.switch_blocks.items():
            i = start_ip + 1
            while i < end_ip:
                line = program[i]
                if line.startswith('V') or line.startswith('N'): case_ips.add(i)
                elif line.startswith('W'): i = self.switch_blocks[i][0]
                i += 1
            self.switch_blocks[start_ip] = (end_ip, case_ips)
        self.run_block(program, self.global_ctx)
    def run_block(self, lines, ctx, start=0):
        ip = start; control_stack = []; try_stack = []; in_switch = None
        evaluator = ExprEvaluator(ctx); python_block_lines = []
        while ip < len(lines):
            line = lines[ip]; self.current_line = ip + 1; evaluator.line_no = self.current_line
            if line.startswith('!') and not python_block_lines:
                code = line[1:]
                if code.rstrip().endswith(':'): python_block_lines.append(code); ip += 1; continue
                else:
                    try: exec(code, {'__builtins__': __builtins__}, ctx.vars)
                    except Exception as e: raise VulError(f"Python error: {e}", line=self.current_line)
                    ip += 1; continue
            if python_block_lines:
                if line.startswith('!'): python_block_lines.append(line[1:]); ip += 1; continue
                else:
                    full_code = '\n'.join(python_block_lines)
                    try: exec(full_code, {'__builtins__': __builtins__}, ctx.vars)
                    except Exception as e: raise VulError(f"Python error: {e}", line=self.current_line - len(python_block_lines))
                    python_block_lines = []; continue
            if in_switch is not None:
                end_ip, delimiters = in_switch
                if ip in delimiters: ip = end_ip + 1; in_switch = None; continue
            try:
                m_assign = re.match(r'^([A-Za-z_]\w*)\s*=\s*(.+)$', line)
                if m_assign:
                    var_name = m_assign.group(1); expr_str = m_assign.group(2).strip()
                    val = evaluator.eval(expr_str); ctx.set_var(var_name, val); ip += 1; continue
                if re.match(r'^L\s+', line): ip += 1; continue
                if line.startswith('J'):
                    target = line[1:].strip()
                    if not target: raise VulError("Missing label after J", line=self.current_line)
                    if target not in self.labels: raise VulError(f"Undefined label '{target}'", line=self.current_line)
                    ip = self.labels[target]; continue
                if line.startswith('?'):
                    rest = line[1:].strip()
                    m = re.match(r'^(.+?)\s+J\s+(\S+)$', rest)
                    if m:
                        cond_str, label = m.group(1), m.group(2)
                        if label not in self.labels: raise VulError(f"Undefined label '{label}'", line=self.current_line)
                        if evaluator.eval(cond_str): ip = self.labels[label]; continue
                        else: ip += 1; continue
                    cond_str = rest
                    if evaluator.eval(cond_str):
                        control_stack.append(('if', None)); ip += 1; continue
                    else:
                        depth = 1; ip += 1
                        while ip < len(lines) and depth > 0:
                            cur = lines[ip]
                            if cur.startswith('?'): depth += 1
                            elif cur == ';': depth -= 1
                            elif cur == ':' and depth == 1: break
                            ip += 1
                        if depth == 0: continue
                        control_stack.append(('if', None)); ip += 1; continue
                if line == ':':
                    depth = 1; ip += 1
                    while ip < len(lines) and depth > 0:
                        cur = lines[ip]
                        if cur.startswith('?'): depth += 1
                        elif cur == ';': depth -= 1
                        ip += 1
                    continue
                if line == ';':
                    if control_stack and control_stack[-1][0] == 'if': control_stack.pop()
                    ip += 1; continue
                if line.startswith('@'):
                    cond_str = line[1:].strip()
                    cond = evaluator.eval(cond_str)
                    if not cond:
                        depth = 1; ip += 1
                        while ip < len(lines) and depth > 0:
                            cur = lines[ip]
                            if cur.startswith('@'): depth += 1
                            elif cur == '&': depth -= 1
                            ip += 1
                        continue
                    else:
                        control_stack.append(('while', ip)); ip += 1; continue
                if line == '&':
                    if not control_stack: raise VulError("& without @ or O", line=self.current_line)
                    typ, data = control_stack[-1]
                    if typ == 'while': ip = data; continue
                    elif typ == 'for':
                        start_ip, var, end_val, step = data
                        cur_val = ctx.get_var(var); new_val = cur_val + step; ctx.set_var(var, new_val)
                        if (step > 0 and new_val < end_val) or (step < 0 and new_val > end_val):
                            ip = start_ip + 1; continue
                        else: control_stack.pop(); ip += 1; continue
                    else: raise VulError("Unknown loop type", line=self.current_line)
                if line.startswith('R'):
                    val = evaluator.eval(line[1:].strip()); ctx.returned = True; ctx.return_val = val; return
                if line.startswith('F'):
                    m = re.match(r'^F\s*([A-Za-z_]\w*)\s*\(([^)]*)\)\s*$', line)
                    if not m: raise VulError(f"Invalid function definition: {line}", line=self.current_line)
                    fname = m.group(1); params = [p.strip() for p in m.group(2).split(',') if p.strip()]
                    start_body = ip + 1; end_ip = start_body
                    while end_ip < len(lines) and lines[end_ip] != '~': end_ip += 1
                    if end_ip >= len(lines): raise VulError(f"Function '{fname}' not terminated with '~'", line=self.current_line)
                    body = lines[start_body:end_ip]; func = VulFunction(fname, params, body, self); ctx.set_var(fname, func)
                    ip = end_ip + 1; continue
                if line == '~': return
                if line.startswith('U'):
                    mod = line[1:].strip()
                    if mod.startswith('"') and mod.endswith('"'): mod = mod[1:-1]
                    self.do_import(mod, ctx); ip += 1; continue
                if line.startswith('I'):
                    raise VulError(f"'I' command removed. Use var=expr instead.", line=self.current_line)
                if line.startswith('A'):
                    m = re.match(r'A\s*"([^"]*)"\s*([+\-*/])\s*(.*)', line)
                    if not m: raise VulError(f"Invalid arithmetic: {line}", line=self.current_line, tip="A \"var\" + value")
                    var_name, op, expr_str = m.group(1), m.group(2), m.group(3).strip()
                    val = evaluator.eval(expr_str); old = ctx.get_var(var_name)
                    if op == '+': new = old + val
                    elif op == '-': new = old - val
                    elif op == '*': new = old * val
                    elif op == '/': new = old / val
                    ctx.set_var(var_name, new); ip += 1; continue
                if line.startswith('S'):
                    m = re.match(r'S\s*"([^"]*)"\s*"([^"]*)"\s*"([^"]*)"', line)
                    if not m: raise VulError(f"Invalid replace: {line}", line=self.current_line, tip="S \"var\" \"old\" \"new\"")
                    var_name, old, new = m.group(1), m.group(2), m.group(3)
                    cur = str(ctx.get_var(var_name)); ctx.set_var(var_name, cur.replace(old, new)); ip += 1; continue
                if line.startswith('D') and not re.match(r'D\s*\d', line):
                    m_del = re.match(r'D\s*"([^"]*)"\s*$', line)
                    if m_del:
                        var_name = m_del.group(1)
                        if var_name in ctx.vars: del ctx.vars[var_name]
                        else: raise VulError(f"Variable '{var_name}' not found", line=self.current_line)
                        ip += 1; continue
                if re.match(r'^D\s*\d', line):
                    expr_str = line[1:].strip()
                    if expr_str: val = evaluator.eval(expr_str); time.sleep(val)
                    ip += 1; continue
                if line.startswith('K'):
                    m = re.match(r'K\s*"([^"]*)"\s*"([^"]*)"(?:\s*"([^"]*)")?', line)
                    if not m: raise VulError(f"Invalid input: {line}", line=self.current_line, tip='K "var" "prompt" "type"')
                    var_name, prompt, kind = m.group(1), m.group(2), m.group(3)
                    raw = input(prompt)
                    if kind is None: ctx.set_var(var_name, raw)
                    else:
                        default = 0 if kind in ("I","F","N") else ""
                        try:
                            if kind == "I": val = int(raw)
                            elif kind == "F": val = float(raw)
                            elif kind == "N":
                                val = float(raw)
                                if val == int(val): val = int(val)
                            elif kind == "L":
                                if len(raw)==1 and raw.isalpha(): val = raw
                                else: raise ValueError
                            elif kind == "W":
                                if raw.isalpha(): val = raw
                                else: raise ValueError
                            elif kind == "E":
                                if raw.isalpha() and raw==raw.lower(): val = raw
                                else: raise ValueError
                            elif kind == "U":
                                if raw.isalpha() and raw==raw.upper(): val = raw
                                else: raise ValueError
                            elif kind == "A":
                                if all(ch.isalpha() or ch.isspace() for ch in raw) and raw.strip(): val = raw
                                else: raise ValueError
                            elif kind == "P":
                                if all(ch.isalnum() or ch.isspace() for ch in raw) and raw.strip(): val = raw
                                else: raise ValueError
                            else: raise VulError(f"Unknown type character '{kind}'", line=self.current_line)
                            ctx.set_var(var_name, val)
                        except ValueError: ctx.set_var(var_name, default)
                    ip += 1; continue
                if line.startswith('X'):
                    filename = line[1:].strip().strip('"'); subprocess.Popen(["python", filename]); ip += 1; continue
                if line == 'Q': sys.exit(0)
                if line.startswith('E'):
                    msg = line[1:].strip(); print(f"Error: {msg}"); sys.exit(1)
                if line.startswith('P'):
                    expr_str = line[1:].strip()
                    if expr_str: print(evaluator.eval(expr_str), end='', flush=True)
                    ip += 1; continue
                if line.startswith('G'):
                    expr_str = line[1:].strip()
                    if expr_str: print(evaluator.eval(expr_str), flush=True)
                    ip += 1; continue
                if re.match(r'^T\s*$', line): try_stack.append(ip); ip += 1; continue
                if re.match(r'^C', line):
                    if not try_stack: raise VulError("C without T", line=self.current_line)
                    start_ip = try_stack[-1]; _, end_ip = self.try_blocks[start_ip]; ip = end_ip + 1; continue
                if re.match(r'^Y\s*$', line):
                    if not try_stack: raise VulError("Y without T", line=self.current_line)
                    try_stack.pop(); ip += 1; continue
                if line.startswith('W'):
                    expr_str = line[1:].strip(); switch_val = evaluator.eval(expr_str)
                    start_ip = ip; end_ip, delimiters = self.switch_blocks[start_ip]
                    i = start_ip + 1; matched = False
                    while i < end_ip:
                        cur_line = lines[i]
                        if cur_line.startswith('V'):
                            case_expr = cur_line[1:].strip(); case_val = evaluator.eval(case_expr)
                            if case_val == switch_val: in_switch = (end_ip, delimiters); ip = i + 1; matched = True; break
                        elif cur_line.startswith('N'): in_switch = (end_ip, delimiters); ip = i + 1; matched = True; break
                        elif cur_line.startswith('W'): i = self.switch_blocks[i][0]
                        i += 1
                    if not matched: ip = end_ip + 1
                    continue
                if line.startswith('O'):
                    m_var = re.match(r'O\s*([A-Za-z_]\w*)\s+(.*)', line)
                    if not m_var: raise VulError(f"Invalid for loop: {line}", line=self.current_line, tip="O var start end [step]")
                    var_name = m_var.group(1); rest = m_var.group(2).strip()
                    parts = rest.split()
                    if len(parts) < 2: raise VulError("For loop requires start and end", line=self.current_line)
                    start_expr = parts[0]; end_expr = parts[1]; step_expr = parts[2] if len(parts) > 2 else '1'
                    start_val = evaluator.eval(start_expr); end_val = evaluator.eval(end_expr); step_val = evaluator.eval(step_expr)
                    ctx.set_var(var_name, start_val)
                    if (step_val > 0 and start_val < end_val) or (step_val < 0 and start_val > end_val):
                        control_stack.append(('for', (ip, var_name, end_val, step_val))); ip += 1; continue
                    else:
                        depth = 1; ip += 1
                        while ip < len(lines) and depth > 0:
                            cur = lines[ip]
                            if cur.startswith('O'): depth += 1
                            elif cur == '&': depth -= 1
                            ip += 1
                        continue
                if line.startswith('V') or line.startswith('N') or line == 'Z': ip += 1; continue
                if re.match(r'^\$[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\(', line):
                    evaluator.eval(line); ip += 1; continue
                raise VulError(f"Unknown command: {line}", line=self.current_line, tip="Valid: G P A S D K X Q E U ? : ; @ & L J F R ~ T C Y O W V N Z")
            except Exception as e:
                if not try_stack: raise
                for start_ip in reversed(try_stack):
                    catch_ip, _ = self.try_blocks.get(start_ip, (None, None))
                    if catch_ip is not None:
                        var_match = re.match(r'C\s*"([^"]*)"', lines[catch_ip])
                        if var_match: ctx.set_var(var_match.group(1), str(e))
                        ip = catch_ip + 1; break
                else: raise
    def do_import(self, name, ctx):
        if name.endswith('.vul'):
            try:
                with open(name, 'r') as f: source = f.read()
            except FileNotFoundError: raise VulError(f"Vul file '{name}' not found", line=self.current_line, tip="Make sure the .vul file is in the same folder.")
            sub = VulInterpreter(); sub.global_ctx = ctx; sub.interpret(source)
        else:
            try: mod = importlib.import_module(name); ctx.set_var(name, mod)
            except ImportError: raise VulError(f"Python module '{name}' not found", line=self.current_line, tip="Install it with pip.")
'''
def main():
    parser = argparse.ArgumentParser(description="Build standalone Vul EXE")
    parser.add_argument("vul_file", help="The .vul file to compile")
    parser.add_argument("--name", default="vul_app", help="Output EXE name")
    parser.add_argument("--icon", help="Icon file (.ico)")
    parser.add_argument("--console", action="store_true", default=True)
    parser.add_argument("--onefile", action="store_true", default=True)
    args = parser.parse_args()
    if not os.path.exists(args.vul_file):
        print(f"Error: {args.vul_file} not found")
        sys.exit(1)
    with open(args.vul_file, 'r', encoding='utf-8') as f:
        source = f.read()
    encoded_source = base64.b64encode(source.encode('utf-8')).decode('ascii')
    launcher = f'''
import sys, os, tempfile, base64

# ---- Embedded Vul Interpreter ----
{VUL_CODE}

# ---- Decode and run the user's Vul program ----
source = base64.b64decode("{encoded_source}").decode("utf-8")
with tempfile.NamedTemporaryFile(mode='w', suffix='.vul', delete=False) as f:
    f.write(source)
    tmp_path = f.name
try:
    interpreter = VulInterpreter()
    with open(tmp_path, 'r') as f:
        code = f.read()
    interpreter.interpret(code)
finally:
    os.unlink(tmp_path)
'''
    with open("_launcher.py", 'w', encoding='utf-8') as f:
        f.write(launcher)
    cmd = ["pyinstaller"]
    if args.onefile:
        cmd.append("--onefile")
    if args.icon:
        cmd.extend(["--icon", args.icon])
    if not args.console:
        cmd.append("--windowed")
    cmd.extend(["--name", args.name, "_launcher.py"])
    print(f"Building '{args.name}.exe'...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    if os.path.exists("_launcher.py"):
        os.remove("_launcher.py")
    if result.returncode == 0:
        print(f"🦊✅ '{args.name}.exe' created in dist/ folder")
    else:
        print("🦊❌ Build failed. Check errors above.")
if __name__ == "__main__":
    main()
