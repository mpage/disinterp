import argparse
import re
import subprocess
import sys


from dataclasses import dataclass
from typing import Callable, List, NamedTuple, Optional, Set

SYMBOL_TABLE_START = "SYMBOL TABLE:"
LINE_RE = r"^([^:]+):(\d+)"
JMP_RE = r"^jmp\s+"
DISPATCH_RE = r"^\s+DISPATCH\(\);"
GENERATED_CASES = "generated_cases.c.h"
TARGET_RE = r"^\s+TARGET\(([A-Za-z0-9_]+)\)"
END_INSTRUCTIONS_RE = r"^\s+/\* END INSTRUCTIONS"


class SrcLoc(NamedTuple):
    path: str
    lineno: int

    def __str__(self) -> str:
        return f"{self.path}:{self.lineno}"


@dataclass
class Instr:
    addr: str
    disas: str
    src_loc: Optional[SrcLoc] = None


class SrcCache:
    def __init__(self):
        self.src: Dict[str, List[str]] = {}

    def cache_src(self, path: str) -> None:
        try:
            with open(path) as f:
                data = f.read()
                self.src[path] = data.splitlines()
        except FileNotFoundError:
            self.src[path] = []

    def get(self, loc: SrcLoc) -> str:
        if loc.path not in self.src:
            self.cache_src(loc.path)
        lines = self.src[loc.path]
        if loc.lineno > len(lines):
            return str(loc)
        return lines[loc.lineno - 1]


def make_func_start_re(func: str):
    return r"^[\da-f]+\s+<" + func + r">:$"


def parse_instrs(interp_path: str, func: str) -> List[Instr]:
    cmd = [
        "objdump",
        f"--disassemble={func}",
        "--no-show-raw-insn",
        interp_path,
    ]
    out = subprocess.check_output(cmd, encoding="utf-8")
    in_func = False
    instrs = []
    regex = make_func_start_re(func)
    for line in out.splitlines():
        if in_func:
            if not line:
                break
            else:
                addr, disas = line.split(":", maxsplit=1)
                instrs.append(Instr(addr.strip(), disas.strip()))
        else:
            in_func = bool(re.match(regex, line))
    return instrs


def get_interp_loop_syms(interp_path: str) -> List[str]:
    out = subprocess.check_output(["objdump", "--syms", interp_path], encoding="utf-8")
    syms = []
    in_sym_tab = False
    for line in out.splitlines():
        if not line:
            continue
        if in_sym_tab:
            parts = line.split()
            sym = parts[-1]
            if sym.startswith("_PyEval_EvalFrameDefault"):
                syms.append(sym)
        else:
            in_sym_tab = (line == SYMBOL_TABLE_START)
    return syms


def add_src_locs(interp_path: str, instrs: List[Instr], replace_src_path: Callable[[str], str]) -> None:
    addrs = "\n".join(i.addr for i in instrs)
    out = subprocess.check_output(["addr2line", "-e", interp_path], encoding="utf-8", input=addrs)
    lines = out.splitlines()
    for i, instr in enumerate(instrs):
        matches = re.match(LINE_RE, lines[i])
        if matches:
            path = replace_src_path(matches.group(1))
            instr.src_loc = SrcLoc(path, int(matches.group(2)))


@dataclass
class OpcodeRange:
    opcode: str
    start: int
    end: int

    def contains(self, lineno: int) -> bool:
        return (self.start <= lineno) and (lineno <= self.end)

    def __str__(self) -> str:
        return f"{self.opcode} {self.start} {self.end}"


class InstrAndLinePrinter:
    def __init__(self, src: SrcCache) -> None:
        self.src = src
        self.last_loc: Optiona[SrcLoc] = None
        self.opcode_ranges: List[OpcodeRange] = []

    def init_opcode_ranges(self, path: str) -> None:
        # Should really use a parser here...
        last_range: Optional[OpcodeRange] = None
        with open(path) as f:
            for i, line in enumerate(f.readlines()):
                if matches := re.match(TARGET_RE, line):
                    if last_range is not None:
                        last_range.end = i
                        self.opcode_ranges.append(last_range)
                    last_range = OpcodeRange(matches.group(1), i + 1, 0)
                elif matches := re.match(END_INSTRUCTIONS_RE, line):
                    break

        if last_range is not None:
            last_range.end = i
            self.opcode_ranges.append(last_range)

    def get_opcode(self, src_loc: SrcLoc) -> Optional[str]:
        if not src_loc.path.endswith(GENERATED_CASES):
            return None
        if not self.opcode_ranges:
            self.init_opcode_ranges(src_loc.path)
        for r in self.opcode_ranges:
            if r.contains(src_loc.lineno):

                return r.opcode
        return None

    def print(self, instr: Instr) -> None:
        if instr.src_loc != self.last_loc:
            print()
            opcode = self.get_opcode(instr.src_loc)
            print(f"{instr.src_loc} [{opcode}]")
            print(self.src.get(instr.src_loc))
            print()
            self.last_loc = instr.src_loc
        print(f"{instr.addr:>16}: {instr.disas}")


def dump_sym(sym: str, instrs: List[Instr]) -> None:
    print(f"{sym}:")
    last_loc = None
    src = SrcCache()
    printer = InstrAndLinePrinter(src)
    for instr in instrs:
        printer.print(instr)


def dump_dispatch(sym: str, instrs: List[Instr]) -> None:
    print(f"{sym}:")
    src = SrcCache()
    in_dispatch = False
    printer = InstrAndLinePrinter(src)
    for instr in instrs:
        if in_dispatch:
            printer.print(instr)
            in_dispatch = not bool(re.match(JMP_RE, instr.disas))
        else:
            line = src.get(instr.src_loc)
            if re.match(DISPATCH_RE, line) and instr.disas != "endbr64":
                printer.print(instr)
                in_dispatch = True


def main(interp_path: str, dispatch_only: bool, replace_src_path: Callable[[str], str]) -> None:
    syms = get_interp_loop_syms(interp_path)
    for sym in syms:
        instrs = parse_instrs(interp_path, sym)
        add_src_locs(interp_path, instrs, replace_src_path)
        if dispatch_only:
            dump_dispatch(sym, instrs)
        else:
            dump_sym(sym, instrs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Disassemble CPython's interpreter loop"
    )
    parser.add_argument("--dispatch-only", default=False, action="store_true",
                        help="Only disassemble DISPATCH() statements")
    parser.add_argument("--replace-src", default=None,
                        help="A string like 'orig_path,new_path'."
                             " Replace 'orig_path' with 'new_path' before reading source files.")
    parser.add_argument("interp_path", help="Path to the python binary")
    args = parser.parse_args()
    if args.replace_src is not None:
        orig, replacement = args.replace_src.split(",")
        def path_replacer(path):
            return path.replace(orig, replacement)
    else:
        def path_replacer(path):
            return path
    try:
        main(args.interp_path, args.dispatch_only, path_replacer)
    except subprocess.CalledProcessError as cpe:
        print(f"ERROR: Failed running {cpe.cmd} (status {cpe.returncode})", file=sys.stderr)
        print("stdout:", file=sys.stderr)
        print(cpe.stdout, file=sys.stderr)
        print("stderr:", file=sys.stderr)
        print(cpe.stderr, file=sys.stderr)
