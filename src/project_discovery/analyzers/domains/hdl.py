"""Hardware description languages, FPGA constraints and FPGA projects.

Verilog and SystemVerilog modules, interfaces and packages, VHDL entities, architectures
and packages are read from text with comments, strings and attributes blanked (linear
scans). Per design unit PDT records ports, parameters, child instances, clock and reset
edges, and testbench markers; the code index joins instances across files into the
design hierarchy (top-level units, depth, unresolved vendor primitives or IP).

Lint findings: blocking assignments in clocked always blocks, non-blocking assignments in
combinational blocks, multiple clocks in one unit and the non-standard Synopsys
``std_logic_arith``/``std_logic_unsigned`` packages. Constraint files (XDC/SDC, UCF,
QSF, PCF, LPF, CST) give clocks, pin assignments and I/O standards; project files (Vivado
``.xpr``, ISE ``.xise``, Quartus, Lattice Diamond, FuseSoC ``.core``, apio) give the
target device family.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path, PurePosixPath

from ...core.source_utils import SourceBudgetExceeded, read_text_bounded
from ...intelligence import facts as code_facts
from ...models import FileRecord, Finding
from ..base import Analyzer

MAX_HDL_BYTES = 8 * 1024 * 1024
MAX_UNITS = 2000
_NON_NEWLINE = re.compile(r"[^\n]")
_VERILOG_NOISE = re.compile(
    r"//[^\n]*+|/\*(?:[^*]|\*(?!/))*+(?:\*/)?|\"(?:[^\"\\\n]|\\.)*+\"?|\(\*(?![)])(?:[^*]|\*(?!\)))*+(?:\*\))?"
)
_VHDL_NOISE = re.compile(r"--[^\n]*+|/\*(?:[^*]|\*(?!/))*+(?:\*/)?|\"(?:[^\"\n]|\"\")*+\"?|(?<![\w)])'.'")
_VERILOG_UNIT = re.compile(
    r"(?<![\w$`])(module|macromodule|interface|program|package|checker)[ \t\r\n]++"
    r"(?:(?:automatic|static)[ \t\r\n]++)?([A-Za-z_][\w$]*+)"
)
_VERILOG_END = re.compile(r"(?<![\w$])end(?:module|interface|program|package|checker)\b")
_PORT_DIRECTION = re.compile(r"(?<![\w$])(input|output|inout|ref)\b")
_PORT_STATEMENT = re.compile(r"(?m)(?<![\w$])(input|output|inout)\b([^;()]{0,2000}+);")
_PARAMETER = re.compile(
    r"(?<![\w$])(?:parameter|localparam)\b(?:[ \t\r\n]++(?:int|integer|real|bit|logic|string|signed|unsigned|"
    r"type|longint|shortint|byte|\[[^\]\n]{0,60}+\]))*+[ \t\r\n]++([A-Za-z_][\w$]*+)"
)
_STATEMENT_HEAD = re.compile(r"(?:^|(?<=[;\n])|(?<=\bbegin)|(?<=\bend)|(?<=endgenerate))[ \t\r]*+([A-Za-z_][\w$]*+)"
                             r"[ \t\r\n]*+(#)?")
_INSTANCE_NAME = re.compile(r"[ \t\r\n]*+([A-Za-z_][\w$]*+)[ \t\r\n]*+(?:\[[^\]\n]{0,80}+\][ \t\r\n]*+)?\(")
_ALWAYS = re.compile(r"(?<![\w$])(always_ff|always_comb|always_latch|always)\b[ \t\r\n]*+(@[ \t\r\n]*+(?:\*|\(([^()]{0,400}+)\)))?")
_EDGE = re.compile(r"(posedge|negedge)[ \t\r\n]++([A-Za-z_][\w$.]*+)")
_BEGIN_END = re.compile(r"(?<![\w$])(begin|end|case|casex|casez|casez|endcase|fork|join|join_any|join_none)\b")
_BLOCKING = re.compile(r"(?:^|(?<=[;\n:])|(?<=\bbegin)|(?<=\belse)|(?<=\)))[ \t\r]*+([A-Za-z_][\w$.]*+(?:\[[^\]\n]{0,60}+\])?)"
                       r"[ \t]*+=(?!=)")
_NONBLOCKING = re.compile(r"(?:^|(?<=[;\n])|(?<=\bbegin)|(?<=\belse)|(?<=\)))[ \t\r]*+([A-Za-z_][\w$.]*+(?:\[[^\]\n]{0,60}+\])?)"
                          r"[ \t]*+<=")
_FOR_HEADER = re.compile(r"(?<![\w$])for[ \t\r\n]*+\(")
_TESTBENCH_NAME = re.compile(r"(?i)(?:^tb_|_tb$|^tb$|^test_|_test$|testbench|_tb_)")
_TESTBENCH_BODY = re.compile(r"\$(?:finish|stop|dumpfile|dumpvars|display|monitor)\b|(?<![\w$])initial\b[^;]{0,200}?#[ \t]*+\d")
_RESET_NAME = re.compile(r"(?i)rst|reset|clr|clear")
_KEYWORDS = frozenset("""
always always_ff always_comb always_latch assign initial final wire reg logic input output inout ref parameter
localparam integer real realtime time genvar generate endgenerate if else for foreach while repeat forever case casex
casez endcase begin end function endfunction task endtask module endmodule typedef struct union enum import export
assert assume cover property sequence bit byte int shortint longint string var return default defparam specify
endspecify tri tri0 tri1 wand wor supply0 supply1 signed unsigned packed const static automatic interface
endinterface modport clocking endclocking class endclass package endpackage program endprogram virtual extends
fork join join_any join_none disable wait event force release deassign unique priority void chandle let constraint
covergroup endgroup bind alias config endconfig primitive endprimitive table endtable specparam
""".split())
_PRIMITIVES = frozenset("and or nand nor xor xnor not buf bufif0 bufif1 notif0 notif1 pullup pulldown tran tranif0 "
                        "tranif1 rtran nmos pmos cmos rnmos rpmos".split())

_VHDL_ENTITY = re.compile(r"(?i)(?<![\w])entity[ \t\r\n]++([A-Za-z]\w*+)[ \t\r\n]++is\b")
_VHDL_ARCHITECTURE = re.compile(r"(?i)(?<![\w])architecture[ \t\r\n]++(\w++)[ \t\r\n]++of[ \t\r\n]++(\w++)[ \t\r\n]++is\b")
_VHDL_PACKAGE = re.compile(r"(?i)(?<![\w])package[ \t\r\n]++(?!body\b)(\w++)[ \t\r\n]++is\b")
_VHDL_ENTITY_INSTANCE = re.compile(
    r"(?i)(?<![\w])(\w++)[ \t\r\n]*+:[ \t\r\n]*+entity[ \t\r\n]++(?:(\w++)\.)?(\w++)"
)
_VHDL_COMPONENT_INSTANCE = re.compile(
    r"(?i)(?<![\w])(\w++)[ \t\r\n]*+:[ \t\r\n]*+(?:component[ \t\r\n]++)?(\w++)[ \t\r\n]++(?:generic|port)[ \t\r\n]++map\b"
)
_VHDL_PORT = re.compile(r"(?i)(?<![\w])port[ \t\r\n]*+\(")
_VHDL_PORT_ITEM = re.compile(r"(?i)^[ \t\r\n]*+([\w, \t\r\n]{1,400}+):[ \t\r\n]*+(in|out|inout|buffer|linkage)\b")
_VHDL_CLOCK = re.compile(r"(?i)(?:rising_edge|falling_edge)[ \t]*+\([ \t]*+(\w++)[ \t]*+\)|(?<!\w)(\w++)'event\b")
_VHDL_PROCESS = re.compile(r"(?i)(?<![\w])process\b")
_VHDL_NONSTANDARD = re.compile(r"(?i)\buse[ \t]++ieee\.(std_logic_arith|std_logic_unsigned|std_logic_signed)\b")

_PART_FAMILIES = (
    (re.compile(r"(?i)^xc7a"), "Xilinx Artix-7"), (re.compile(r"(?i)^xc7k"), "Xilinx Kintex-7"),
    (re.compile(r"(?i)^xc7v"), "Xilinx Virtex-7"), (re.compile(r"(?i)^xc7z"), "Xilinx Zynq-7000"),
    (re.compile(r"(?i)^xc7s"), "Xilinx Spartan-7"), (re.compile(r"(?i)^xc6s"), "Xilinx Spartan-6"),
    (re.compile(r"(?i)^xc3s"), "Xilinx Spartan-3"), (re.compile(r"(?i)^xczu"), "Xilinx Zynq UltraScale+"),
    (re.compile(r"(?i)^xcku"), "Xilinx Kintex UltraScale"), (re.compile(r"(?i)^xcvu"), "Xilinx Virtex UltraScale"),
    (re.compile(r"(?i)^xcau"), "Xilinx Artix UltraScale+"), (re.compile(r"(?i)^xcv[ce]"), "AMD Versal"),
    (re.compile(r"(?i)^5c[se]"), "Intel Cyclone V"), (re.compile(r"(?i)^10m"), "Intel MAX 10"),
    (re.compile(r"(?i)^10cl"), "Intel Cyclone 10 LP"), (re.compile(r"(?i)^10cx"), "Intel Cyclone 10 GX"),
    (re.compile(r"(?i)^10a"), "Intel Arria 10"), (re.compile(r"(?i)^1s[gxm]"), "Intel Stratix 10"),
    (re.compile(r"(?i)^ag[fim]"), "Intel Agilex"), (re.compile(r"(?i)^ep4ce"), "Intel Cyclone IV E"),
    (re.compile(r"(?i)^ep4cgx"), "Intel Cyclone IV GX"), (re.compile(r"(?i)^5m"), "Intel MAX V"),
    (re.compile(r"(?i)^(?:ice40|ice5lp|ice40up|up5k|hx[148]k|lp[148]k)"), "Lattice iCE40"),
    (re.compile(r"(?i)^lfe5"), "Lattice ECP5"), (re.compile(r"(?i)^lcmxo"), "Lattice MachXO"),
    (re.compile(r"(?i)^lifcl"), "Lattice CrossLink-NX"), (re.compile(r"(?i)^lfcpnx"), "Lattice CertusPro-NX"),
    (re.compile(r"(?i)^gw[125]"), "Gowin"), (re.compile(r"(?i)^mpf"), "Microchip PolarFire"),
    (re.compile(r"(?i)^m2s"), "Microchip SmartFusion2"), (re.compile(r"(?i)^m2gl"), "Microchip IGLOO2"),
    (re.compile(r"(?i)^a3p"), "Microsemi ProASIC3"),
)
_CONSTRAINT_SUFFIXES = (".xdc", ".sdc", ".ucf", ".qsf", ".pcf", ".lpf", ".cst")
_PROJECT_SUFFIXES = (".xpr", ".xise", ".qpf", ".ldf", ".core")


def _family(part: str) -> str:
    return next((name for pattern, name in _PART_FAMILIES if pattern.match(part.strip())), "")


def _blank(pattern: re.Pattern, text: str) -> str:
    return pattern.sub(lambda match: _NON_NEWLINE.sub(" ", match.group()), text)


def _pairs(text: str, opening: str = "(", closing: str = ")") -> dict[int, int]:
    pairs, stack = {}, []
    for index, char in enumerate(text):
        if char == opening:
            stack.append(index)
        elif char == closing and stack:
            pairs[stack.pop()] = index
    return pairs


def _split_depth(text: str, separator: str) -> list[str]:
    parts, depth, start = [], 0, 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def _identifiers(text: str) -> list[str]:
    cleaned = re.sub(r"\[[^\]\n]{0,80}+\]", " ", text)
    return [word for word in re.findall(r"(?<![\w$'])[A-Za-z_][\w$]*+", cleaned) if word not in _KEYWORDS]


def _hdl_kind(record: FileRecord) -> str | None:
    lower = PurePosixPath(record.path.replace("\\", "/")).name.lower()
    if record.language in {"Verilog", "SystemVerilog", "V / Verilog (ambiguous)"}:
        return "verilog"
    if record.language == "VHDL":
        return "vhdl"
    if lower.endswith(_CONSTRAINT_SUFFIXES):
        return "constraints"
    if lower.endswith(_PROJECT_SUFFIXES) or lower == "apio.ini":
        return "project"
    return None


class HardwareDescriptionAnalyzer(Analyzer):
    name = "hdl"
    version = "1.0.0"
    description = ("Verilog/SystemVerilog/VHDL design units, ports, instances, clocks and RTL lint; FPGA constraints "
                   "and project targets.")
    domains = ("hardware_description",)

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.content_skipped_reason is None and _hdl_kind(record) is not None

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.size_bytes > MAX_HDL_BYTES:
            return []
        try:
            text = read_text_bounded(path, MAX_HDL_BYTES, errors="replace", expected_identity=record.analysis_identity)
        except (OSError, SourceBudgetExceeded):
            return []
        kind = _hdl_kind(record)
        if kind == "verilog":
            return self._verilog(record, text)
        if kind == "vhdl":
            return self._vhdl(record, text)
        if kind == "constraints":
            return self._constraints(record, text)
        return self._project(record, text)

    def _finding(self, record, title, detail, *, lines=(), severity="INFO", confidence="CONFIRMED",
                 recommendation=None) -> Finding:
        evidence = [f"{record.path}:{line}" for line in sorted(set(lines))[:25]] or [record.path]
        return Finding("hardware_description", f"{title}: {record.path}", detail, confidence=confidence,
                       evidence=evidence, analyzer=self.name, severity=severity, recommendation=recommendation)

    # -- Verilog / SystemVerilog -------------------------------------------------------
    def _verilog(self, record: FileRecord, text: str) -> list[Finding]:
        clean = _blank(_VERILOG_NOISE, text)
        if record.language == "V / Verilog (ambiguous)" and not re.search(r"(?<![\w$])endmodule\b", clean):
            return []

        def line_of(offset: int) -> int:
            return clean.count("\n", 0, offset) + 1

        parens = _pairs(clean)
        units, blocking, nonblocking, multi_clock = [], [], [], []
        for match in list(_VERILOG_UNIT.finditer(clean))[:MAX_UNITS]:
            kind, name = match.group(1), match.group(2)
            end_match = _VERILOG_END.search(clean, match.end())
            end = end_match.start() if end_match else len(clean)
            header_end = clean.find(";", match.end(), end)
            header_end = end if header_end == -1 else header_end
            body = clean[header_end + 1:end]
            ports = self._verilog_ports(clean, match.end(), header_end, body, parens)
            parameters = _PARAMETER.findall(clean, match.end(), end)
            children = Counter()
            primitives = 0
            for head in _STATEMENT_HEAD.finditer(clean, header_end + 1, end):
                type_name = head.group(1)
                if type_name in _KEYWORDS:
                    continue
                position = head.end()
                if head.group(2):
                    opening = clean.find("(", position - 1, position + 2)
                    close = parens.get(opening)
                    if close is None:
                        continue
                    position = close + 1
                instance = _INSTANCE_NAME.match(clean, position)
                if not instance or instance.group(1) in _KEYWORDS:
                    continue
                if type_name in _PRIMITIVES:
                    primitives += 1
                else:
                    children[type_name] += 1
            clocks, resets = Counter(), Counter()
            for always in _ALWAYS.finditer(clean, header_end + 1, end):
                block_kind, sensitivity = always.group(1), always.group(3) or ""
                edges = _EDGE.findall(sensitivity)
                start = always.end()
                stop = self._block_end(clean, start, end)
                region = clean[start:stop]
                sequential = bool(edges) or block_kind == "always_ff"
                combinational = block_kind == "always_comb" or (block_kind == "always" and (
                    always.group(2) or "").replace(" ", "") in {"@*", "@(*)"})
                for index, (edge, signal) in enumerate(edges):
                    if index and _RESET_NAME.search(signal) or (edge == "negedge" and _RESET_NAME.search(signal)):
                        resets[signal] += 1
                    else:
                        clocks[signal] += 1
                if sequential:
                    loops = [(opening, parens.get(opening, opening)) for opening in
                             (m.end() - 1 for m in _FOR_HEADER.finditer(region))]
                    for assignment in _BLOCKING.finditer(region):
                        if any(start_ <= assignment.start() <= stop_ for start_, stop_ in loops):
                            continue
                        blocking.append(line_of(start + assignment.start(1)))
                elif combinational:
                    nonblocking.extend(line_of(start + item.start(1)) for item in _NONBLOCKING.finditer(region))
            testbench = bool(_TESTBENCH_NAME.search(name) or (kind == "module" and _TESTBENCH_BODY.search(body)))
            if len(clocks) > 1 and not testbench:
                multi_clock.append((name, line_of(match.start()), sorted(clocks)))
            units.append((kind, name, line_of(match.start()), ports, parameters, children, primitives, clocks,
                          resets, testbench))
            code_facts.emit_fact("hdl_module", name, kind=kind, language=record.language, testbench=int(testbench),
                                 ports=len(ports), line=line_of(match.start()), clocks=sorted(clocks)[:8])
            for child, count in sorted(children.items())[:500]:
                code_facts.emit_fact("hdl_instance", child, parent=name, count=count)
        return self._unit_findings(record, units, blocking, nonblocking, multi_clock, [])

    def _verilog_ports(self, clean, start, header_end, body, parens) -> list[tuple[str, str]]:
        ports: list[tuple[str, str]] = []
        header = clean[start:header_end]
        position = 0
        if header.lstrip().startswith("#"):
            opening = clean.find("(", start)
            close = parens.get(opening)
            position = (close + 1 - start) if close is not None and close < header_end else 0
        opening = header.find("(", position)
        if opening != -1:
            close = parens.get(start + opening)
            if close is not None:
                direction = ""
                for item in _split_depth(clean[start + opening + 1:close], ","):
                    found = _PORT_DIRECTION.search(item)
                    if found:
                        direction = found.group(1)
                    names = _identifiers(_PORT_DIRECTION.sub(" ", item))
                    if names:
                        ports.append((direction or "?", names[-1]))
        if ports and all(direction == "?" for direction, _ in ports):
            declared = {}
            for direction, names in _PORT_STATEMENT.findall(body):
                for part in _split_depth(names, ","):
                    words = _identifiers(part)
                    if words:
                        declared[words[-1]] = direction
            ports = [(declared.get(name, "?"), name) for _, name in ports]
        return ports

    @staticmethod
    def _block_end(clean: str, start: int, limit: int) -> int:
        """End of the statement or begin/end block that starts at ``start``."""
        head = re.match(r"[ \t\r\n]*+(begin|fork|case|casex|casez)\b", clean[start:start + 400])
        if not head:
            stop = clean.find(";", start, limit)
            return limit if stop == -1 else stop + 1
        depth = 0
        for token in _BEGIN_END.finditer(clean, start, limit):
            word = token.group(1)
            if word in {"begin", "case", "casex", "casez", "fork"}:
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    return token.end()
        return limit

    # -- VHDL -------------------------------------------------------------------------------
    def _vhdl(self, record: FileRecord, text: str) -> list[Finding]:
        clean = _blank(_VHDL_NOISE, text)

        def line_of(offset: int) -> int:
            return clean.count("\n", 0, offset) + 1

        parens = _pairs(clean)
        units = []
        entities = {}
        for match in list(_VHDL_ENTITY.finditer(clean))[:MAX_UNITS]:
            name = match.group(1)
            port = _VHDL_PORT.search(clean, match.end(), match.end() + 20000)
            ports = []
            if port:
                close = parens.get(port.end() - 1)
                if close is not None:
                    for item in _split_depth(clean[port.end():close], ";"):
                        declared = _VHDL_PORT_ITEM.match(item)
                        if declared:
                            for port_name in declared.group(1).split(","):
                                if port_name.strip():
                                    ports.append((declared.group(2).lower(), port_name.strip()))
            entities[name.lower()] = (name, line_of(match.start()), ports)
        architectures = list(_VHDL_ARCHITECTURE.finditer(clean))
        bodies = {}
        for index, match in enumerate(architectures):
            end = architectures[index + 1].start() if index + 1 < len(architectures) else len(clean)
            bodies.setdefault(match.group(2).lower(), []).append((match.end(), end))
        for key, (name, line, ports) in entities.items():
            children, clocks = Counter(), Counter()
            processes = 0
            for start, end in bodies.get(key, []):
                region = clean[start:end]
                for instance in _VHDL_ENTITY_INSTANCE.finditer(region):
                    children[instance.group(3).lower()] += 1
                for instance in _VHDL_COMPONENT_INSTANCE.finditer(region):
                    if instance.group(2).lower() not in {"entity", "process", "block", "generate"}:
                        children[instance.group(2).lower()] += 1
                processes += len(_VHDL_PROCESS.findall(region))
                for clock in _VHDL_CLOCK.finditer(region):
                    clocks[(clock.group(1) or clock.group(2)).lower()] += 1
            testbench = bool(_TESTBENCH_NAME.search(name)) or (not ports and bool(re.search(
                r"(?i)\bwait[ \t]++for\b|\breport\b|\bassert\b", clean)))
            units.append(("entity", name, line, ports, [], children, 0, clocks, Counter(), testbench))
            code_facts.emit_fact("hdl_module", name.lower(), kind="entity", language="VHDL", testbench=int(testbench),
                                 ports=len(ports), line=line, clocks=sorted(clocks)[:8], processes=processes)
            for child, count in sorted(children.items())[:500]:
                code_facts.emit_fact("hdl_instance", child, parent=name.lower(), count=count)
        for match in _VHDL_PACKAGE.finditer(clean):
            units.append(("package", match.group(1), line_of(match.start()), [], [], Counter(), 0, Counter(),
                          Counter(), False))
        multi_clock = [(name, line, sorted(clocks)) for kind, name, line, _, _, _, _, clocks, _, testbench in units
                       if len(clocks) > 1 and not testbench]
        nonstandard = [(match.group(1).lower(), line_of(match.start())) for match in _VHDL_NONSTANDARD.finditer(clean)]
        return self._unit_findings(record, units, [], [], multi_clock, nonstandard)

    # -- shared reporting --------------------------------------------------------------
    def _unit_findings(self, record, units, blocking, nonblocking, multi_clock, nonstandard) -> list[Finding]:
        if not units:
            return []
        described = []
        for kind, name, _line, ports, parameters, children, primitives, clocks, resets, testbench in units[:20]:
            parts = [f"{kind} {name}"]
            if ports:
                directions = Counter(direction for direction, _ in ports)
                parts.append(f"{len(ports)} port(s) (" + ", ".join(f"{count} {key}" for key, count in sorted(directions.items())) + ")")
            if parameters:
                parts.append(f"{len(parameters)} parameter(s)")
            if children:
                parts.append(f"{sum(children.values())} instance(s) of {len(children)} type(s)")
            if primitives:
                parts.append(f"{primitives} gate primitive(s)")
            if clocks:
                parts.append("clocks " + ", ".join(sorted(clocks)))
            if resets:
                parts.append("async resets " + ", ".join(sorted(resets)))
            if testbench:
                parts.append("testbench")
            described.append(" ".join(parts[:1]) + (": " + "; ".join(parts[1:]) if len(parts) > 1 else ""))
        findings = [self._finding(
            record, "HDL design units", f"{len(units)} design unit(s). " + " | ".join(described) + ".",
            lines=[line for _, _, line, *_ in units],
        )]
        if blocking:
            findings.append(self._finding(
                record, "Blocking assignment in clocked logic",
                "Blocking (=) assignments inside an edge-triggered always block make simulation depend on statement "
                "order and can differ from the synthesized flip-flops.", lines=blocking, severity="LOW",
                confidence="INFERRED", recommendation="Use non-blocking (<=) assignments for registers in sequential blocks.",
            ))
        if nonblocking:
            findings.append(self._finding(
                record, "Non-blocking assignment in combinational logic",
                "Non-blocking (<=) assignments in always_comb or always @(*) blocks delay updates by a delta cycle and "
                "cause simulation/synthesis mismatches.", lines=nonblocking, severity="LOW", confidence="INFERRED",
                recommendation="Use blocking (=) assignments in combinational blocks.",
            ))
        if multi_clock:
            findings.append(self._finding(
                record, "Multiple clock domains in one design unit",
                "; ".join(f"{name}: {', '.join(clocks[:6])}" for name, _, clocks in multi_clock[:10])
                + ". Signals crossing between these clocks need synchronizers or asynchronous FIFOs.",
                lines=[line for _, line, _ in multi_clock], severity="INFO", confidence="INFERRED",
            ))
        if nonstandard:
            findings.append(self._finding(
                record, "Non-standard IEEE arithmetic packages",
                f"Uses {', '.join(sorted({name for name, _ in nonstandard}))}: vendor (Synopsys) packages that are not "
                "part of the IEEE standard and conflict with numeric_std.", lines=[line for _, line in nonstandard],
                severity="LOW", recommendation="Use ieee.numeric_std with explicit signed/unsigned types.",
            ))
        return findings

    # -- constraints and projects ------------------------------------------------------
    def _constraints(self, record: FileRecord, text: str) -> list[Finding]:
        lower = record.path.lower()
        clocks: list[tuple[str, float | None]] = []
        pins: dict[str, str] = {}
        standards: dict[str, str] = {}
        exceptions = Counter()
        device = family = top = ""
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if lower.endswith((".xdc", ".sdc")):
                if line.startswith("create_clock"):
                    period = re.search(r"-period[ \t]++([\d.]{1,12}+)", line)
                    name = re.search(r"-name[ \t]++\{?([\w/\[\].-]{1,80}+)", line)
                    port = re.search(r"get_ports[ \t]++\{?[ \t]*+([\w/\[\].-]{1,80}+)", line)
                    clocks.append(((name or port).group(1) if (name or port) else "?",
                                   float(period.group(1)) if period else None))
                for match in re.finditer(r"PACKAGE_PIN[ \t]++(\w{1,12}+)", line):
                    for port in re.findall(r"get_ports[ \t]++\{?[ \t]*+([\w/\[\].-]{1,80}+)", line):
                        pins[port] = match.group(1)
                for match in re.finditer(r"IOSTANDARD[ \t]++(\w{1,24}+)", line):
                    for port in re.findall(r"get_ports[ \t]++\{?[ \t]*+([\w/\[\].-]{1,80}+)", line):
                        standards[port] = match.group(1)
                for keyword in ("set_false_path", "set_multicycle_path", "set_max_delay", "set_clock_groups"):
                    if line.startswith(keyword):
                        exceptions[keyword] += 1
            elif lower.endswith(".ucf"):
                net = re.match(r"(?i)NET[ \t]++\"?([\w<>\[\]/.-]{1,80}+)\"?[ \t]++LOC[ \t]*+=[ \t]*+\"?(\w{1,12}+)", line)
                if net:
                    pins[net.group(1)] = net.group(2)
                standard = re.search(r"(?i)IOSTANDARD[ \t]*+=[ \t]*+\"?(\w{1,24}+)", line)
                net_name = re.match(r"(?i)NET[ \t]++\"?([\w<>\[\]/.-]{1,80}+)", line)
                if standard and net_name:
                    standards[net_name.group(1)] = standard.group(1)
                period = re.search(r"(?i)PERIOD[ \t]*+=?[ \t]*+([\d.]{1,12}+)[ \t]*+ns", line)
                if period:
                    clocks.append((net_name.group(1) if net_name else "?", float(period.group(1))))
            elif lower.endswith(".qsf"):
                location = re.match(r"set_location_assignment[ \t]++(?:PIN_)?(\w{1,12}+)[ \t]++-to[ \t]++\"?([\w\[\]/.-]{1,80}+)", line)
                if location:
                    pins[location.group(2)] = location.group(1)
                setting = re.match(r"set_global_assignment[ \t]++-name[ \t]++(\w{1,60}+)[ \t]++\"?([^\"]{1,120}+)\"?", line)
                if setting:
                    key, value = setting.group(1).upper(), setting.group(2).strip()
                    device = value if key == "DEVICE" else device
                    family = value if key == "FAMILY" else family
                    top = value if key == "TOP_LEVEL_ENTITY" else top
                standard = re.match(r"set_instance_assignment[ \t]++-name[ \t]++IO_STANDARD[ \t]++\"([^\"]{1,40}+)\"[ \t]++-to[ \t]++"
                                    r"\"?([\w\[\]/.-]{1,80}+)", line)
                if standard:
                    standards[standard.group(2)] = standard.group(1)
            elif lower.endswith(".pcf"):
                io = re.match(r"set_io[ \t]++(?:-\w{1,12}+[ \t]++)*+([\w\[\]/.-]{1,80}+)[ \t]++(\w{1,12}+)", line)
                if io:
                    pins[io.group(1)] = io.group(2)
            elif lower.endswith(".lpf"):
                locate = re.match(r"(?i)LOCATE[ \t]++COMP[ \t]++\"([^\"]{1,80}+)\"[ \t]++SITE[ \t]++\"(\w{1,12}+)\"", line)
                if locate:
                    pins[locate.group(1)] = locate.group(2)
                frequency = re.match(r"(?i)FREQUENCY[ \t]++PORT[ \t]++\"([^\"]{1,80}+)\"[ \t]++([\d.]{1,12}+)[ \t]*+MHZ", line)
                if frequency:
                    clocks.append((frequency.group(1), 1000.0 / float(frequency.group(2))))
                standard = re.match(r"(?i)IOBUF[ \t]++PORT[ \t]++\"([^\"]{1,80}+)\"[^;]{0,200}?IO_TYPE[ \t]*+=[ \t]*+(\w{1,24}+)", line)
                if standard:
                    standards[standard.group(1)] = standard.group(2)
            elif lower.endswith(".cst"):
                location = re.match(r"(?i)IO_LOC[ \t]++\"([^\"]{1,80}+)\"[ \t]++(\w{1,12}+)", line)
                if location:
                    pins[location.group(1)] = location.group(2)
                standard = re.match(r"(?i)IO_PORT[ \t]++\"([^\"]{1,80}+)\"[^;]{0,200}?IO_TYPE[ \t]*+=[ \t]*+(\w{1,24}+)", line)
                if standard:
                    standards[standard.group(1)] = standard.group(2)
        if not (clocks or pins or device or exceptions):
            return []
        if device:
            code_facts.emit_fact("fpga_part", device, family=family or _family(device), source="quartus")
        for name, period in clocks[:64]:
            code_facts.emit_fact("hdl_clock_constraint", name, period_ns=period)
        parts = []
        if device or family:
            parts.append(f"device {device or '?'} ({family or _family(device) or 'unknown family'})")
        if top:
            parts.append(f"top-level entity {top}")
        if clocks:
            parts.append("clocks " + ", ".join(
                f"{name}" + (f" {period:g} ns ({1000 / period:.4g} MHz)" if period else "") for name, period in clocks[:10]))
        if pins:
            parts.append(f"{len(pins)} pin assignment(s)")
        if standards:
            parts.append("I/O standards " + ", ".join(sorted(set(standards.values()))[:10]))
        if exceptions:
            parts.append("timing exceptions " + ", ".join(f"{count} {name}" for name, count in sorted(exceptions.items())))
        findings = [self._finding(record, "FPGA constraints", "; ".join(parts) + ".")]
        if lower.endswith(".xdc") and pins:
            missing = sorted(port for port in pins if port not in standards)
            if missing:
                findings.append(self._finding(
                    record, "Pins without an I/O standard",
                    f"{len(missing)} placed port(s) have no IOSTANDARD ({', '.join(missing[:12])}); Vivado's bitstream "
                    "DRC (NSTD-1) rejects designs with unspecified I/O standards.", severity="LOW",
                    confidence="INFERRED", recommendation="Set IOSTANDARD for every placed port.",
                ))
        return findings

    def _project(self, record: FileRecord, text: str) -> list[Finding]:
        lower = record.path.lower()
        part = tool = top = ""
        if lower.endswith(".xpr"):
            match = re.search(r"<Option[ \t]++Name=\"Part\"[ \t]++Val=\"([\w.-]{1,60}+)\"", text)
            part, tool = (match.group(1) if match else ""), "Vivado"
        elif lower.endswith(".xise"):
            match = re.search(r"xil_pn:name=\"Device\"[ \t]++xil_pn:value=\"([\w.-]{1,60}+)\"", text)
            part, tool = (match.group(1) if match else ""), "ISE"
        elif lower.endswith(".ldf"):
            match = re.search(r"device=\"([\w.-]{1,60}+)\"", text)
            part, tool = (match.group(1) if match else ""), "Lattice Diamond"
        elif lower.endswith(".qpf"):
            match = re.search(r"PROJECT_REVISION[ \t]*+=[ \t]*+\"([^\"]{1,80}+)\"", text)
            top, tool = (match.group(1) if match else ""), "Quartus"
        elif lower.endswith(".core"):
            if "CAPI=2" not in text[:200]:
                return []
            name = re.search(r"(?m)^name[ \t]*+:[ \t]*+([\w:.-]{1,120}+)", text)
            toplevel = re.search(r"(?m)^[ \t]++toplevel[ \t]*+:[ \t]*+([\w.-]{1,80}+)", text)
            part = (re.search(r"(?m)^[ \t]++part[ \t]*+:[ \t]*+([\w.-]{1,60}+)", text) or [None, ""])[1] or ""
            top, tool = (toplevel.group(1) if toplevel else ""), f"FuseSoC core {name.group(1) if name else ''}".strip()
        elif lower.endswith("apio.ini"):
            match = re.search(r"(?m)^[ \t]*+board[ \t]*+=[ \t]*+([\w.-]{1,60}+)", text)
            part, tool = (match.group(1) if match else ""), "apio"
        if not (part or top or tool.startswith("FuseSoC")):
            return []
        family = _family(part) if part else ""
        if part:
            code_facts.emit_fact("fpga_part", part, family=family, source=tool)
        return [self._finding(
            record, "FPGA project", f"{tool} project" + (f" targeting {part}" if part else "")
            + (f" ({family})" if family else "") + (f"; top level {top}" if top else "") + ".",
        )]
