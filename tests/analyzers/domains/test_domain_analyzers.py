"""Embedded, firmware, HDL, shader and frontend analyzers, and their project summaries."""
import json
import struct
from pathlib import Path

from project_discovery.analyzers.domains.embedded import EmbeddedAnalyzer
from project_discovery.analyzers.domains.firmware import FirmwareAnalyzer
from project_discovery.analyzers.domains.frontend import FrontendAnalyzer
from project_discovery.analyzers.domains.hdl import HardwareDescriptionAnalyzer
from project_discovery.analyzers.domains.shaders import ShaderAnalyzer
from project_discovery.catalog.languages import detect_language
from project_discovery.cli import run_scan
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord


def run(analyzer, tmp_path: Path, name: str, content, file_type: str = "unknown"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    record = FileRecord(name, path.stat().st_size, path.suffix, detect_language(name), file_type=file_type)
    assert analyzer.supports(record), name
    with collecting_facts() as facts:
        findings = analyzer.analyze(path, record)
    issues = {}
    for finding in findings:
        lines = sorted(int(item.rsplit(":", 1)[1]) for item in finding.evidence
                       if ":" in item and item.rsplit(":", 1)[1].isdigit())
        issues[finding.title.split(": ")[0]] = (finding.severity, lines, finding.detail)
    return issues, [(kind, name, json.loads(detail)) for kind, name, detail in facts.facts]


# -------------------------------------------------------------------- embedded

def test_interrupt_handler_safety(tmp_path: Path):
    issues, facts = run(EmbeddedAnalyzer(), tmp_path, "isr.c", (
        "#include \"stm32f4xx_hal.h\"\n"
        "void USART2_IRQHandler(void) {\n  HAL_Delay(10);\n  printf(\"irq\\n\");\n  xQueueSend(queue, &byte, 0);\n}\n"
        "void HAL_GPIO_EXTI_Callback(uint16_t pin) {\n  char *p = malloc(16);\n  xQueueSendFromISR(queue, &pin, NULL);\n}\n"
        "void task(void *arg) { for (;;) { vTaskDelay(100); GPIOA->ODR ^= 1; } }\n"
        "void Error_Handler(void) { while (1) { HAL_Delay(100); } }\n"
    ))
    assert "USART2_IRQHandler, HAL_GPIO_EXTI_Callback" in issues["Interrupt handlers"][2]
    assert issues["Blocking call in an interrupt handler"][:2] == ("MEDIUM", [3])
    assert issues["Heap allocation in an interrupt handler"][:2] == ("MEDIUM", [8])
    assert issues["Task-context RTOS call in an interrupt handler"][:2] == ("MEDIUM", [5])
    assert issues["Console output in an interrupt handler"][:2] == ("LOW", [4])
    stats = facts[0][2]
    assert stats["interrupt_handlers"] == 2 and stats["register_accesses"] == 1 and stats["rtos:FreeRTOS"] == 3


def test_embedded_configuration_files(tmp_path: Path):
    platformio, facts = run(EmbeddedAnalyzer(), tmp_path, "platformio.ini",
                            "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n")
    assert "board=esp32dev" in platformio["PlatformIO environments"][2]
    assert facts[0][:2] == ("embedded_target", "esp32dev")
    sdkconfig, _ = run(EmbeddedAnalyzer(), tmp_path, "sdkconfig", (
        "CONFIG_IDF_TARGET=\"esp32s3\"\n# CONFIG_SECURE_BOOT is not set\n# CONFIG_FLASH_ENCRYPTION_ENABLED is not set\n"))
    assert sdkconfig["Firmware protections disabled"][0] == "LOW"
    linker, regions = run(EmbeddedAnalyzer(), tmp_path, "app.ld", (
        "MEMORY\n{\n  RAM (xrw) : ORIGIN = 0x20000000, LENGTH = 128K\n  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 1024K\n"
        "  ALIAS (rx) : ORIGIN = 0x08080000, LENGTH = 64K\n}\n"))
    assert "RAM (xrw) at 0x20000000, 128 KiB" in linker["Memory map"][2]
    assert "FLASH and ALIAS" in linker["Overlapping memory regions"][2]
    assert {name for _, name, _ in regions} == {"RAM", "FLASH", "ALIAS"}
    freertos, _ = run(EmbeddedAnalyzer(), tmp_path, "FreeRTOSConfig.h",
                      "#define configTICK_RATE_HZ 1000\n#define configCHECK_FOR_STACK_OVERFLOW 0\n")
    assert freertos["Task stack overflow checking disabled"][0] == "LOW"
    cubemx, _ = run(EmbeddedAnalyzer(), tmp_path, "board.ioc",
                    "Mcu.Family=STM32F4\nMcu.UserName=STM32F407VGTx\nMcu.IP0=ADC1\nMcu.IP1=USART2\nMcu.Pin0=PA0\n")
    assert "MCU STM32F407VGTx" in cubemx["STM32CubeMX project"][2]


# -------------------------------------------------------------------- firmware

def _ihex(records) -> str:
    lines = []
    for address, kind, data in records:
        body = bytes([len(data), address >> 8, address & 0xFF, kind]) + data
        lines.append(":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper())
    return "\n".join(lines) + "\n"


def test_firmware_image_formats(tmp_path: Path):
    hexfile, facts = run(FirmwareAnalyzer(), tmp_path, "app.hex", _ihex(
        [(0, 4, b"\x08\x00"), (0, 0, b"\x00\x01\x02\x03"), (0, 5, b"\x08\x00\x01\x89"), (0, 1, b"")]))
    assert "0x08000000-0x08000003; entry point 0x8000189" in hexfile["Intel HEX firmware image"][2]
    corrupt, _ = run(FirmwareAnalyzer(), tmp_path, "bad.hex", ":0400000000010203F7\n")
    assert corrupt["Corrupt Intel HEX records"][0] == "LOW" and "Intel HEX image without end record" in corrupt
    header = bytearray(52)
    header[:16] = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHIIIIIHHHHHH", header, 16, 2, 40, 1, 0x08000189, 52, 0, 0, 52, 32, 1, 40, 0, 0)
    elf = bytes(header) + struct.pack("<IIIIIIII", 1, 0, 0x08000000, 0x08000000, 0x400, 0x400, 7, 0x1000)
    issues, elf_facts = run(FirmwareAnalyzer(), tmp_path, "fw.elf", elf + b"\x00" * 64, "executable/elf")
    assert "32-bit little-endian ARM bare-metal firmware" in issues["Firmware image (ELF)"][2]
    assert issues["Writable and executable segment"][0] == "LOW"
    assert elf_facts[0][:2] == ("elf_binary", "ARM")
    uf2 = b""
    for index in range(2):
        uf2 += struct.pack("<IIIIIIII", 0x0A324655, 0x9E5D5157, 0x2000, 0x10000000 + 256 * index, 256, index, 2,
                           0xE48BFF56) + b"\x00" * 476 + struct.pack("<I", 0x0AB16F30)
    uf2_issues, _ = run(FirmwareAnalyzer(), tmp_path, "pico.uf2", uf2)
    assert "for RP2040 (2)" in uf2_issues["UF2 firmware image"][2]
    raw, _ = run(FirmwareAnalyzer(), tmp_path, "boot.bin",
                 struct.pack("<IIII", 0x20020000, 0x08000195, 0x08000201, 0x08000203) + b"\x00" * 200)
    assert "reset handler 0x08000194" in raw["Cortex-M firmware image"][2]
    del facts


def test_firmware_build_system_risks(tmp_path: Path):
    yocto, _ = run(FirmwareAnalyzer(), tmp_path, "conf/local.conf",
                   "MACHINE ??= \"raspberrypi4\"\nEXTRA_IMAGE_FEATURES ?= \"debug-tweaks\"\n")
    assert yocto["Development image features enabled"][0] == "MEDIUM"
    buildroot, _ = run(FirmwareAnalyzer(), tmp_path, "demo_defconfig", "BR2_arm=y\nBR2_TARGET_GENERIC_ROOT_PASSWD=\"\"\n")
    assert buildroot["Empty root password"][0] == "MEDIUM"
    recipe, _ = run(FirmwareAnalyzer(), tmp_path, "meta/app_1.0.bb",
                    "LICENSE = \"MIT\"\nSRC_URI = \"git://example.com/app.git;branch=main\"\nSRCREV = \"${AUTOREV}\"\n")
    assert "Recipe fetches sources without transport security" in recipe and "Unpinned source revision" in recipe
    partitions, _ = run(FirmwareAnalyzer(), tmp_path, "partitions.csv",
                        "nvs, data, nvs, 0x9000, 0x6000,\nota_0, app, ota_0, 0x10000, 0x180000,\n")
    assert partitions["Single OTA slot"][0] == "LOW"


# -------------------------------------------------------------------- HDL

def test_verilog_units_lint_and_clocks(tmp_path: Path):
    issues, facts = run(HardwareDescriptionAnalyzer(), tmp_path, "top.sv", (
        "module top #(parameter WIDTH = 8) (input logic clk_a, input logic clk_b, input logic rst_n, output logic q);\n"
        "  counter #(.W(WIDTH)) u_cnt (.clk(clk_a), .q(r));\n  IBUFDS ibuf (.I(p), .IB(n), .O(o));\n"
        "  always_ff @(posedge clk_a or negedge rst_n) begin\n    if (!rst_n) q = 0;\n    else q <= r;\n  end\n"
        "  always_ff @(posedge clk_b) begin q2 <= r; end\n"
        "  always_comb begin y <= a & b; end\nendmodule\n"
        "module counter (input clk, output reg q);\n  always @(posedge clk) q <= q + 1;\nendmodule\n"
        "module tb_top;\n  initial begin #10 $finish; end\nendmodule\n"
    ))
    assert "module top: 4 port(s) (3 input, 1 output)" in issues["HDL design units"][2]
    assert issues["Blocking assignment in clocked logic"][1] == [5]
    assert issues["Non-blocking assignment in combinational logic"][1] == [9]
    assert "top: clk_a, clk_b" in issues["Multiple clock domains in one design unit"][2]
    instances = {(name, values["parent"]) for kind, name, values in facts if kind == "hdl_instance"}
    assert instances == {("counter", "top"), ("IBUFDS", "top")}
    testbenches = {name for kind, name, values in facts if kind == "hdl_module" and values["testbench"]}
    assert testbenches == {"tb_top"}


def test_vhdl_and_fpga_constraints(tmp_path: Path):
    vhdl, _ = run(HardwareDescriptionAnalyzer(), tmp_path, "alu.vhd", (
        "library ieee;\nuse ieee.std_logic_unsigned.all;\n"
        "entity alu is\n  port ( clk : in std_logic; a, b : in std_logic_vector(7 downto 0); y : out std_logic );\nend entity;\n"
        "architecture rtl of alu is\nbegin\n  u_add : entity work.adder port map (a => a, b => b, s => y);\n"
        "  process (clk) begin if rising_edge(clk) then null; end if; end process;\nend architecture;\n"
    ))
    assert "entity alu: 4 port(s) (3 in, 1 out); 1 instance(s) of 1 type(s); clocks clk" in vhdl["HDL design units"][2]
    assert vhdl["Non-standard IEEE arithmetic packages"][0] == "LOW"
    xdc, _ = run(HardwareDescriptionAnalyzer(), tmp_path, "pins.xdc", (
        "create_clock -period 10.000 -name sys_clk [get_ports clk]\nset_property PACKAGE_PIN W5 [get_ports clk]\n"
        "set_property IOSTANDARD LVCMOS33 [get_ports clk]\nset_property PACKAGE_PIN U16 [get_ports {led[0]}]\n"))
    assert "sys_clk 10 ns (100 MHz)" in xdc["FPGA constraints"][2]
    assert "led[0]" in xdc["Pins without an I/O standard"][2]
    qsf, part = run(HardwareDescriptionAnalyzer(), tmp_path, "proj.qsf",
                    "set_global_assignment -name DEVICE 5CSEMA5F31C6\nset_location_assignment PIN_AF14 -to CLOCK_50\n")
    assert part[0] == ("fpga_part", "5CSEMA5F31C6", {"family": "Intel Cyclone V", "source": "quartus"})
    assert "1 pin assignment(s)" in qsf["FPGA constraints"][2]


# -------------------------------------------------------------------- shaders

def test_shader_bindings_stages_and_limits(tmp_path: Path):
    glsl, facts = run(ShaderAnalyzer(), tmp_path, "blur.comp", (
        "#version 450\nlayout(local_size_x = 64, local_size_y = 32) in;\n"
        "layout(set = 0, binding = 0) uniform sampler2D src;\n"
        "layout(set = 0, binding = 0, rgba8) uniform writeonly image2D dst;\nvoid main() {}\n"))
    assert "set/0/0: dst, src" in glsl["Conflicting resource bindings"][2]
    assert "2,048 invocations" in glsl["Compute workgroup exceeds common limits"][2]
    assert facts[0] == ("shader", "GLSL", {"bindings": 1, "entries": 1, "stage": "compute"})
    legacy, _ = run(ShaderAnalyzer(), tmp_path, "old.frag", "uniform sampler2D tex;\nvoid main() {}\n")
    assert "GLSL shader without #version" in legacy
    es, _ = run(ShaderAnalyzer(), tmp_path, "es.frag", "#version 300 es\nout vec4 c;\nvoid main() { c = vec4(1.0); }\n")
    assert "GLSL ES fragment shader without default float precision" in es
    hlsl, _ = run(ShaderAnalyzer(), tmp_path, "lit.hlsl", (
        "Texture2D albedo : register(t0);\nTexture2D normal : register(t0);\n[numthreads(8, 8, 1)]\n"
        "void CSMain(uint3 id : SV_DispatchThreadID) {}\nfloat4 PSMain(float4 p : SV_Position) : SV_Target { return 0; }\n"))
    assert "stages compute, pixel; entry points CSMain, PSMain" in hlsl["Shader"][2]
    assert "albedo, normal" in hlsl["Conflicting resource bindings"][2]
    wgsl, _ = run(ShaderAnalyzer(), tmp_path, "s.wgsl", (
        "@group(0) @binding(0) var<uniform> u: U;\n@binding(0) @group(0) var t: texture_2d<f32>;\n"
        "@compute @workgroup_size(64) fn cs_main() {}\n"))
    assert "Conflicting resource bindings" in wgsl and "stages compute" in wgsl["Shader"][2]


def test_spirv_module_header_and_entry_points(tmp_path: Path):
    module = (struct.pack("<IIIII", 0x07230203, 0x00010500, 0x00080000, 30, 0)
              + struct.pack("<I", (5 << 16) | 15) + struct.pack("<II", 5, 4) + b"main" + b"\x00" * 4
              + struct.pack("<I", (4 << 16) | 71) + struct.pack("<III", 10, 33, 0))
    issues, _ = run(ShaderAnalyzer(), tmp_path, "k.spv", module)
    assert "SPIR-V 1.5" in issues["SPIR-V module"][2] and "main (compute)" in issues["SPIR-V module"][2]


# -------------------------------------------------------------------- frontend

def test_react_components_hooks_and_keys(tmp_path: Path):
    issues, facts = run(FrontendAnalyzer(), tmp_path, "App.tsx", (
        "import { useState, useEffect, useMemo } from 'react';\n"
        "export function App({ user }: Props) {\n"
        "  const [count, setCount] = useState(0);\n"
        "  const style = { width: useMemo(() => 1, []) };\n"
        "  if (count > 3) {\n    useEffect(() => {}, []);\n  }\n"
        "  const onClick = () => { const v = useState(1); };\n"
        "  useEffect(() => { document.title = 'x'; });\n"
        "  return <ul>{items.map(item => <Item name={item.name} />)}{items.map(i => <Item key={i.id} />)}</ul>;\n"
        "}\n"
        "function Item({ name }) { return <li>{name}</li>; }\n"
        "function Gate({ ok }) {\n  if (!ok) return null;\n  const [v] = useState(0);\n  return <p>{v}</p>;\n}\n"
    ))
    assert issues["React hook called conditionally"][:2] == ("MEDIUM", [6, 8, 15])
    assert issues["List items rendered without a key"][1] == [10]
    assert issues["Effect without a dependency array"][1] == [9]
    children = {(name, values["parent"]) for kind, name, values in facts if kind == "component_child"}
    assert ("Item", "App") in children
    libraries = {name for kind, name, _ in facts if kind == "frontend_library"}
    assert libraries == {"React"}


def test_routes_single_file_components_and_configs(tmp_path: Path):
    routes, _ = run(FrontendAnalyzer(), tmp_path, "router.tsx", (
        "import { Routes, Route } from 'react-router-dom';\nexport const R = () => (\n  <Routes>\n"
        "    <Route path=\"/\" element={<Home />} />\n    <Route path=\"/users/:id\" element={<User />} />\n  </Routes>\n);\n"))
    assert "2 React Router route(s): /, /users/:id" in routes["Client-side routes"][2]
    vue, facts = run(FrontendAnalyzer(), tmp_path, "UserCard.vue", (
        "<template>\n  <div><user-avatar :src=\"url\" /><BaseButton>Go</BaseButton><router-link to=\"/\" /></div>\n</template>\n"
        "<script setup lang=\"ts\">\nconst props = defineProps<{ user: User; size?: number }>();\n</script>\n"))
    assert "UserCard with props user, size; renders BaseButton, UserAvatar" in vue["Vue component"][2]
    _, route_facts = run(FrontendAnalyzer(), tmp_path, "app/dashboard/[team]/page.tsx",
                         "export default function Page() { return <main />; }\n")
    assert ("route_file", "/dashboard/:team", {"framework": "Next.js"}) in route_facts
    config, _ = run(FrontendAnalyzer(), tmp_path, "next.config.js",
                    "module.exports = { typescript: { ignoreBuildErrors: true } };\n")
    assert config["Type errors ignored in production builds"][0] == "LOW"
    angular, _ = run(FrontendAnalyzer(), tmp_path, "app.component.ts", (
        "@Component({\n  selector: 'app-root',\n  templateUrl: './app.component.html',\n})\nexport class AppComponent {}\n"))
    assert "AppComponent <app-root> template ./app.component.html" in angular["Angular components"][2]
    del facts


# -------------------------------------------------------------------- summaries

def test_scan_summarizes_domains_in_the_code_index(tmp_path: Path):
    project = tmp_path / "project"
    files = {
        "rtl/top.v": "module top(input clk);\n  child u (.clk(clk));\nendmodule\nmodule child(input clk);\nendmodule\n",
        "shaders/a.frag": "#version 450\nlayout(location = 0) out vec4 c;\nvoid main() { c = vec4(1); }\n",
        "web/App.jsx": "import React from 'react';\nexport function App() { return <Nav />; }\nfunction Nav() { return <a />; }\n",
        "next.config.js": "module.exports = {};\n",
        "pages/about.jsx": "export default function About() { return <p />; }\n",
        "app.ld": "MEMORY { FLASH (rx) : ORIGIN = 0x0, LENGTH = 256K }\n",
    }
    for name, text in files.items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    index = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["code_index"]
    assert index["hdl"]["tops"][0]["name"] == "top" and index["hdl"]["tops"][0]["depth"] == 2
    assert index["shaders"]["files"] == {"GLSL": 1}
    assert index["frontend"]["most_used"] == [{"name": "Nav", "uses": 1}]
    assert index["frontend"]["routes"] == {"Next.js": ["/about"]}
    assert index["embedded"]["memory_bytes"] == {"flash": 262144}


def test_uimage_without_an_extension_is_analyzed(tmp_path: Path):
    header = struct.pack(">IIIIIIIBBBB", 0x27051956, 0, 0, 1024, 0x80008000, 0x80008000, 0, 5, 2, 2, 0)
    header += b"Linux-6.1.0".ljust(32, b"\0")
    issues, _ = run(FirmwareAnalyzer(), tmp_path, "uImage", header + b"\0" * 64, file_type="binary/unclassified")
    assert "Linux-6.1.0" in issues["U-Boot uImage"][2]


def test_linker_maps_with_symbols_lowercase_units_and_comments(tmp_path: Path):
    icf, regions = run(EmbeddedAnalyzer(), tmp_path, "app.icf", (
        "define symbol __ICFEDIT_region_ROM_start__ = 0x08000000;\n"
        "define symbol __ICFEDIT_region_ROM_end__   = 0x0807FFFF;\n"
        "define region ROM_region = mem:[from __ICFEDIT_region_ROM_start__ to __ICFEDIT_region_ROM_end__];\n"
    ))
    assert "ROM_region at 0x8000000, 512 KiB" in icf["Memory map"][2]
    ld, _ = run(EmbeddedAnalyzer(), tmp_path, "gcc.ld", (
        "MEMORY\n{\n  RAM (xrw) : ORIGIN = 0x20000000, LENGTH = 128K /* SRAM1 */\n"
        "  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512k\n}\n"
    ))
    assert "RAM (xrw) at 0x20000000, 128 KiB" in ld["Memory map"][2] and "512 KiB" in ld["Memory map"][2]


def test_generate_constructs_parameters_and_overrides_are_recorded(tmp_path: Path):
    # Instances inside generate loops and branches carry their constructs; parameters and
    # overrides are recorded for elaboration. Regressions: an instance right after
    # endgenerate, or after a for header's begin, was missed, and a one-item branch
    # (if (FAST) adder u (...);) was not an instance.
    _, facts = run(HardwareDescriptionAnalyzer(), tmp_path, "gen.sv", (
        "module gen #(parameter LANES = 4, localparam LAST = LANES - 1) (input clk);\n"
        "  parameter IGNORED = 1;\n"
        "  genvar i;\n"
        "  generate\n"
        "    for (i = 0; i < LANES; i = i + 1) begin : g\n"
        "      lane #(.WIDTH(8 * (i + 1))) u_lane (.clk(clk));\n"
        "    end\n"
        "    if (LANES > 2) fast u_fast (.clk(clk)); else slow u_slow (.clk(clk));\n"
        "  endgenerate\n"
        "  tail u_tail (.clk(clk));\n"
        "  cell u_arr [3:0] (.clk(clk));\n"
        "  always @(posedge clk) for (int k = 0; k < 4; k++) r[k] <= 0;\n"
        "endmodule\n"
    ))
    instances = {name: values["count"] for kind, name, values in facts if kind == "hdl_instance"}
    assert instances == {"lane": 1, "fast": 1, "slow": 1, "tail": 1, "cell": 1}
    parameters = next(values["parameters"] for kind, name, values in facts if kind == "hdl_parameters")
    assert parameters == [["LANES", "4", True], ["LAST", "LANES - 1", False], ["IGNORED", "1", False]]
    sites = {name: values for kind, name, values in facts if kind == "hdl_generate"}
    assert sites["lane"]["constructs"] == [["for", "i", "0", "i < LANES", "i = i + 1"]]
    assert sites["lane"]["overrides"] == {"WIDTH": "8 * (i + 1)"}
    assert sites["fast"]["constructs"] == [["if", "LANES > 2", True]]
    assert sites["slow"]["constructs"] == [["if", "LANES > 2", False]]
    assert sites["cell"]["array"] == "3:0" and sites["cell"]["constructs"] == []
    assert "tail" not in sites  # no construct, override or array: counted from hdl_instance


def test_vhdl_generics_and_generate_regions_are_recorded(tmp_path: Path):
    _, facts = run(HardwareDescriptionAnalyzer(), tmp_path, "core.vhd", (
        "library ieee;\nuse ieee.std_logic_1164.all;\n"
        "entity core is\n  generic (CHANNELS : integer := 3; WITH_DEBUG : boolean := false);\n"
        "  port (clk : in std_logic);\nend entity;\n"
        "architecture rtl of core is\nbegin\n"
        "  gen_ch : for c in 0 to CHANNELS - 1 generate\n"
        "    u_ch : entity work.channel generic map (ID => c) port map (clk => clk);\n"
        "  end generate;\n"
        "  gen_dbg : if WITH_DEBUG generate\n"
        "    u_dbg : entity work.debug_unit port map (clk => clk);\n"
        "  end generate;\n"
        "end architecture;\n"
    ))
    parameters = next(values["parameters"] for kind, name, values in facts if kind == "hdl_parameters")
    assert parameters == [["channels", "3", True], ["with_debug", "false", True]]
    sites = {name: values for kind, name, values in facts if kind == "hdl_generate"}
    assert sites["channel"]["constructs"] == [["range", "c", "0", "CHANNELS - 1", "to"]]
    assert sites["channel"]["overrides"] == {"id": "c"}
    assert sites["debug_unit"]["constructs"] == [["if", "WITH_DEBUG", True]]


def test_scan_elaborates_the_design_hierarchy(tmp_path: Path):
    project = tmp_path / "project"
    (project / "rtl").mkdir(parents=True)
    (project / "rtl" / "top.sv").write_text(
        "module top #(parameter LANES = 4, parameter USE_FIFO = 0) (input clk);\n"
        "  for (genvar i = 0; i < LANES; i++) begin : g_lane\n"
        "    lane #(.WIDTH(8 * (i + 1))) u_lane (.clk(clk));\n"
        "  end\n"
        "  if (USE_FIFO) begin : g_fifo\n    fifo u_fifo (.clk(clk));\n  end\n"
        "  else begin : g_reg\n    regbank u_reg (.clk(clk));\n  end\n"
        "  tree #(.N(4)) u_tree (.clk(clk));\n"
        "endmodule\n"
        "module lane #(parameter WIDTH = 8) (input clk);\n"
        "  for (genvar b = 0; b < WIDTH / 8; b++) begin\n    byte_unit u_b (.clk(clk));\n  end\n"
        "endmodule\n"
        "module byte_unit (input clk);\nendmodule\n"
        "module fifo (input clk);\nendmodule\n"
        "module regbank (input clk);\n  cell u_arr [3:0] (.clk(clk));\nendmodule\n"
        "module cell (input clk);\nendmodule\n"
        "module tree #(parameter N = 2) (input clk);\n"
        "  if (N > 1) begin : g_split\n"
        "    tree #(.N(N / 2)) left (.clk(clk));\n    tree #(.N(N / 2)) right (.clk(clk));\n"
        "  end else begin : g_leaf\n    cell u_leaf (.clk(clk));\n  end\n"
        "endmodule\n"
        "module open_loop #(parameter N = 2) (input clk);\n"
        "  for (genvar i = 0; i < MISSING; i++) begin\n    cell u (.clk(clk));\n  end\n"
        "endmodule\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    hdl = report["metrics"]["code_index"]["hdl"]
    tops = {item["name"]: item for item in hdl["tops"]}
    # 4 lanes with 1+2+3+4 byte units, regbank with a 4-cell array (USE_FIFO = 0), and a
    # tree of 4 leaves (7 trees and 4 cells).
    assert tops["top"] == {
        "name": "top", "path": "rtl/top.sv", "depth": 5, "instances": 4 + 10 + 5 + 11,
        "lexical_instances": 7, "elaboration": "complete",
    }
    assert tops["open_loop"]["elaboration"] == "partial" and tops["open_loop"]["instances"] == 1
    assert any("generate loop not evaluated" in reason for reason in hdl["unelaborated"]["reasons"])
    detail = next(item["detail"] for item in report["findings"] if item["title"] == "HDL design hierarchy")
    assert "top (depth 5, 30 instances;" in detail and "Elaboration was partial for open_loop" in detail
