"""Embedded systems: targets, RTOS configuration, memory maps and interrupt handlers.

Configuration files name the hardware: PlatformIO environments (platform, board,
framework), ESP-IDF ``sdkconfig`` (target chip, flash size, secure boot and flash
encryption), Zephyr ``prj.conf`` and ``west.yml``, STM32CubeMX ``.ioc`` projects (MCU,
peripherals, pins), Rust ``.cargo/config.toml`` target triples and FreeRTOS
``FreeRTOSConfig.h``. Linker scripts (GNU ld, IAR ``.icf``, Keil scatter) give the memory
map; device trees give the board model and enabled peripherals.

C, C++, Arduino and Rust sources are read through the shared code model: interrupt
handlers (CMSIS ``*_IRQHandler``, AVR ``ISR()``, ``__attribute__((interrupt))``,
``IRAM_ATTR``), RTOS APIs (FreeRTOS, Zephyr, CMSIS-RTOS, ThreadX, RT-Thread), HAL and
register access. Inside interrupt handlers PDT reports blocking delays, heap allocation,
printf and task-context RTOS calls that have an ``...FromISR`` variant.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path, PurePosixPath

from ...core.limits import AnalyzerLimits, over_limit
from ...core.source_utils import SourceBudgetExceeded, read_text_bounded
from ...intelligence import facts as code_facts
from ...intelligence.model import FUNCTION_KINDS, model_for
from ...models import FileRecord, Finding
from ..base import Analyzer, oversize_finding
from ..code.findings import code_finding

_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_SOURCE_LANGUAGES = frozenset({"C", "C++", "C/C++ Header", "Arduino Sketch", "Rust"})
_SOURCE_HINT = re.compile(
    r"IRQHandler|ISR[ \t]*+\(|__attribute__[ \t]*+\(\([ \t]*+interrupt|IRAM_ATTR|attachInterrupt|"
    r"xTaskCreate|xQueue|xSemaphore|vTaskDelay|osThreadNew|osDelay|k_thread|K_THREAD_DEFINE|k_sleep|"
    r"tx_thread_create|rt_thread_create|HAL_[A-Z]|LL_[A-Z]|digitalWrite|pinMode|analogRead|Serial\.begin|"
    r"gpio_set_level|esp_|nrf_|gpio_put|#pragma[ \t]++vector|__interrupt|cortex_m|#!\[no_std\]|"
    r"->(?:ODR|IDR|BSRR|BRR|CR1|CR2|CCR|SR|DR|MODER|PUPDR|OTYPER|AFR)\b|\(\*\(volatile"
)
# CMSIS vector names, *_isr conventions and STM32 HAL callbacks (run from the IRQ).
_ISR_NAME = re.compile(
    r"(?:_IRQHandler|_IRQ_Handler|_isr|_ISR|_Isr)$|^(?:NMI|HardFault|MemManage|BusFault|UsageFault|SVC|SVCall|"
    r"DebugMon|PendSV|SysTick|Default)_Handler$|^HAL_\w*Callback$"
)
_AVR_ISR = re.compile(r"(?<![\w$])ISR[ \t]*+\([ \t]*+(\w{1,80}+)")
_ISR_ATTRIBUTE = re.compile(
    r"__attribute__[ \t]*+\(\([ \t]*+(?:interrupt|isr|signal)\b|(?<![\w$])IRAM_ATTR\b|#pragma[ \t]++vector\b|"
    r"(?<![\w$])__interrupt\b|(?<![\w$])__irq\b|#\[interrupt\]|#\[exception\]"
)
_RTOS_APIS = {
    "FreeRTOS": re.compile(r"(?<![\w$])(?:xTaskCreate\w*+|vTaskDelay\w*+|xQueue\w++|xSemaphore\w++|xTimer\w++|"
                           r"xEventGroup\w++|vTaskStartScheduler|ulTaskNotify\w*+|xTaskNotify\w*+)[ \t]*+\("),
    "Zephyr": re.compile(r"(?<![\w$])(?:k_thread_create|K_THREAD_DEFINE|k_sem_\w++|k_mutex_\w++|k_msgq_\w++|"
                         r"k_sleep|k_msleep|k_work_\w++|k_timer_\w++|k_fifo_\w++)[ \t]*+\("),
    "CMSIS-RTOS": re.compile(r"(?<![\w$])os(?:ThreadNew|ThreadCreate|Delay|DelayUntil|MutexNew|SemaphoreNew|"
                             r"MessageQueueNew|MessageQueuePut|MessageQueueGet|KernelStart|EventFlagsNew)[ \t]*+\("),
    "ThreadX": re.compile(r"(?<![\w$])tx_(?:thread|queue|semaphore|mutex|event_flags|timer)_\w++[ \t]*+\("),
    "RT-Thread": re.compile(r"(?<![\w$])rt_(?:thread|sem|mutex|mq|mb|event|timer)_\w++[ \t]*+\("),
    "Embassy/RTIC": re.compile(r"#\[(?:embassy_executor::main|embassy_executor::task|rtic::app|task)\b"),
}
_FRAMEWORK_APIS = {
    "STM32 HAL/LL": re.compile(r"(?<![\w$])(?:HAL|LL)_[A-Z][A-Za-z0-9]*+_\w++[ \t]*+\("),
    "Arduino": re.compile(r"(?<![\w$.])(?:digitalWrite|digitalRead|pinMode|analogRead|analogWrite|attachInterrupt|"
                          r"delayMicroseconds)[ \t]*+\(|(?<![\w$])Serial\d?\.begin[ \t]*+\("),
    "ESP-IDF": re.compile(r"(?<![\w$])(?:esp_\w++|gpio_set_level|gpio_config|nvs_\w++|xTaskCreatePinnedToCore)[ \t]*+\("),
    "nRF SDK": re.compile(r"(?<![\w$])(?:nrf_\w++|nrfx_\w++|sd_ble_\w++)[ \t]*+\("),
    "Pico SDK": re.compile(r"(?<![\w$])(?:gpio_put|gpio_init|stdio_init_all|pio_\w++|multicore_launch_core1)[ \t]*+\("),
    "Embedded Rust": re.compile(r"#!\[no_std\]|(?<![\w$])cortex_m(?:_rt)?::|(?<![\w$])embedded_hal::"),
}
_REGISTER_ACCESS = re.compile(
    r"\*[ \t]*+\([ \t]*+volatile[ \t]++[\w ]{1,40}+\*[ \t]*+\)[ \t]*+\(?[ \t]*+0x[0-9A-Fa-f]{4,}+"
    r"|(?<![\w$])[A-Z][A-Z0-9_]{1,15}+->(?:ODR|IDR|BSRR|BRR|CR1|CR2|CR3|CCR\d?|SR|DR|MODER|PUPDR|OTYPER|OSPEEDR|AFR|"
    r"IER|ISR|ICR|ARR|PSC|CNT|BRR|APB1ENR|APB2ENR|AHB1ENR|AHBENR)\b"
)
# Calls that block, allocate or are task-context only: wrong inside an interrupt.
_ISR_BLOCKING = re.compile(
    r"(?<![\w$.])(?:HAL_Delay|delay|delayMicroseconds|vTaskDelay|vTaskDelayUntil|osDelay|k_sleep|k_msleep|"
    r"usleep|sleep|_delay_ms|nrf_delay_ms|sleep_ms|busy_wait_ms)[ \t]*+\("
)
_ISR_ALLOCATION = re.compile(r"(?<![\w$.])(?:malloc|calloc|realloc|free|pvPortMalloc|vPortFree|new)[ \t(]")
_ISR_PRINT = re.compile(r"(?<![\w$.])(?:printf|puts|sprintf|Serial\.print(?:ln)?|ESP_LOG[EWIDV])[ \t]*+\(")
_TASK_ONLY = re.compile(
    r"(?<![\w$.])(?:xQueueSend|xQueueSendToBack|xQueueSendToFront|xQueueReceive|xQueueOverwrite|xSemaphoreGive|"
    r"xSemaphoreTake|xTaskNotifyGive|xTaskNotify|xTimerStart|xTimerStop|xTimerReset|xEventGroupSetBits|"
    r"xStreamBufferSend|xMessageBufferSend)[ \t]*+\("
)

_PLATFORMIO_ENV = re.compile(r"(?m)^[ \t]*+\[env:([^\]\r\n]{1,80}+)\]")
_INI_SETTING = re.compile(r"(?m)^[ \t]*+([A-Za-z_][\w.-]{0,60}+)[ \t]*+=[ \t]*+([^\r\n;#]{0,300}+)")
_KCONFIG_SETTING = re.compile(r"(?m)^(CONFIG_[A-Z0-9_]{1,120}+)=([^\r\n]{0,200}+)")
_KCONFIG_UNSET = re.compile(r"(?m)^#[ \t]*+(CONFIG_[A-Z0-9_]{1,120}+)[ \t]++is not set")
_IOC_SETTING = re.compile(r"(?m)^([A-Za-z][\w.]{0,120}+)=([^\r\n]{0,300}+)")
_FREERTOS_DEFINE = re.compile(r"(?m)^[ \t]*+#[ \t]*+define[ \t]++(config[A-Z][A-Za-z0-9_]{1,60}+)[ \t]++([^\r\n]{1,120}+)")
_CARGO_TARGET = re.compile(r"(?m)^[ \t]*+target[ \t]*+=[ \t]*+[\"']([\w.-]{1,80}+)[\"']")
_EMBEDDED_TRIPLE = re.compile(r"^(?:thumbv\w++|armv\w*+-none-\w++|riscv32\w++|riscv64\w*+-unknown-none\w*+|"
                              r"xtensa-\w++|avr-\w++|msp430-\w++|aarch64-unknown-none\w*+)")

_LD_MEMORY_BLOCK = re.compile(r"(?s)MEMORY[ \t\r\n]*+\{([^{}]{0,20000}+)\}")
_LD_REGION = re.compile(
    r"([A-Za-z_][\w.]{0,60}+)[ \t]*+(?:\(([!rwxailRWXAIL]{1,8}+)\))?[ \t]*+:[ \t]*+(?:ORIGIN|org|o)[ \t]*+=[ \t]*+"
    r"([^,\r\n]{1,80}+),[ \t]*+(?:LENGTH|len|l)[ \t]*+=[ \t]*+([^\r\n;]{1,80}+)"
)
# Bounds are hex literals or symbols defined elsewhere (the IAR ICF editor writes
# from __ICFEDIT_region_ROM_start__ to __ICFEDIT_region_ROM_end__).
_ICF_REGION = re.compile(
    r"define[ \t]++region[ \t]++([A-Za-z_]\w{0,60}+)[ \t]*+=[ \t]*+mem:\[[ \t]*+from[ \t]++(0x[0-9A-Fa-f]{1,16}+|\w{1,80}+)"
    r"[ \t]++(?:to[ \t]++(0x[0-9A-Fa-f]{1,16}+|\w{1,80}+)|size[ \t]++(0x[0-9A-Fa-f]{1,16}+|\w{1,80}+))"
)
_ICF_SYMBOL = re.compile(r"define[ \t]++(?:exported[ \t]++)?symbol[ \t]++(\w{1,80}+)[ \t]*+=[ \t]*+(0x[0-9A-Fa-f]{1,16}+|\d{1,12}+)")
_SCATTER_REGION = re.compile(
    r"(?m)^[ \t]*+([A-Za-z_]\w{0,60}+)[ \t]++(0x[0-9A-Fa-f]{1,16}+)[ \t]++(0x[0-9A-Fa-f]{1,16}+)[ \t]*+\{"
)
_LD_SYMBOL = re.compile(r"(?m)^[ \t]*+(_estack|_Min_Heap_Size|_Min_Stack_Size|__stack_size__|__heap_size__|"
                        r"_stack_size|_heap_size)[ \t]*+=[ \t]*+([^;\r\n]{1,60}+);")
_DTS_MODEL = re.compile(r"(?m)^[ \t]*+model[ \t]*+=[ \t]*+\"([^\"\r\n]{1,200}+)\"")
_DTS_COMPATIBLE = re.compile(r"(?<![\w-])compatible[ \t]*+=[ \t]*+((?:\"[^\"\r\n]{1,120}+\"[ \t]*+,?[ \t]*+){1,8}+)")
_DTS_STATUS_OK = re.compile(r"status[ \t]*+=[ \t]*+\"(?:okay|ok)\"")
_QUOTED = re.compile(r"\"([^\"\r\n]{1,120}+)\"")
# GNU ld accepts K, M and G in either case (512k).
_SIZE = re.compile(r"^\(?[ \t]*+(0x[0-9A-Fa-f]++|\d++)[ \t]*+([KMGkmg])?(?:[Bb])?[ \t]*+\)?$")


def _strip_block_comments(text: str) -> str:
    """Blank /* ... */ comments in linear time (an unterminated one runs to the end)."""
    pieces, position = [], 0
    while True:
        start = text.find("/*", position)
        if start == -1:
            pieces.append(text[position:])
            return "".join(pieces)
        end = text.find("*/", start + 2)
        end = len(text) if end == -1 else end + 2
        pieces.append(text[position:start])
        pieces.append(" " * (end - start))
        position = end


def _number(text: str) -> int | None:
    """Parse linker-style sizes: 0x8000, 512K, 1M, (64 * 1024)."""
    value = text.strip().rstrip(";").strip()
    product = re.fullmatch(r"\(?[ \t]*+(\d{1,9}+)[ \t]*+\*[ \t]*+(\d{1,9}+)[ \t]*+\)?", value)
    if product:
        return int(product.group(1)) * int(product.group(2))
    match = _SIZE.match(value)
    if not match:
        return None
    number = int(match.group(1), 16) if match.group(1).lower().startswith("0x") else int(match.group(1))
    unit = match.group(2).upper() if match.group(2) else None
    return number * {None: 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[unit]


def _size(value: int | None) -> str:
    if value is None:
        return "?"
    for unit, scale in (("GiB", 1024 ** 3), ("MiB", 1024 ** 2), ("KiB", 1024)):
        if value >= scale and value % (scale // 1024 or 1) == 0:
            return f"{value / scale:g} {unit}"
    return f"{value} B"


def _kind(record: FileRecord) -> str | None:
    posix = record.path.replace("\\", "/")
    name = PurePosixPath(posix).name
    lower = name.lower()
    if lower == "platformio.ini":
        return "platformio"
    if lower.startswith("sdkconfig"):
        return "sdkconfig"
    if lower == "prj.conf" or (lower.endswith(".conf") and "/boards/" in f"/{posix}"):
        return "zephyr_conf"
    if lower == "west.yml":
        return "west"
    if lower.endswith(".ioc"):
        return "cubemx"
    if lower.endswith((".ld", ".lds", ".icf", ".sct")):
        return "linker"
    if lower.endswith((".dts", ".dtsi")) or (lower.endswith(".overlay") and "zephyr" in posix.lower()) or (
        lower.endswith(".overlay") and "/boards/" in f"/{posix}"
    ):
        return "devicetree"
    if lower == "freertosconfig.h":
        return "freertos_config"
    if lower in {"config.toml", "config"} and posix.endswith((".cargo/config.toml", ".cargo/config")):
        return "cargo_config"
    if record.language in _SOURCE_LANGUAGES:
        return "source"
    return None


class EmbeddedAnalyzer(Analyzer):
    name = "embedded"
    limits = AnalyzerLimits(
        _MAX_CONFIG_BYTES,
        "whole",
        outcome="UNKNOWN finding for a file past the budget",
    )
    version = "1.0.0"
    description = ("Embedded targets (PlatformIO, ESP-IDF, Zephyr, STM32CubeMX, Rust), memory maps, device trees, "
                   "RTOS usage and interrupt-handler safety.")
    domains = ("embedded",)
    languages = tuple(sorted(_SOURCE_LANGUAGES))

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.content_skipped_reason is None and _kind(record) is not None

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        kind = _kind(record)
        if kind == "source":
            return self._source(path, record)
        if over_limit(record.size_bytes, _MAX_CONFIG_BYTES):
            return [oversize_finding(self, record, "embedded", "Embedded configuration", _MAX_CONFIG_BYTES)]
        try:
            text = read_text_bounded(path, _MAX_CONFIG_BYTES, errors="replace",
                                     expected_identity=record.analysis_identity)
        except (OSError, SourceBudgetExceeded):
            return []
        handler = getattr(self, f"_{kind}")
        return handler(record, text)

    # -- configuration -----------------------------------------------------------------
    def _finding(self, record: FileRecord, title: str, detail: str, *, severity: str = "INFO",
                 confidence: str = "CONFIRMED", recommendation: str | None = None) -> Finding:
        return Finding("embedded", f"{title}: {record.path}", detail, confidence=confidence,
                       evidence=[record.path], analyzer=self.name, severity=severity,
                       recommendation=recommendation)

    def _platformio(self, record: FileRecord, text: str) -> list[Finding]:
        headers = list(_PLATFORMIO_ENV.finditer(text))
        environments = []
        for index, header in enumerate(headers):
            end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
            body = text[header.end():end]
            next_section = re.search(r"(?m)^[ \t]*+\[", body)
            body = body[:next_section.start()] if next_section else body
            settings = {key.lower(): value.strip() for key, value in _INI_SETTING.findall(body)}
            environment = {"name": header.group(1).strip(), **{
                key: settings[key] for key in ("platform", "board", "framework", "upload_protocol") if key in settings
            }}
            environments.append(environment)
            if environment.get("board"):
                code_facts.emit_fact("embedded_target", environment["board"], source="platformio",
                                     platform=environment.get("platform", ""), framework=environment.get("framework", ""))
        if not environments:
            return []
        described = "; ".join(
            f"{item['name']}: " + ", ".join(f"{key}={value}" for key, value in item.items() if key != "name")
            for item in environments[:12]
        )
        return [self._finding(record, "PlatformIO environments",
                              f"{len(environments)} build environment(s). {described}.")]

    def _sdkconfig(self, record: FileRecord, text: str) -> list[Finding]:
        settings = dict(_KCONFIG_SETTING.findall(text))
        unset = set(_KCONFIG_UNSET.findall(text))
        target = settings.get("CONFIG_IDF_TARGET", "").strip('"')
        if not settings:
            return []
        flash = settings.get("CONFIG_ESPTOOLPY_FLASHSIZE", "").strip('"')
        secure_boot = settings.get("CONFIG_SECURE_BOOT") == "y" or settings.get("CONFIG_SECURE_BOOT_V2_ENABLED") == "y"
        encryption = settings.get("CONFIG_FLASH_ENCRYPTION_ENABLED") == "y"
        partition = settings.get("CONFIG_PARTITION_TABLE_FILENAME", "").strip('"')
        if target:
            code_facts.emit_fact("embedded_target", target, source="esp-idf", flash=flash)
        details = [f"target {target or 'unknown'}"]
        if flash:
            details.append(f"flash {flash}")
        if settings.get("CONFIG_FREERTOS_HZ"):
            details.append(f"FreeRTOS tick {settings['CONFIG_FREERTOS_HZ']} Hz")
        if partition:
            details.append(f"partition table {partition}")
        details.append(f"secure boot {'on' if secure_boot else 'off'}, flash encryption {'on' if encryption else 'off'}")
        findings = [self._finding(record, "ESP-IDF configuration", "; ".join(details) + ".")]
        explicit_off = {"CONFIG_SECURE_BOOT", "CONFIG_FLASH_ENCRYPTION_ENABLED"} & unset
        if not record.path.endswith(".defaults") and (not secure_boot or not encryption) and (
            explicit_off or "CONFIG_SECURE_BOOT" in settings or "CONFIG_FLASH_ENCRYPTION_ENABLED" in settings
        ):
            findings.append(self._finding(
                record, "Firmware protections disabled",
                "Secure boot and/or flash encryption are off, so a device's firmware can be read out or replaced "
                "with unsigned code by anyone with physical access.", severity="LOW",
                recommendation="Enable secure boot v2 and flash encryption in release configurations.",
            ))
        return findings

    def _zephyr_conf(self, record: FileRecord, text: str) -> list[Finding]:
        settings = dict(_KCONFIG_SETTING.findall(text))
        if not settings:
            return []
        enabled = sorted(key[7:] for key, value in settings.items() if value.strip() == "y")
        notable = [name for name in enabled if name.split("_", 1)[0] in {
            "BT", "NETWORKING", "WIFI", "USB", "MCUBOOT", "BOOTLOADER", "SHELL", "LOG", "SERIAL", "GPIO", "I2C",
            "SPI", "SENSOR", "FLASH", "NVS", "SETTINGS", "MBEDTLS", "TFM", "POSIX", "CPP", "FPU", "WATCHDOG",
        }]
        return [self._finding(
            record, "Zephyr Kconfig fragment",
            f"{len(settings)} option(s), {len(enabled)} enabled"
            + (f"; subsystems: {', '.join(notable[:25])}" if notable else "") + ".",
        )]

    def _west(self, record: FileRecord, text: str) -> list[Finding]:
        projects = re.findall(r"(?m)^[ \t]*+-[ \t]*+name:[ \t]*+([\w.-]{1,80}+)", text)
        if "manifest:" not in text:
            return []
        return [self._finding(record, "Zephyr west manifest",
                              f"{len(projects)} project(s): {', '.join(projects[:20]) or 'none listed'}.")]

    def _cubemx(self, record: FileRecord, text: str) -> list[Finding]:
        settings = dict(_IOC_SETTING.findall(text))
        mcu = settings.get("Mcu.UserName") or settings.get("Mcu.Name") or settings.get("PCC.PartNumber") or ""
        if not mcu:
            return []
        peripherals = sorted({value.strip() for key, value in settings.items() if re.fullmatch(r"Mcu\.IP\d{1,4}+", key)})
        pins = sum(1 for key in settings if re.fullmatch(r"Mcu\.Pin\d{1,4}+", key))
        toolchain = settings.get("ProjectManager.TargetToolchain", "")
        code_facts.emit_fact("embedded_target", mcu, source="stm32cubemx", family=settings.get("Mcu.Family", ""))
        return [self._finding(
            record, "STM32CubeMX project",
            f"MCU {mcu} ({settings.get('Mcu.Family', 'unknown family')}, package {settings.get('Mcu.Package', '?')}); "
            f"{len(peripherals)} peripheral(s): {', '.join(peripherals[:30])}; {pins} configured pin(s)"
            + (f"; toolchain {toolchain}" if toolchain else "") + ".",
        )]

    def _cargo_config(self, record: FileRecord, text: str) -> list[Finding]:
        targets = [target for target in _CARGO_TARGET.findall(text) if _EMBEDDED_TRIPLE.match(target)]
        for target in targets:
            code_facts.emit_fact("embedded_target", target, source="cargo")
        if not targets:
            return []
        return [self._finding(record, "Embedded Rust target",
                              f"Cross-compiles for {', '.join(sorted(set(targets)))} (bare-metal).")]

    def _freertos_config(self, record: FileRecord, text: str) -> list[Finding]:
        defines = {key: value.split("/*", 1)[0].split("//", 1)[0].strip() for key, value in _FREERTOS_DEFINE.findall(text)}
        if not defines:
            return []
        keys = ("configCPU_CLOCK_HZ", "configTICK_RATE_HZ", "configMAX_PRIORITIES", "configMINIMAL_STACK_SIZE",
                "configTOTAL_HEAP_SIZE", "configUSE_PREEMPTION", "configCHECK_FOR_STACK_OVERFLOW",
                "configUSE_MALLOC_FAILED_HOOK", "configSUPPORT_DYNAMIC_ALLOCATION")
        described = ", ".join(f"{key[6:]}={defines[key]}" for key in keys if key in defines)
        findings = [self._finding(record, "FreeRTOS configuration", f"{described or 'no core settings'}.")]
        overflow = defines.get("configCHECK_FOR_STACK_OVERFLOW", "").strip("() ")
        if overflow in {"0", ""} and "configCHECK_FOR_STACK_OVERFLOW" in defines:
            findings.append(self._finding(
                record, "Task stack overflow checking disabled",
                "configCHECK_FOR_STACK_OVERFLOW is 0, so a task that overruns its stack silently corrupts memory.",
                severity="LOW",
                recommendation="Set configCHECK_FOR_STACK_OVERFLOW to 2 and implement vApplicationStackOverflowHook.",
            ))
        if "configASSERT" not in text:
            findings.append(self._finding(
                record, "FreeRTOS assertions not defined",
                "configASSERT is not defined, so the kernel's internal consistency checks are compiled out.",
                severity="INFO", recommendation="Define configASSERT in debug builds.",
            ))
        return findings

    def _linker(self, record: FileRecord, text: str) -> list[Finding]:
        regions: list[tuple[str, str, int | None, int | None]] = []
        # Comments inside MEMORY (CubeMX writes "LENGTH = 128K /* SRAM1 */") hid sizes.
        text = _strip_block_comments(text)
        block = _LD_MEMORY_BLOCK.search(text)
        if block:
            for name, attributes, origin, length in _LD_REGION.findall(block.group(1)):
                regions.append((name, attributes or "", _number(origin), _number(length)))
        icf_symbols = {name: value for name, value in _ICF_SYMBOL.findall(text)}

        def icf_value(token: str) -> int | None:
            token = icf_symbols.get(token, token)
            if token.lower().startswith("0x"):
                return int(token, 16)
            return int(token) if token.isdigit() else None

        for name, start, end, size in _ICF_REGION.findall(text):
            origin = icf_value(start)
            if origin is None:
                continue
            bound = icf_value(size) if size else icf_value(end)
            length = None if bound is None else (bound if size else bound - origin + 1)
            regions.append((name, "", origin, length))
        if not regions and record.path.lower().endswith(".sct"):
            for name, origin, length in _SCATTER_REGION.findall(text):
                regions.append((name, "", int(origin, 16), int(length, 16)))
        symbols = dict(_LD_SYMBOL.findall(text))
        if not regions and not symbols:
            return []
        for name, attributes, origin, length in regions[:64]:
            code_facts.emit_fact("memory_region", name, origin=origin, length=length, attributes=attributes)
        described = "; ".join(
            f"{name}{f' ({attributes})' if attributes else ''} at {hex(origin) if origin is not None else '?'}, "
            f"{_size(length)}" for name, attributes, origin, length in regions[:16]
        )
        extra = ", ".join(f"{key} = {value.strip()}" for key, value in symbols.items())
        findings = [self._finding(
            record, "Memory map",
            (f"{len(regions)} memory region(s): {described}." if regions else "No MEMORY regions.")
            + (f" Stack/heap: {extra}." if extra else ""),
        )]
        spans = sorted((origin, origin + length, name) for name, _, origin, length in regions
                       if origin is not None and length)
        overlaps = [f"{first[2]} and {second[2]}" for first, second in zip(spans, spans[1:], strict=False)
                    if second[0] < first[1]]
        if overlaps:
            findings.append(self._finding(
                record, "Overlapping memory regions",
                f"Regions overlap: {', '.join(overlaps[:8])}. Sections placed in both can overwrite each other "
                "unless the overlap is a deliberate alias.", severity="LOW", confidence="INFERRED",
            ))
        return findings

    def _devicetree(self, record: FileRecord, text: str) -> list[Finding]:
        clean = _strip_block_comments(text)
        model = _DTS_MODEL.search(clean)
        compatibles = []
        for match in _DTS_COMPATIBLE.finditer(clean):
            compatibles.extend(_QUOTED.findall(match.group(1)))
        enabled = len(_DTS_STATUS_OK.findall(clean))
        if not model and not compatibles:
            return []
        counts = Counter(compatibles)
        for compatible, count in counts.most_common(40):
            code_facts.emit_fact("device_tree_compatible", compatible, count=count)
        if model:
            code_facts.emit_fact("embedded_target", model.group(1), source="devicetree")
        return [self._finding(
            record, "Device tree",
            (f"Board model \"{model.group(1)}\". " if model else "")
            + f"{len(counts)} distinct compatible string(s), {enabled} node(s) explicitly enabled; most common: "
            + ", ".join(f"{name} ({count})" for name, count in counts.most_common(12)) + ".",
        )]

    # -- sources ---------------------------------------------------------------------
    def _source(self, path: Path, record: FileRecord) -> list[Finding]:
        model = model_for(path, record)
        if model is None or not _SOURCE_HINT.search(model.text):
            return []
        clean = model.clean or model.text
        stats: Counter = Counter()
        for rtos, pattern in _RTOS_APIS.items():
            count = len(pattern.findall(clean))
            if count:
                stats[f"rtos:{rtos}"] += count
        for framework, pattern in _FRAMEWORK_APIS.items():
            count = len(pattern.findall(model.text if framework == "Embedded Rust" else clean))
            if count:
                stats[f"framework:{framework}"] += count
        stats["register_accesses"] = len(_REGISTER_ACCESS.findall(clean))
        handlers = self._interrupt_handlers(model, clean)
        stats["interrupt_handlers"] = len(handlers)
        issues: dict[str, list[int]] = {"blocking": [], "allocation": [], "print": [], "task_api": []}
        for _name, _line, start, end in handlers:
            body = clean[start:end]
            for key, pattern in (("blocking", _ISR_BLOCKING), ("allocation", _ISR_ALLOCATION),
                                 ("print", _ISR_PRINT), ("task_api", _TASK_ONLY)):
                for match in pattern.finditer(body):
                    issues[key].append(model.line_of(start + match.start()))
        stats = +stats
        if stats:
            code_facts.emit_fact("embedded_stats", model.language, **dict(sorted(stats.items())))
        findings = []
        if handlers:
            findings.append(code_finding(
                model, "embedded", "Interrupt handlers",
                f"{len(handlers)} interrupt or exception handler(s): "
                + ", ".join(name for name, *_ in handlers[:15]) + ".",
                [line for _, line, _, _ in handlers], analyzer=self.name, severity="INFO", confidence="INFERRED",
            ))
        messages = {
            "blocking": ("Blocking call in an interrupt handler", "MEDIUM",
                         "Delays and sleeps inside an ISR stall every lower-priority interrupt and the scheduler, "
                         "and RTOS delays from an ISR are undefined.",
                         "Set a flag or notify a task from the ISR and do the slow work there."),
            "allocation": ("Heap allocation in an interrupt handler", "MEDIUM",
                           "malloc/new are not interrupt-safe: an ISR that preempts an allocation corrupts the heap.",
                           "Use statically allocated buffers or a lock-free pool in interrupt context."),
            "task_api": ("Task-context RTOS call in an interrupt handler", "MEDIUM",
                         "FreeRTOS APIs without the FromISR suffix may block or switch context from inside an ISR, "
                         "which corrupts kernel state.",
                         "Use the ...FromISR variant and portYIELD_FROM_ISR with a higher-priority-task-woken flag."),
            "print": ("Console output in an interrupt handler", "LOW",
                      "printf-style output is slow and usually not reentrant, so it lengthens interrupt latency.",
                      "Buffer the message and print it from task context."),
        }
        for key, lines in issues.items():
            if lines:
                title, severity, impact, recommendation = messages[key]
                findings.append(code_finding(model, "embedded", title, impact, sorted(set(lines)),
                                             analyzer=self.name, severity=severity, recommendation=recommendation))
        return findings

    @staticmethod
    def _interrupt_handlers(model, clean: str) -> list[tuple[str, int, int, int]]:
        handlers = []
        for symbol in model.symbols:
            if symbol.kind not in FUNCTION_KINDS or not symbol.body:
                continue
            start = model.line_start(symbol.line)
            # Attributes between the previous declaration and this body (same or previous lines).
            cut = max(clean.rfind("}", max(0, start - 400), start), clean.rfind(";", max(0, start - 400), start))
            prefix = clean[max(cut + 1, start - 400):symbol.body[0]]
            if _ISR_NAME.search(symbol.name) or _ISR_ATTRIBUTE.search(prefix):
                handlers.append((symbol.name, symbol.line, *symbol.body))
        for match in _AVR_ISR.finditer(clean):
            close = model.parens.get(clean.find("(", match.start()))
            if close is None:
                continue
            brace = clean.find("{", close, close + 200)
            end = model.braces.get(brace) if brace != -1 else None
            if end is not None and not any(body_start <= brace + 1 <= body_end for *_, body_start, body_end in handlers):
                handlers.append((f"ISR({match.group(1)})", model.line_of(match.start()), brace + 1, end))
        return handlers
