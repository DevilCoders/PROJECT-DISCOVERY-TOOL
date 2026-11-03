# Native execution backend

PDT's optional native extension is part of the production scan path. It provides portable C byte counting and CPU capability reporting, dispatches to Linux x86-64 SSE2/POPCNT Assembly when supported, and can use a dynamically loaded OpenCL GPU for one narrowly scoped operation: counting a byte in a large immutable buffer.

## Runtime components

- C: portable scalar byte counter, CPU capability reporting, OpenCL loader and runtime/device management.
- x86-64 Assembly: Linux x86-64 byte-count primitive using SIMD comparison/movemask and POPCNT, selected only after runtime feature checks.
- OpenCL C kernel: bounded count/reduction kernel used only for large immutable byte buffers.
- C++17: separate native magic-byte classifier used by file-type detection.
- Rust/PyO3: separate no-follow filesystem iterator; it does not depend on the GPU subsystem.
- Python: capability selection, orchestration and portable fallback paths.

## GPU dispatch contract

The extension loads the system OpenCL loader at runtime. No OpenCL headers, SDK or vendor toolkit is required to build PDT. A GPU is reported as usable only after platform/device discovery, required symbol binding, context/program creation and kernel compilation succeed.

The current kernel counts matching bytes and reduces partial counts. It is eligible only when all of these conditions hold:

1. the input is a Python bytes object (immutable while the GIL is released);
2. the buffer is at least 8MiB;
3. the selected device's reported maximum allocation and conservative global-memory budget permit the allocation;
4. kernel creation, buffer allocation, dispatch, readback and completion all succeed.

The extension uses per-call command queues, kernels and buffers. Shared context/program objects are initialized while the Python GIL is held. The GIL is released only for the OpenCL enqueue/readback/finish sequence and for CPU counting over immutable bytes. Mutable bytearray and other buffer exporters remain on the GIL-held CPU path; this avoids data races if another Python thread mutates the source while a GPU transfer is in flight.

If OpenCL is missing, no usable GPU is found, device limits are exceeded, or any runtime operation fails, the operation falls back to CPU. CPU dispatch chooses x86-64 Assembly only after SSE2/POPCNT runtime checks; otherwise it uses portable C. If the extension cannot be built, Python remains available as a fallback. GPU availability never becomes a scan requirement.

Scope limitation: only byte counting/reduction is GPU-accelerated. Source parsing, security rules, archive analysis, dependency resolution and finding generation remain CPU-side. The 8MiB threshold is a conservative initial gate, not a performance claim; device-specific benchmark calibration is still required. GPU dispatch/fallback counters and non-sensitive device capability fields are recorded in scan metrics.

## Bounded concurrent analysis

The CLI uses a bounded ThreadPoolExecutor for independent file/analyzer work. --jobs 0 selects an automatic worker count; --jobs N sets an explicit count (1–64). At most twice the worker count is queued. Results are collected in submission order to keep report output deterministic, and SQLite cache operations remain on the coordinator thread. Analyzer plug-ins are assumed concurrent-safe unless they explicitly set concurrent_safe = False, in which case their instance is serialized with a lock.

This is concurrent thread-pool execution, not a claim that every analyzer is internally asynchronous. The scheduler still consumes an in-memory inventory and accumulates findings in memory; persistent streaming inventory, bounded report data, cancellation and resumable checkpoints remain release gates.

## Safety and portability

- Target code is never imported, executed, compiled or contacted over the network.
- Native functions accept explicit contiguous buffers; the extension does not open target paths or follow symlinks.
- The OpenCL loader is optional and loaded dynamically; no GPU SDK is needed during installation.
- The x86-64 Assembly routine follows the System V ABI and is only compiled on Linux x86-64.
- Windows and macOS use portable C for CPU counting; OpenCL is used only when a compatible runtime/device is present.
- Native build integration is in setup.py, pyproject.toml and MANIFEST.in.

Production release still requires fake/no-device and GPU-present tests, injected OpenCL failure coverage, sanitizer/fuzz work, cross-platform packaging validation and GPU-versus-CPU benchmarks across representative buffer sizes.
