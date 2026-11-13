# Native execution backend

PDT's optional native extension is part of the production scan path. It provides portable C byte counting and CPU capability reporting, dispatches to Linux x86-64 SSE2/POPCNT Assembly when supported, and can use a dynamically loaded OpenCL GPU for one narrowly scoped operation: counting a byte in a large immutable buffer.

## Runtime components

- C: portable scalar byte counter, CPU capability reporting, OpenCL loader and runtime/device management.
- x86-64 Assembly: Linux x86-64 byte-count primitive using SIMD comparison/movemask and POPCNT, selected only after runtime feature checks.
- OpenCL C kernel: bounded count/reduction kernel used only for large immutable byte buffers.
- C++17: separate native magic-byte classifier used by file-type detection.
- Rust/PyO3: separate no-follow filesystem iterator; it does not depend on the GPU subsystem. Each entry is a flat tuple of 16 fields: path, kind, size, mode, modification time, hidden flag, link target, error, depth, device, inode, change time, owner uid, group gid, the platform attribute bits (Windows `FILE_ATTRIBUTE_*`, macOS `st_flags`) and the device number of a block or character device. The module states its field count in `ENTRY_FIELDS`; a build with fewer fields (an extension built from older sources) is not used, `pdt capabilities` reports it as outdated, and the Python fallback records the same metadata. Rebuild it with `python setup.py build_ext --inplace`, which builds it optimized (setuptools-rust would otherwise build in-place and editable extensions in debug mode, about half as fast).
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

The analysis engine runs per-file analyzers in worker processes or threads. `--executor auto` (the default) uses processes for inventories of 1,000 files or more and threads below that; `--executor process|thread` forces either. `--jobs 0` selects an automatic worker count (twice the hardware threads, at most 8); `--jobs N` sets 1–64 workers. Files are batched per task (up to 4 MiB of content per batch), at most twice the worker count of batches is pending, and results are collected in submission order so reports are deterministic. Each file up to 4 MiB is read once through the verified descriptor and served to every analyzer.

Worker processes never write to the scan databases: the coordinator persists inventory records, findings, diagnostics and code facts in bounded SQLite batches (`OUTPUT/.pdt-cache/inventory.sqlite3`), and later phases read them back as lazy sequences. If a worker process dies, the pool restarts and the affected batch is re-run file by file. Ctrl-C terminates workers immediately and keeps what was persisted, and `--resume` continues an interrupted scan. A worker whose coordinator is killed outright exits by itself within about a second. Analyzer plugins that set `concurrent_safe = False` are serialized with a lock in thread mode.

This is parallel execution of independent per-file work, not a claim that every analyzer is internally asynchronous. Report metrics, the Python import graph (within its caps) and each per-file analyzer's working set are still held in memory; bounded-memory behavior at 100 GB+ is unverified until the large-corpus benchmarks run.

## Safety and portability

- Target code is never imported, executed, compiled or contacted over the network.
- Native functions accept explicit contiguous buffers; the extension does not open target paths or follow symlinks.
- The OpenCL loader is optional and loaded dynamically; no GPU SDK is needed during installation.
- The x86-64 Assembly routine follows the System V ABI and is only compiled on Linux x86-64.
- Windows and macOS use portable C for CPU counting; OpenCL is used only when a compatible runtime/device is present.
- Native build integration is in setup.py, pyproject.toml and MANIFEST.in.

Production release still requires fake/no-device and GPU-present tests, injected OpenCL failure coverage, sanitizer/fuzz work, cross-platform packaging validation and GPU-versus-CPU benchmarks across representative buffer sizes.
