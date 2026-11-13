# Native execution backend

PDT's optional native extension is part of the production scan path. It provides portable C byte counting and CPU capability reporting, dispatches to Linux x86-64 SSE2/POPCNT Assembly when supported, and can use a dynamically loaded OpenCL GPU for one narrowly scoped operation: counting a byte in a large immutable buffer.

## Runtime components

- C: portable scalar byte counter, CPU capability reporting, OpenCL loader and runtime/device management.
- x86-64 Assembly: Linux x86-64 byte-count primitive using SIMD comparison/movemask and POPCNT, selected only after runtime feature checks.
- OpenCL C kernel: bounded count/reduction kernel used only for large immutable byte buffers.
- C++17: the magic-byte rule matcher of file-type detection. Its table (`native/cpp/pdt_signature_rules.h`) is generated from the Python signature catalog by `python tools/signature_rules.py --write`; `match_rule(sample, start)` returns the first rule from `start` whose bytes match, and Python validates the candidate (a rejected candidate continues the scan after it). The module states its table digest in `RULES_DIGEST`; a build from another catalog is not used, `pdt capabilities` reports it as outdated, and the Python matcher returns the same results.
- Rust/PyO3: separate no-follow filesystem iterator; it does not depend on the GPU subsystem. Each entry is a flat tuple of 16 fields: path, kind, size, mode, modification time, hidden flag, link target, error, depth, device, inode, change time, owner uid, group gid, the platform attribute bits (Windows `FILE_ATTRIBUTE_*`, macOS `st_flags`) and the device number of a block or character device. The module states its field count in `ENTRY_FIELDS`; a build with fewer fields (an extension built from older sources) is not used, `pdt capabilities` reports it as outdated, and the Python fallback records the same metadata. Rebuild it with `python setup.py build_ext --inplace`, which builds it optimized (setuptools-rust would otherwise build in-place and editable extensions in debug mode, about half as fast).
- Python: capability selection, orchestration and portable fallback paths.

## GPU dispatch contract

GPU byte counting is opt-in: `pdt scan --gpu` (or `configure_gpu()` in the Python API). Without it the extension never loads the OpenCL runtime, so no vendor driver runs inside a scan, and every buffer is counted on the CPU; `metrics.native_backend.gpu_status` is `disabled`. `pdt capabilities` probes the GPU and reports a usable device that scans leave off as `available`.

With `--gpu`, the extension loads the system OpenCL loader at runtime. No OpenCL headers, SDK or vendor toolkit is required to build PDT. A GPU is reported as usable only after platform/device discovery, required symbol binding, context/program creation and kernel compilation succeed.

The current kernel counts matching bytes and reduces partial counts. It is eligible only when all of these conditions hold:

1. GPU counting is enabled (`--gpu`);
2. the input is a Python bytes object (immutable while the GIL is released);
3. the buffer is at least the threshold, 8 MiB unless `--gpu-min-mb` sets it;
4. the selected device's reported maximum allocation and conservative global-memory budget permit the allocation;
5. kernel creation, buffer allocation, dispatch, readback and completion all succeed.

The extension uses per-call command queues, kernels and buffers. Shared context/program objects are initialized while the Python GIL is held. The GIL is released only for the OpenCL enqueue/readback/finish sequence and for CPU counting over immutable bytes. Mutable bytearray and other buffer exporters remain on the GIL-held CPU path; this avoids data races if another Python thread mutates the source while a GPU transfer is in flight.

If OpenCL is missing, no usable GPU is found, device limits are exceeded, or any runtime operation fails, the operation falls back to CPU. CPU dispatch chooses x86-64 Assembly only after SSE2/POPCNT runtime checks; otherwise it uses portable C. If the extension cannot be built, Python remains available as a fallback. GPU availability never becomes a scan requirement.

Scope limitation: only byte counting/reduction runs on the GPU. Source parsing, security rules, archive analysis, dependency resolution and finding generation remain CPU-side.

### Measured performance

`python tools/gpu_benchmark.py` times both paths on the current machine. On an NVIDIA GeForce RTX 3060 (28 compute units, 12 GiB; Windows 10, 2026-11-13) against the portable C counter, the GPU path was slower at every size:

| Buffer | GPU | CPU (portable C) | GPU / CPU |
|---:|---:|---:|---:|
| 1 MiB | 0.7 ms | 0.3 ms | 2.61 |
| 8 MiB | 4.0 ms | 1.9 ms | 2.13 |
| 64 MiB | 31.6 ms | 15.1 ms | 2.09 |
| 512 MiB | 268.6 ms | 120.4 ms | 2.23 |

Counting a byte is bound by memory bandwidth, and a buffer in host memory must first be copied to the device: the copy alone takes longer than a CPU pass over the same bytes (the GPU path moved about 2 GiB/s, the C counter 4 GiB/s, and the SSE2/POPCNT Assembly counter on Linux is faster still). No threshold makes the GPU path pay off for this kernel, so it is off by default; `--gpu` remains for hardware where a measurement says otherwise. The threshold default of 8 MiB applies once it is enabled.

### Tests

Every platform tests the fallback accounting with a hook that forces each fallback reason (`_set_gpu_test_fault`), the threshold, the disabled default (no OpenCL library loaded) and that worker processes receive `--gpu`. On Linux, `tests/engine/test_fake_opencl.py` builds a fake OpenCL loader (`tests/engine/fake_opencl.c`) and runs the extension against it: a missing symbol, no platform, no device, unknown device limits, a context, kernel-build, dispatch or buffer failure, a device memory limit and a working fake device whose kernel runs on the host. A machine with a usable GPU also checks that GPU and CPU counts agree; CI provisions no GPU, so that check runs on developer hardware (the RTX 3060 above). GPU dispatch/fallback counters and non-sensitive device capability fields are recorded in scan metrics.

Every fallback has a reason. `gpu_unavailable_reason` says why the GPU path is unusable on this host, from the
first step that failed: `loader` (no OpenCL ICD loader, or a required symbol missing), `device` (no platform, no
GPU device, or a device that does not report its limits), `context`, `kernel_build` (program creation or
compilation) or `host_memory`; it is empty when the GPU is online, and `native_extension` without the C
extension. `gpu_fallback_reasons` counts each large immutable buffer counted on the CPU under its reason:
the unavailable reason, `memory_limit` (past the device's allocation limit or a quarter of its memory),
`host_memory`, or `dispatch` (a queue, kernel, buffer, argument, enqueue, read-back or finish failure). The
counts are summed over the analysis worker processes, and the terminal summary, the Markdown and HTML reports
and `pdt capabilities` show them. Small and mutable buffers never take the GPU path, so they are not fallbacks.

## Bounded concurrent analysis

The analysis engine runs per-file analyzers in worker processes or threads. `--executor auto` (the default) uses processes for inventories of 1,000 files or more and threads below that; `--executor process|thread` forces either. `--jobs 0` selects an automatic worker count (twice the hardware threads, at most 8); `--jobs N` sets 1–64 workers. Files are batched per task (up to 4 MiB of content per batch), at most twice the worker count of batches is pending, and results are collected in submission order so reports are deterministic. Each file up to 4 MiB is read once through the verified descriptor and served to every analyzer.

Worker processes never write to the scan databases: the coordinator persists inventory records, findings, diagnostics and code facts in bounded SQLite batches (`OUTPUT/.pdt-cache/inventory.sqlite3`), and later phases read them back as lazy sequences. If a worker process dies, the pool restarts and the affected batch is re-run file by file. Ctrl-C terminates workers immediately and keeps what was persisted, and `--resume` continues an interrupted scan. A worker whose coordinator is killed outright exits by itself within about a second. Analyzer plugins that set `concurrent_safe = False` are serialized with a lock in thread mode.

This is parallel execution of independent per-file work, not a claim that every analyzer is internally asynchronous. The Python import graph's lists are store rows (its module indexes and a compact integer adjacency stay in memory); the other report metrics and each per-file analyzer's working set are still held in memory; bounded-memory behavior at 100 GB+ is unverified until the large-corpus benchmarks run.

## Safety and portability

- Target code is never imported, executed, compiled or contacted over the network.
- Native functions accept explicit contiguous buffers; the extension does not open target paths or follow symlinks.
- The OpenCL loader is optional and loaded dynamically; no GPU SDK is needed during installation.
- The x86-64 Assembly routine follows the System V ABI and is only compiled on Linux x86-64.
- Windows and macOS use portable C for CPU counting; OpenCL is used only when a compatible runtime/device is present.
- Native build integration is in setup.py, pyproject.toml and MANIFEST.in.

Production release still requires fake/no-device and GPU-present tests, injected OpenCL failure coverage, sanitizer/fuzz work, cross-platform packaging validation and GPU-versus-CPU benchmarks across representative buffer sizes.
