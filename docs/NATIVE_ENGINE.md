# Native execution backend

The optional compiled extension is part of the real PDT execution path:
filesystem file-type classification calls the native byte counter to inspect a
bounded magic-byte sample, and streaming secret analysis uses it for newline
accounting. The C module also reports architecture, CPU backend and hardware
thread count for the scan report.

- Portable C implementation: byte counting and native capability reporting.
- Linux x86-64 Assembly backend: SSE2 byte comparison/movemask plus POPCNT.
- Runtime C dispatch: checks CPU support before entering the Assembly routine.
- Fallback: scalar C on unsupported CPUs/platforms or when Assembly is not built;
  Python implementation when the optional extension cannot be compiled.
- The Assembly routine follows the x86-64 System V ABI and is only compiled on
  Linux x86-64. Windows and macOS currently use the portable C extension when
  a compiler is available.

The extension is built locally by setuptools and marked optional so installation
can continue with the Python fallback if a compiler is unavailable. It accepts
explicit contiguous Python buffers and does not open paths, follow symlinks,
execute project code or access the network. The GIL is retained while reading
caller-provided buffers so mutable bytearrays cannot be concurrently changed.

This is an initial native primitive, not yet a high-throughput filesystem walker.
Rust traversal, bounded inventory storage, cross-platform wheels, sanitizers,
fuzzing and benchmark gates remain production work.
