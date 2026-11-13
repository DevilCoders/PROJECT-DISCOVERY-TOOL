# Code Intelligence and Domain Analyzers

This document describes the shared code model, the cross-file code index and the analyzers
built on them: performance, concurrency, resource management, type systems, data flow and
taint, embedded systems, firmware, hardware description languages, graphics shaders,
frontend applications and cross-project integration. For each one it states the method,
what is reported, and the limits that keep results honest.

Every result is static: PDT never executes, imports or builds the scanned code. Results
that depend on heuristics are reported as `INFERRED`, never `CONFIRMED`.

## 1. Shared code model

`project_discovery.intelligence.model.model_for(path, record)` builds one structural model per file
and analysis thread, and every analyzer of that file reuses it (one entry per thread, keyed by
path, size and modification time). Files larger than 4 MiB are not modelled; they are almost
always generated or minified, and the code-index analyzer reports them as `UNKNOWN`.

| Backend | Languages | Method |
|---|---|---|
| Syntax tree | Python | Standard-library `ast`. Symbols carry qualified names (`Class.method`), decorators, parameters and async markers. Call targets are resolved through `import`/`from ... import` aliases (including relative imports), `self`/`cls`, module-level definitions, and the class of the receiver when the code states it (see below). |
| Structural lexer | C, C++, C/C++ headers, Objective-C/C++, CUDA, OpenCL, GLSL, HLSL, Metal, WGSL, Java, Kotlin, Scala, Groovy, C#, Swift, Dart, JavaScript, TypeScript, Vue, Svelte, Go, Rust, PHP, Solidity, Zig, Arduino | A linear-time cleaner blanks comments, string contents and (JavaScript/TypeScript) regular-expression literals while keeping every offset, so braces and parentheses are paired exactly. Definitions come from type keywords, function keywords and C-style typed signatures, nested by brace containment; calls carry their receiver; imports are read per family. Recognized forms include Kotlin/Scala classes whose primary constructor spans lines, `where` clauses before a brace on its own line (Rust, Kotlin, Swift), Go `type ( ... )` groups (function literals such as `func(i, j int) bool {` are not definitions), Swift `init`/`deinit`/`subscript`, C++ out-of-class constructors and destructors (`Widget::Widget(...) : a_(a) {`, `Widget::~Widget()`), and C#/Dart expression-bodied members (`=> expr;`). A `.m` file, which can be Objective-C or MATLAB, is modelled as Objective-C when it has `#import`, `#include`, `@interface`, `@implementation`, `@protocol` or `@class` at the start of a line, and is not modelled otherwise. |
| Tree-sitter refinement | C, C++, C/C++ headers, CUDA, Arduino, Java, C#, Kotlin, Scala, Swift, JavaScript, TypeScript (and TSX), Go, Rust, PHP, Solidity, when the grammar is provisioned locally | The file is parsed, and the grammar's tags query, completed by patterns PDT adds where a bundled query has gaps, replaces the lexer's symbols and calls: exact definition spans and nesting, method containers (namespaces, Go receivers, Rust `impl` blocks, Swift extensions, C++ `Type::method`), constructors, abstract and interface members, expression-bodied members and calls the lexer cannot see (Kotlin trailing lambdas), and no false definitions or calls from prototypes, declarations and initializers. The cleaned text, brace pairs, strings, imports and macros stay the lexer's, so both backends keep one contract. |

**When the Tree-sitter refinement applies.** `tree-sitter-language-pack` must be installed and the language's grammar already in its local cache: PDT never downloads grammars (see the [Operations Guide](../guides/OPERATIONS.md)). The lexical model is kept when no grammar is provisioned, when `PDT_CODE_MODEL=lexical` is set, when error nodes cover more than 20% of the parse, when the syntax tree nests deeper than 4,096 levels (Tree-sitter's query cursor slows down quadratically on such trees; the deepest of 1,124 real npm JavaScript files measured 53 levels), and on any parser failure. Regions the tree does not structure (error nodes, Rust macro arguments and `macro_rules!` bodies, C/C++ `#define` bodies) keep the lexer's definitions and calls. `metrics.code_index.symbols.models` counts the files each backend modelled, per language, and `pdt capabilities` shows which languages a provisioned grammar refines. Results are still structural, without type resolution, and reported as `INFERRED`.

**Python receiver types** (`intelligence.model.python_types`). A call on an object resolves to
its class's method when the code states the class: a constructor call (`repo = Repo()`), an
annotation (`repo: Repo`, `def f(repo: Repo)`, `Optional[Repo]`, `Repo | None`, quoted forward
references), a return annotation (`Repo().clone().find()`), `with Repo() as repo`,
`store or Store()`, a module-level instance, or a `self` attribute assigned in any method. The
inference is flow-insensitive and conservative: a name that is assigned two classes, or
anything of unknown class other than `None`, gets no type. Only classes of the module and
capitalized imported names count as classes. On 671 scikit-learn modules this resolves 79.8%
of call sites instead of 70.7%.

The lexer is an approximation: it does not expand macros, resolve overloads or understand
templates and generics. Hostile inputs (unterminated strings and comments, deep nesting) are
covered by tests that bound the time per file.

## 2. Code facts and the code index

During analysis, analyzers record **facts** next to their findings: symbols, call sites,
referenced identifiers, imports and domain facts (complexity, type usage, taint summaries,
ISRs, memory regions, HDL instances, shader bindings, components, routes, HTTP calls,
message topics and more). Facts are written to the scan's private SQLite inventory in the
same transaction as the file's findings, so `--resume` stays consistent. Writes are
idempotent and bounded per file (5,000 symbols, 20,000 calls, 10,000 references and 5,000
domain facts) and per table (5–20 million rows); a ceiling that is reached is reported as an
`UNKNOWN` "Code index truncated" finding. `metrics.code_index.truncated.kinds` counts the files per
cut kind; a cut of references also qualifies the dead-code finding, and names that are called are
never dead-code candidates.

After analysis, `intelligence.index.analyze_code_index` runs these passes over a read-only
connection using temporary tables (memory does not grow with repository size):

| Pass | Result |
|---|---|
| Symbols | Definitions by language and kind. |
| Call graph | Python calls resolved to module-qualified definitions; lexical calls resolved by name within a language group (same file, unique, ambiguous or external); recursion cycles from strongly connected components (Kosaraju, capped at 500,000 edges). A lexical call resolves in its own file only without a receiver, through `this`/`self`/`Self`, or through the caller's own class; a call through another receiver (`items.size()`, `PathBuf::new()`) or on a call's result (`getItems().size()`, `Runtime.getRuntime().exec()`, `new Builder().build()`) never resolves to the caller itself. A Python module name that several files define (`svc_a/helpers.py` and `svc_b/helpers.py` are both `helpers`) resolves to the file whose import root contains the importer, or not at all; such definitions are named `path:qualified`. Calls through a PEP 420 namespace package (`ns.pkg.mod.run` for `src/ns/pkg/mod.py`) resolve to the package-chain name. |
| Unreferenced private functions | Private definitions whose name appears nowhere in the scan: dead-code candidates. Reflection and string dispatch are not visible. |
| Test links | Public functions referenced from test files. |
| Module graph | JavaScript/TypeScript, C/C++, JVM, Go, Rust, PHP and Dart imports resolved to files, external packages and dependency cycles (Python has its own module graph, which names modules by import name, `pkg.mod` rather than `src.pkg.mod`, keeps the path in each module and edge, and resolves imports through PEP 420 namespace packages). Go imports resolve against the module paths of the scanned `go.mod` files; without one, a directory suffix of at least two segments. Standard-library imports (no dot in the first segment) and other modules stay external. |
| Complexity, type usage, concurrency model, memory | Project totals of the per-file facts. |
| Data flow | Totals of taint flows and Python flows that cross module boundaries (see §4). |
| Embedded, firmware, HDL, shaders, frontend | Domain summaries (targets, binary hardening, design hierarchy, shader inventory, component graph and routes). |
| Integration | What the project serves and calls (endpoints, HTTP calls, topics, gRPC, package names), used by `pdt compare` (see §6). |

Each pass that fails is isolated: it produces an `UNKNOWN` finding and the other passes
still run. Results are in the report under `metrics.code_index`.

### Querying the index

```bash
pdt query OUTPUT --symbol Engine.run
pdt query OUTPUT --callers helper --json
pdt query OUTPUT --callees run --limit 50
pdt query OUTPUT --references parse_config
```

`OUTPUT` is the scan's output directory (the index is `OUTPUT/.pdt-cache/inventory.sqlite3`).
Names may be bare (`run`), qualified (`Engine.run`) or module-qualified as the call graph prints them (`pkg.engine.Engine.run`, matched against the defining file's path). Callers include calls resolved inside their own file (`self.run()`, `this.run()`). Each call row carries a `resolution`: `resolved`, `same file`, `receiver not resolved` (a call through an object whose type the index does not know) or `by name`. On a scan without a code index (an `--inventory-only` scan) `pdt query` warns and exits 3, since an empty answer would be unknown, not absent; on a truncated index it warns that results can be incomplete.

## 3. Quality analyzers

| Analyzer | Python (syntax tree) | Other languages (lexer) |
|---|---|---|
| `performance-hotspots` | McCabe complexity (25 or more is LOW), functions over 300 lines, queries/HTTP calls/sleeps/deep copies/`list.insert(0)` in loops whose trip count depends on data, three or more nested data loops, string `+=` in loops, row-wise DataFrame iteration. A loop's (or comprehension's) iterable runs once and is not "in the loop"; loops over literals or module constants, `executemany`, transaction control statements and `fetchmany` paging are not N+1. | Decision-point complexity (decisions inside a nested function or closure count for that function, as on the Python path), queries and HTTP calls in loop bodies, nested loops, sleeps. Profiling artifacts (pprof, cpuprofile, heap and core dumps) are inventoried. |
| `concurrency` | Blocking calls in coroutines, un-awaited coroutines, `acquire()` without `with`/`finally` (acquire/release pairs split across methods and `__enter__` are deliberate and not reported), thread targets that write globals without a lock. | Go locks without `defer Unlock`, `WaitGroup.Add` inside the goroutine; Java/Kotlin double-checked locking without `volatile`, executors never shut down, sleeping while synchronized, `runBlocking`, `GlobalScope`; C# `async void` (except event handlers), `.Result`/`.Wait()` in async code, `lock(this)`; Rust manual `Send`/`Sync`, `static mut`, blocking sleep in async; JavaScript un-awaited promises, sequential `await` in loops; C `pthread_mutex_lock` without unlock. |
| `resource-management` | Files, sockets, database connections and processes opened in a function and neither closed, returned, stored nor handed to an owner; `tempfile.mktemp`; unbounded `lru_cache` on methods. | C/C++ allocations without `free`, `p = realloc(p, n)`, `new[]` with `delete`, `alloca`, `fopen` without `fclose`; Go response bodies and query rows not closed; JVM and C# resources outside try-with-resources/`using`, `HttpClient` per call; React effects that subscribe without cleanup, intervals never cleared; unsafe Rust inventory. |
| `type-systems` | Annotation coverage (functions, parameters, returns), `Any`, `cast`, `# type: ignore`, module-level ignore comments. | TypeScript `any`, `@ts-ignore`/`@ts-expect-error`/`@ts-nocheck`, non-null assertions; JavaScript `// @ts-check`/`@flow`; Kotlin `!!`; Swift `as!`/`try!`; C# `dynamic` and `#nullable disable`; Java unchecked suppressions; Go `interface{}`. Configuration: tsconfig/jsconfig (comments and trailing commas allowed), mypy (`mypy.ini`, `setup.cfg`, `pyproject.toml`, per-module `ignore_errors`), pyright, Flow (`[untyped]`, `[declarations]`) and MSBuild `<Nullable>`. |

## 4. Data flow and taint (`dataflow`)

**Sources:** web request data (Flask, Django, FastAPI, Starlette, aiohttp, Tornado, Pyramid,
Bottle; Express, Koa, Next.js, NestJS; PHP superglobals, Laravel, Symfony; Servlet, Spring,
JAX-RS; net/http, gorilla/mux, Gin, Echo; ASP.NET; actix-web, axum), route-handler parameters
(except those validated by type, such as `int` or `<int:id>`), WebSocket and socket reads, DOM
sources (`location`, `document.URL`, `document.referrer`) and, for C, `recv`, `fgets`, `scanf`,
`getenv` and `argv`.

**Sinks and severity:** SQL, command, code, deserialization, template and format-string
injection (HIGH); path traversal, server-side request forgery, cross-site scripting and
unbounded copies (MEDIUM); open redirects (LOW). Parameterized queries, list-form process
arguments without a shell and safe YAML loaders are not sinks.

**Python engine.** Values carry labels naming where input entered. Each function is
interpreted in statement order: assignments propagate labels and re-assignment replaces them,
branches merge, loops run again from the merged state until it stops growing, `except`
handlers start from any point of the `try` body and are alternatives to the normal path, and
comprehension targets carry their iterable's labels. Sanitizers clear labels for the sink
kinds they defend (`shlex.quote` for commands, `os.path.basename`/`secure_filename` for paths,
`html.escape` for HTML, `int()` for all). Functions of the same module get summaries (which
parameters reach a sink or the return value), iterated to a fixed point, so input that passes
through local helpers is followed, including methods called on objects of a known class
(`repo.find(name)`, `self.repo.find(name)`). Only functions that touch a source or sink, and their
callers and callees, are interpreted, so files without either cost a single tree walk.

**Cross-module flows (Python).** Calls that pass tainted values into imported functions are
recorded, as are module-level functions and public methods whose parameters reach a sink; a
call on an object of an imported class is recorded as a call to that class's method
(`store = Store(); store.run(sql)` becomes `.store.Store.run`). The code index joins
the two (resolving relative imports) and reports "… across modules" findings with the full
path, for example `views.py:4 request.args -> shop.db.find() -> run_query() -> execute`.

**Lexical engine** (JavaScript/TypeScript, PHP, Java/Kotlin/Scala/Groovy, Go, C#, Rust, C/C++).
Within each function and the top-level code, assignments and sinks are visited in source
order; string interpolation (template literals, PHP and Kotlin `"$x"`, C# `$"{x}"`), out
parameters (`recv`, `sprintf`), builder methods (`append`, `push`) and destructuring are
followed. Re-assigning a variable from clean input in the same block clears it.

Functions of the file get summaries: each parameter is followed, as a marked value, to the
sinks it reaches and to what the function returns, and input a function reads itself and
returns is recorded too. Summaries are iterated (up to three rounds, bounded by an event
budget) so helpers that call helpers are followed, for example
`app.js:17 req.query -> outer() -> inner() -> exec`. Only functions that hold a sink, call
another function of the file, or return to a caller in the file are summarized. Calls that
pass untrusted input to a function the file does not define are recorded; the code index
joins them with the summary of the callee when exactly one file of the same language family
defines a function of that name, and reports them as "... across modules" findings, for
example `app.js:3 req.query -> runQuery() -> pool.query at lib/db.js:2`. An ambiguous name is
not guessed. Files in dependency trees (`node_modules`, `vendor`, `site-packages` and similar)
are summarized for other files only when they read untrusted input themselves, as calls into
installed packages are not followed in Python either. The engine does not reason about
branches. On 1,199 JavaScript files of npm and Babel (17 MB) it adds 5% to the data-flow
analyzer's time (9% when the same files are treated as first-party code).

Every flow names its source, sink and lines. Static analysis cannot see run-time validation,
authorization or framework escaping, so flows are `INFERRED` and need review.

## 5. Domain analyzers

### Embedded systems (`embedded`)

PlatformIO environments; ESP-IDF `sdkconfig` (target, flash size, secure boot and flash
encryption, reported LOW when off outside `sdkconfig.defaults`); Zephyr `prj.conf`, board
`.conf` and `west.yml`; STM32CubeMX `.ioc` (MCU, peripherals, pins, toolchain); Rust
`.cargo/config.toml` bare-metal targets; `FreeRTOSConfig.h` (stack-overflow checking off is
LOW); linker memory maps (GNU ld `MEMORY` with K/M/G in either case and inline comments, IAR `.icf`
with region bounds given by `define symbol`, Keil scatter), with overlapping regions;
device trees (model, `compatible` strings, enabled nodes). In C, C++, Arduino and Rust sources:
interrupt handlers (CMSIS vector names, `*_isr`, STM32 HAL callbacks, AVR `ISR()`,
`__attribute__((interrupt))`, `IRAM_ATTR`, `#[interrupt]`), RTOS and HAL usage, direct register
access, and inside handlers: blocking delays, heap allocation and task-context FreeRTOS calls
that have a `...FromISR` variant (MEDIUM), and console output (LOW).

### Firmware and binaries (`firmware`)

Headers are parsed from bounded, verified reads (at most a few MiB per file):

* **ELF:** class, byte order, machine, type, entry, load segments, stripped/debug state, build
  ID and compiler notes. Linux binaries get hardening facts (NX stack, PIE, full RELRO, stack
  protector, FORTIFY, RPATH); writable-and-executable segments and executable stacks are
  MEDIUM. **PE:** architecture, subsystem, ASLR/NX/CFG flags; UEFI images are reported.
* **Intel HEX, Motorola S-record** (checksums, address ranges, entry point, truncation),
  **UF2** (family IDs such as RP2040, nRF52840, SAMD, STM32 and ESP32 variants).
* **Device tree blobs and FIT images, U-Boot uImage, Android boot images, ESP32 application
  images** (with the embedded app descriptor), SquashFS, UBI, JFFS2, cramfs, ext2/3/4, TRX and
  compressed blobs; raw `.bin`/`.img` files are checked for a Cortex-M vector table and their
  entropy is measured. Version strings of U-Boot, Linux, BusyBox, OpenSSL, FreeRTOS, Zephyr,
  ESP-IDF, Dropbear, mbed TLS and lwIP are listed.
* **Build inputs:** Yocto recipes (unencrypted fetches, `${AUTOREV}`) and configuration
  (`debug-tweaks` and empty-password image features are MEDIUM), Buildroot defconfigs (an empty
  root password with root login enabled is MEDIUM), OpenWrt feeds and ESP-IDF partition tables
  (a single OTA slot is LOW).

### Hardware description languages (`hdl`)

Verilog and SystemVerilog modules, interfaces and packages; VHDL entities, architectures and
packages. Comments, strings and attributes are blanked in linear time. Per unit: ports and
directions (ANSI and non-ANSI), parameters, child instances (gate primitives are counted
separately), clock and asynchronous-reset edges, and testbench markers. Lint: blocking
assignments in clocked blocks and non-blocking assignments in combinational blocks (LOW),
several clocks in one unit (INFO) and `std_logic_arith`/`std_logic_unsigned` (LOW).
Constraints: XDC/SDC clocks, pins, I/O standards and timing exceptions (placed pins without an
I/O standard are LOW), UCF, Quartus QSF (device, family, top level), PCF, LPF and CST. Projects:
Vivado `.xpr`, ISE `.xise`, Lattice Diamond `.ldf`, Quartus `.qpf`, FuseSoC `.core` and apio,
with the device family. The code index builds the **design hierarchy**: top-level units,
depth, instance counts, unresolved types (vendor primitives or IP outside the scan) and
recursive instantiation.

### Graphics and shaders (`shaders`)

GLSL (stage from the extension, including mesh, task and ray-tracing stages, or
`#pragma shader_stage`), HLSL (registers and spaces, cbuffers, `[numthreads]`, DXR
`[shader(...)]`, Unity/Unreal `#pragma` entry points), WGSL, Metal, Godot shaders and Unity
ShaderLab (properties, sub-shaders, passes, render pipeline). Findings: different resources on
the same binding slot, GLSL without `#version`, GLSL ES fragment shaders without a default
float precision, and workgroups over 1,024 invocations (LOW). Compiled SPIR-V (version,
generator, entry points with execution models, bindings), DXBC/DXIL (shader kind and model)
and metallib files are identified from their headers.

### Frontend applications (`frontend`)

React function and class components and `memo`/`forwardRef` wrappers, with the components they
render, props and hooks; Vue single-file components (template children, `defineProps`), Svelte
components (`export let`, `$props`) and Angular `@Component` classes (selectors, templates).
Findings: hooks called inside conditions, loops or callbacks, or after an early return
(MEDIUM); list items rendered from `.map()` without `key` (LOW); effects without a dependency
array (INFO); `ignoreBuildErrors`/`ignoreDuringBuilds` and production `eval` source maps (LOW).
Routes: React Router, Vue Router, Angular `Routes` and file-system routing (Next.js pages and
app routers, Nuxt, SvelteKit, Remix, Astro; reported only when the framework is detected).
Imports name framework, state, data-fetching, routing, UI, styling, form and testing
libraries; webpack, Rspack, Vite, Rollup, esbuild, Next.js, Nuxt, SvelteKit, Angular, Parcel,
Turborepo and Nx configuration is summarized. The code index builds the **component graph**
(roots, most reused components, components never rendered).

## 6. Integration points and the integration map (`integration-points`)

Per scan: outbound HTTP calls with literal URLs (requests/httpx/aiohttp/urllib, fetch/axios/
Angular HttpClient/ky/got, RestTemplate/WebClient/OkHttp, net/http, .NET HttpClient), message
topics produced and consumed (Kafka, RabbitMQ, NATS, MQTT, SQS, Google Pub/Sub, Redis, Celery,
Socket.IO, Spring listeners), gRPC services, servers and client stubs, and package identity
from manifests. Served endpoints come from the API endpoint analyzer. Interpolated URL parts,
numbers, UUIDs and credential-like segments become `{}`: everything after a `webhooks` or
`hooks` segment and after the first segment on `hooks.*` hosts (webhook URLs carry their secret
in the path), long opaque tokens, and anything the secret registry recognizes. Files below dependency and vendor directories (`node_modules`,
`vendor`, `site-packages`, `.venv`, `target`, `third_party`, ...) describe other projects and are
skipped. Lists are capped (500 packages, root and workspace manifests first; 5,000 endpoints,
calls and topics); what a cap leaves out is counted under `truncated` and reported as an
`UNKNOWN` "Integration points truncated" finding. The `dependencies` pass lists each lockfile's
resolved packages for `pdt compare`.

`pdt compare` joins the summaries of several scans into `integration_map` edges:

| Edge | Evidence | Confidence |
|---|---|---|
| `package_dependency` | A declares a dependency on B's package name (normalized) | CONFIRMED |
| `http_api` | A calls a path that B serves, exactly or below a gateway/mount prefix; a served literal segment needs the same literal | INFERRED |
| `messaging` | A publishes a topic that B consumes; declaring a queue is not publishing | INFERRED |
| `shared_channel` | A and B use one topic or queue and neither publishes what the other consumes (no direction) | INFERRED |
| `grpc` | A uses a client stub for a service B defines or serves | INFERRED |

Reports from older scans fall back to the endpoint evidence in their API findings.

## 7. Precision checks

* Every package regex, including the lexical rule patterns, is timed against adversarial inputs and
  witnesses built from its own structure by `tests/test_regex_complexity.py`.
* Self-scan of PDT: the new analyzers report no CRITICAL, HIGH or MEDIUM finding on PDT's own
  source (performance characterizations remain at LOW).
* Each analyzer has tests that pin both detections and the cases that must not be reported
  (parameterized queries, sanitizers, validated parameters, deliberate lock hand-offs,
  constant-trip loops, comments).
