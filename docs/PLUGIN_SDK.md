# Analyzer Plugin SDK

## Writing a plugin

PDT discovers third-party analyzers through the Python entry-point group:

```toml
[project.entry-points."pdt.analyzers"]
my-analyzer = "my_package.analyzer:MyAnalyzer"
```

A plugin subclasses `project_discovery.analyzers.base.Analyzer` and provides:
- A stable unique `name` of 1–64 printable characters.
- `api_version = 1`.
- `supports(FileRecord) -> bool`.
- `analyze(Path, FileRecord) -> list[Finding]`.
- Optional `version`, `description`, `domains` and `languages` metadata.

PDT validates the plugin type, API version and unique names. Load failures are kept as scan diagnostics instead of being discarded, so `--strict` scans fail when a plugin does not load. Plugins load in entry-point name order.

## How PDT runs plugins

By default PDT never imports plugin code itself. Each plugin runs in **host processes**: separate Python interpreters that apply an operating-system sandbox, check that it works, and only then import the plugin. This means the plugin's import-time code is already sandboxed.

- **File access.** For each file the plugin supports, PDT reads the file through its verified, no-follow path and gives the host a private copy under the original file name. `record.path` still holds the real path relative to the project.
- **Environment.** Hosts get only `PATH`, locale, time-zone and Windows system variables. `HOME` and the temporary-directory variables point at the host's own folder, so tokens and cloud credentials in PDT's environment never reach a plugin.
- **Protocol.** Hosts talk to PDT in length-prefixed JSON frames over pipes, never pickle, so nothing a plugin sends can run code in PDT. A plugin that prints to stdout cannot corrupt the stream.
- **Validation.** PDT rebuilds every finding from that JSON. It always sets `analyzer` to the plugin's name, so a plugin cannot pose as a built-in analyzer. It redacts and bounds all text fields and replaces terminal control characters. Invalid findings are dropped and reported.
- **Failures.** If a host crashes, exceeds `--plugin-timeout` (default 60 s per request) or breaks the protocol, PDT kills it. The file gets an `UNKNOWN` coverage finding, and the next file starts a new host. After 3 consecutive host failures, the plugin is disabled for the rest of the scan, with a final coverage finding that says so.
- **Concurrency.** Each host holds its own plugin instance and handles one request at a time. PDT starts more hosts when analysis threads or worker processes need them. Do not rely on state shared across files.

### Isolation modes

| `--plugin-isolation` | Where plugin code runs | OS restrictions | Intended for |
|---|---|---|---|
| `sandbox` (default) | Host processes | Applied and verified; the plugin is refused if the platform minimum cannot be verified | Any third-party plugin |
| `process` | Host processes | None, but the environment, staged copies, timeouts and validation still apply | Systems where the sandbox is unavailable (for example Linux without Landlock), or plugins that need more access |
| `off` | Inside PDT, with its permissions | None | Trusted plugins that need direct file access (the pre-0.2 behavior) |

`process` and `off` print a warning for every plugin they load.

### What the sandbox enforces

Before a host imports the plugin, it attempts each forbidden action: a write outside its folder, a read of a canary file outside the allowlist, a network connection, and starting a process. The result is recorded per plugin in `metrics.plugin_isolation.plugins[].sandbox`. In `sandbox` mode, a plugin loads only when all four restrictions are verified, on Linux, macOS and Windows alike.

| | Linux | macOS | Windows |
|---|---|---|---|
| Mechanisms | Landlock, seccomp-bpf, no_new_privs, resource limits, parent-death signal | Seatbelt profile, resource limits | AppContainer without capabilities, job object, untrusted integrity level, process mitigation policies |
| File writes | Denied everywhere | Denied (except `/dev/null`) | Denied everywhere, including the container's own folder and low-integrity folders such as LocalLow |
| Mode, owner, time and xattr changes | Denied (seccomp) | Denied | Denied |
| File reads | Only the Python runtime, system libraries, PDT, the plugin's package and the staged copies | Same | Only PDT's copy of the standard-library runtime, the staged PDT and plugin packages, the staged copies, and system folders Windows opens to every app container (such as `C:\Windows`) |
| Network | Denied: no sockets except `socketpair`; TCP also denied by Landlock ABI 4+ | Denied | Denied, loopback included; names do not resolve |
| Process creation | Denied (fork, clone and exec; Landlock also denies execute) | Denied | Denied (one-process job and the child-process policy) |
| Other processes | No ptrace, memory access, signals or resource and scheduling changes | No signals to other processes | Cannot open other processes, so no termination and no memory access |
| Memory limit (`--plugin-memory-mb`, default 4096) | `RLIMIT_AS` | Not enforced by macOS | Job memory limit |
| Lifetime | Dies with PDT | Exits within 1 s of PDT | Dies with PDT (kill-on-close job) |

On Windows the network check is threefold: the host's token must be an AppContainer with no capabilities, a connection to a loopback listener that PDT holds outside the container must fail (Windows drops it silently, so it times out), and a connection to the unrouted documentation address `192.0.2.1` must fail. The probe never contacts a real host.

On every CI runner (Linux, macOS and Windows, CPython 3.11–3.14), the test suite runs a hostile test plugin under the real sandbox and checks the file-write, file-read, network and process-creation rows. On Windows a second hostile plugin also tries to read the project, PDT's database and the user's packages, to write into the staged packages, the runtime copy and the container's folder, to send UDP and resolve names, and to open PDT's process. Run `pdt capabilities` to see what the sandbox verifies on a given machine and whether each installed plugin loads.

### How Windows hosts are prepared

An AppContainer can read only what is granted to it, so PDT prepares three folders and grants the container read access to them alone. It never changes the permissions of the user's Python installation, site-packages or projects.

- **Runtime copy.** The interpreter, its `DLLs` folder and the standard library (no `site-packages`, tests, IDLE or Tk) are copied once per Python build to `%LOCALAPPDATA%\ProjectDiscoveryTool\plugin-runtime` (about 40 MB). Set `PDT_PLUGIN_RUNTIME_DIR` to use another folder.
- **Staged packages.** For each plugin, PDT copies its own package, the plugin's top-level module or package, and the installed files of every distribution the plugin requires (its `Requires-Dist`, without extras) into the scan's plugin folder. A plugin whose files and dependencies exceed 512 MiB is refused; run it with `--plugin-isolation process` instead.
- **Staging folders.** Each host's folder, which receives the private copy of every analyzed file.

Hosts run in the per-user AppContainer profile `ProjectDiscoveryTool.PluginHost`, which PDT creates on first use and keeps, as browsers keep theirs. Hosts cannot write to the profile's folder, and PDT deletes any file found there before its first host starts. To remove the profile, run `python -c "import ctypes; ctypes.windll.userenv.DeleteAppContainerProfile('ProjectDiscoveryTool.PluginHost')"` and delete the runtime folder.

## Writing plugins that work in the sandbox

- Read only the `path` passed to `analyze()`, and use `record.path` in titles and evidence. Sibling files are not available; each call receives one file.
- Do not write files, open network connections or start processes. Each of these raises `PermissionError` in the sandbox. Keep working state in memory.
- Import everything you need at module level. Later imports work only from the Python runtime, the plugin's own package and, on Windows, the distributions the plugin declares in `Requires-Dist`. Declare every third-party package you import: on Windows an undeclared one is not staged and cannot be imported.
- PDT sets `Finding.analyzer` itself. Other limits:

  | Item | Limit |
  |---|---|
  | `category` | Must match `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}` |
  | `title` / `detail` | 300 / 8,000 characters |
  | `evidence` | 64 items of up to 1,000 characters each |
  | `code_evidence` | 64 lines |
  | Findings per file | 5,000 |
  | File size handed to a plugin | 1 GiB |

- `concurrent_safe` matters only with `--plugin-isolation off`, because isolated hosts never run requests in parallel.
- Isolated plugins contribute findings only. Code facts (`project_discovery.code_facts.emit_fact`), which feed the cross-file code index, are not part of the host protocol, so calls to them inside a host are ignored. A plugin run with `--plugin-isolation off` executes inside PDT's fact collector and can record facts.

## Limits of the isolation

- **Installation is not isolated.** A package that runs code when it is installed, or that ships a `.pth` startup hook, runs with full permissions in every Python process of that environment, PDT included. The sandbox covers the code PDT loads as a plugin. Install plugins only from sources you trust, ideally into an environment used only for PDT.
- **Windows system folders stay readable.** Files that Windows grants to every app container, such as those under `C:\Windows` and `C:\Program Files`, remain readable to plugins. They do not include the project, PDT's output or the user's files.
- **Windows Python builds with libraries outside `DLLs`.** The runtime copy holds the interpreter, `DLLs` and the standard library. Builds that keep native libraries elsewhere, such as conda's `Library\bin`, can fail to import the affected standard-library modules inside the sandbox.
- **Plugins see what they analyze.** The sandbox limits where a plugin can reach, not what it learns from the files PDT gives it.
- **Metadata stays visible.** On Linux and macOS, `stat()` (file names, sizes and times) is not restricted, although reading contents and listing directories outside the allowlist are.
- **Linux needs Landlock.** Without kernel Landlock support (Linux 5.13+, with `landlock` in the active LSM list), `sandbox` mode refuses plugins. Use `--plugin-isolation process` only if you accept the reduced protection.
- **Runtime paths must not contain the project.** If the Python runtime or the plugin's package directory contains the scanned project (for example, a scan of a `site-packages` subdirectory), reads cannot be restricted, and `sandbox` mode refuses the plugin on Linux and macOS.

## Report fields

- `metrics.plugin_isolation` holds the mode, timeout, memory limit, required restrictions and one entry per discovered plugin: entry point, distribution, name, version, `loaded` or `failed` with the error, and the verified sandbox report.
- `metrics.analyzer_registry[]` marks each analyzer's `origin` (`builtin` or `plugin`) and `isolation`.
