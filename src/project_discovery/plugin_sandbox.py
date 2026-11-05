"""Operating-system sandbox for isolated plugin hosts.

A plugin host calls :func:`lock_down` before it imports any plugin code, then
:func:`run_probes` verifies each restriction by attempting the forbidden action. What
each platform enforces:

Linux
    Landlock: no filesystem writes, no program execution, and reads only beneath the
    Python runtime, the plugin's own files and the host's staging directory (TCP is
    also denied on Landlock ABI 4+, and signals and abstract sockets are scoped on
    ABI 6+). A seccomp-bpf filter denies sockets, process creation, ptrace, namespaces,
    mounts, keyrings, io_uring, terminal injection and signals to other processes.
    Plus no_new_privs, RLIMIT_AS/CORE/FSIZE and a parent-death signal.
macOS
    A Seatbelt profile that denies network access, process creation, Mach service
    lookups, signals to other processes, file writes, and file reads outside the same
    allowlist. Plus RLIMIT_CORE/FSIZE.
Windows
    A job object created by PDT (no child processes, a memory limit, UI limits, and the
    host dies with PDT), untrusted integrity level (no writes anywhere, including
    low-integrity locations such as the LocalLow folder, and no access to PDT's
    process) and process mitigation policies. Windows has no unprivileged way to deny file reads
    or network access to an interpreter installed in the user profile, so those two stay
    open there and reports say so.
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import signal
import socket
import struct
import subprocess
import sys
from typing import Callable

FILESYSTEM_WRITES = "filesystem_writes"
FILESYSTEM_READS = "filesystem_reads"
NETWORK = "network"
PROCESS_CREATION = "process_creation"
RESTRICTIONS = (FILESYSTEM_WRITES, FILESYSTEM_READS, NETWORK, PROCESS_CREATION)

_LINUX = sys.platform.startswith("linux")
_MACOS = sys.platform == "darwin"
_WINDOWS = os.name == "nt"


def required_restrictions(platform_name: str = sys.platform) -> tuple[str, ...]:
    """Restrictions that sandbox mode must verify before a plugin may load."""
    if platform_name == "win32":
        return (FILESYSTEM_WRITES, PROCESS_CREATION)
    # Linux and macOS enforce all four; other platforms have no backend and fail closed.
    return RESTRICTIONS


def _same_or_inside(path: str, parent: str) -> bool:
    path, parent = os.path.normcase(path), os.path.normcase(parent)
    try:
        return os.path.commonpath([path, parent]) == parent
    except ValueError:  # different drives
        return False


def _overlaps(first: str, second: str) -> bool:
    return _same_or_inside(first, second) or _same_or_inside(second, first)


_LINUX_SYSTEM_DIRS = (
    "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/nix/store", "/gnu/store",
    "/etc/ld.so.conf.d", "/sys/devices/system/cpu", "/proc/self",
)
_LINUX_SYSTEM_FILES = (
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/localtime", "/etc/mime.types",
    "/etc/os-release", "/dev/urandom", "/dev/random",
)
_MACOS_SYSTEM_DIRS = (
    "/System", "/usr", "/Library/Frameworks", "/Library/Developer/CommandLineTools",
    "/private/var/db/timezone", "/opt/homebrew", "/dev",
)


def read_allowlist(config: dict, essential_paths=()) -> tuple[list[str], list[str], list[str]]:
    """Return (directories, files, exposed) the sandboxed host may read.

    Essential paths (the interpreter, system libraries, PDT and the plugin's own
    package) stay readable even inside the scanned project, for example a virtual
    environment in the project directory. An essential path that contains the project
    or PDT's output is listed in ``exposed``, and reads are then not reported as
    restricted. Other ``sys.path`` entries that overlap either are dropped.
    """
    excluded = [os.path.realpath(item) for item in config.get("exclude_paths", ())]
    directories: list[str] = []
    files: list[str] = []
    exposed: list[str] = []

    def add(item: str, *, essential: bool) -> None:
        if not item:
            return
        real = os.path.realpath(item)
        if not os.path.exists(real) or real in directories or real in files:
            return
        overlapping = [path for path in excluded if _overlaps(real, path)]
        if overlapping and not essential:
            return
        exposed.extend(
            path for path in overlapping
            if _same_or_inside(path, real) and path not in exposed
        )
        (directories if os.path.isdir(real) else files).append(real)

    for item in (sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix):
        add(item, essential=True)
    system_dirs = _LINUX_SYSTEM_DIRS if _LINUX else _MACOS_SYSTEM_DIRS if _MACOS else ()
    for item in (*system_dirs, *(_LINUX_SYSTEM_FILES if _LINUX else ()), *essential_paths):
        add(item, essential=True)
    for item in sys.path:
        add(item, essential=False)
    # The staging directory is the one place PDT hands the plugin, even though it lives
    # under PDT's (otherwise excluded) output directory.
    scratch = os.path.realpath(config["scratch"])
    if scratch not in directories:
        directories.append(scratch)
    return directories, files, exposed


# --------------------------------------------------------------------------- Linux

_PR_SET_PDEATHSIG = 1
_PR_SET_NO_NEW_PRIVS = 38
_SYS_LANDLOCK_CREATE_RULESET = 444  # identical on every architecture since Linux 5.1
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_FS_EXECUTE = 1 << 0
_FS_WRITE_FILE = 1 << 1
_FS_READ_FILE = 1 << 2
_FS_READ_DIR = 1 << 3
_FS_REFER = 1 << 13
_FS_TRUNCATE = 1 << 14
_FS_IOCTL_DEV = 1 << 15
_NET_BIND_TCP = 1 << 0
_NET_CONNECT_TCP = 1 << 1
_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
_SCOPE_SIGNAL = 1 << 1


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


def _path_beneath_attr(access: int, descriptor: int):
    # struct landlock_path_beneath_attr is packed: __u64 allowed_access, __s32 parent_fd.
    return ctypes.create_string_buffer(struct.pack("=Qi", access, descriptor), 12)


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _syscall(libc, number: int, *args) -> int:
    # syscall(2) is variadic: pass every integer as a full-width long.
    converted = [ctypes.c_long(item) if isinstance(item, int) else item for item in args]
    result = libc.syscall(ctypes.c_long(number), *converted)
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def _prctl(libc, option: int, value: int) -> None:
    if libc.prctl(
        ctypes.c_int(option), ctypes.c_ulong(value),
        ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0),
    ) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _landlock(libc, directories: list[str], files: list[str]) -> int:
    abi = _syscall(libc, _SYS_LANDLOCK_CREATE_RULESET, None, 0, _LANDLOCK_CREATE_RULESET_VERSION)
    handled_fs = (1 << 13) - 1  # ABI 1: execute, read/write files, read dirs, all creation/removal
    if abi >= 2:
        handled_fs |= _FS_REFER
    if abi >= 3:
        handled_fs |= _FS_TRUNCATE
    if abi >= 5:
        handled_fs |= _FS_IOCTL_DEV
    attr = _LandlockRulesetAttr(
        handled_fs,
        _NET_BIND_TCP | _NET_CONNECT_TCP if abi >= 4 else 0,
        _SCOPE_ABSTRACT_UNIX_SOCKET | _SCOPE_SIGNAL if abi >= 6 else 0,
    )
    ruleset = _syscall(libc, _SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    rules = [(path, _FS_READ_FILE | _FS_READ_DIR) for path in directories]
    rules += [(path, _FS_READ_FILE) for path in files]
    rules.append(("/dev/null", _FS_READ_FILE | _FS_WRITE_FILE | (_FS_TRUNCATE if abi >= 3 else 0)))
    try:
        for path, access in rules:
            try:
                descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except OSError:
                continue
            try:
                rule = _path_beneath_attr(access & handled_fs, descriptor)
                _syscall(libc, _SYS_LANDLOCK_ADD_RULE, ruleset, _LANDLOCK_RULE_PATH_BENEATH, rule, 0)
            finally:
                os.close(descriptor)
        _syscall(libc, _SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0)
    finally:
        os.close(ruleset)
    return abi


_SECCOMP_SET_MODE_FILTER = 1
_SECCOMP_FILTER_FLAG_TSYNC = 1
_RET_KILL_PROCESS = 0x80000000
_RET_ERRNO = 0x00050000
_RET_ALLOW = 0x7FFF0000
_LD_ABS = 0x20
_JEQ = 0x15
_JGE = 0x35
_JSET = 0x45
_RET = 0x06
_CLONE_THREAD = 0x00010000
_AF_UNIX = 1
_TIOCSTI = 0x5412

# Syscall numbers for the 64-bit architectures the filter supports.
_SYSCALLS = {
    "x86_64": dict(
        audit_arch=0xC000003E, seccomp=317, ioctl=16, socket=41, socketpair=53, clone=56,
        fork=57, vfork=58, execve=59, kill=62, truncate=76, chmod=90, fchmod=91, chown=92,
        fchown=93, lchown=94, ptrace=101, rt_sigqueueinfo=129, utime=132, setpriority=141,
        sched_setparam=142, sched_setscheduler=144, pivot_root=155, chroot=161, mount=165,
        umount2=166, setxattr=188, lsetxattr=189, fsetxattr=190, removexattr=197,
        lremovexattr=198, fremovexattr=199, tkill=200, sched_setaffinity=203, tgkill=234,
        utimes=235, add_key=248, request_key=249, keyctl=250, ioprio_set=251,
        inotify_add_watch=254, migrate_pages=256, fchownat=260, futimesat=261, fchmodat=268,
        unshare=272, move_pages=279, utimensat=280, rt_tgsigqueueinfo=297, perf_event_open=298,
        fanotify_init=300, fanotify_mark=301, prlimit64=302, name_to_handle_at=303,
        open_by_handle_at=304, setns=308, process_vm_readv=310, process_vm_writev=311,
        kcmp=312, sched_setattr=314, bpf=321, execveat=322, userfaultfd=323,
    ),
    "aarch64": dict(
        audit_arch=0xC00000B7, seccomp=277, setxattr=5, lsetxattr=6, fsetxattr=7,
        removexattr=14, lremovexattr=15, fremovexattr=16, inotify_add_watch=27, ioctl=29,
        ioprio_set=30, umount2=39, mount=40, pivot_root=41, truncate=45, chroot=51, fchmod=52,
        fchmodat=53, fchownat=54, fchown=55, utimensat=88, unshare=97, ptrace=117,
        sched_setparam=118, sched_setscheduler=119, sched_setaffinity=122, kill=129, tkill=130,
        tgkill=131, rt_sigqueueinfo=138, setpriority=140, socket=198, socketpair=199,
        add_key=217, request_key=218, keyctl=219, clone=220, execve=221, migrate_pages=238,
        move_pages=239, rt_tgsigqueueinfo=240, perf_event_open=241, prlimit64=261,
        fanotify_init=262, fanotify_mark=263, name_to_handle_at=264, open_by_handle_at=265,
        setns=268, process_vm_readv=270, process_vm_writev=271, kcmp=272, sched_setattr=274,
        bpf=280, execveat=281, userfaultfd=282,
    ),
}
# Added after the per-architecture tables were unified (same number everywhere).
_UNIFIED_SYSCALLS = dict(
    pidfd_send_signal=424, io_uring_setup=425, io_uring_enter=426, io_uring_register=427,
    open_tree=428, move_mount=429, fsopen=430, fsconfig=431, fsmount=432, fspick=433,
    clone3=435, pidfd_getfd=438, process_madvise=440, mount_setattr=442, fchmodat2=452,
    setxattrat=463, removexattrat=466,
)
_DENIED_EPERM = (
    # Program execution, process creation and access to other processes.
    "execve", "execveat", "fork", "vfork", "ptrace", "process_vm_readv", "process_vm_writev",
    "process_madvise", "pidfd_getfd", "pidfd_send_signal", "tkill", "kcmp", "migrate_pages",
    "move_pages", "setpriority", "ioprio_set",
    # Mounts, namespaces, keyrings and kernel interfaces.
    "mount", "umount2", "pivot_root", "chroot", "unshare", "setns", "keyctl", "add_key",
    "request_key", "bpf", "perf_event_open", "userfaultfd", "name_to_handle_at",
    "open_by_handle_at", "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick",
    "mount_setattr", "fanotify_init", "fanotify_mark", "inotify_add_watch",
    # Metadata changes that Landlock does not cover: modes, owners, times, attributes.
    "chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "fchown", "lchown", "fchownat",
    "utime", "utimes", "futimesat", "utimensat", "setxattr", "lsetxattr", "fsetxattr",
    "setxattrat", "removexattr", "lremovexattr", "fremovexattr", "removexattrat", "truncate",
)
# Resource and scheduling calls are allowed only on the calling process (pid 0), so a
# plugin cannot throttle PDT.
_SELF_ONLY = ("prlimit64", "sched_setaffinity", "sched_setparam", "sched_setscheduler", "sched_setattr")
# ENOSYS makes glibc fall back from clone3 to clone, whose flags the filter can inspect.
_DENIED_ENOSYS = ("clone3", "io_uring_setup", "io_uring_enter", "io_uring_register")


def _seccomp_architecture() -> str | None:
    if struct.calcsize("P") != 8:
        return None  # a 32-bit interpreter uses a different syscall ABI
    machine = platform.machine().lower()
    return {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(machine)


def seccomp_program(architecture: str, own_pid: int) -> list[tuple[int, int, int, int]]:
    """Build the BPF filter as (code, jt, jf, k) instructions."""
    table = {**_SYSCALLS[architecture], **_UNIFIED_SYSCALLS}
    eperm, eacces, enosys = _RET_ERRNO | errno.EPERM, _RET_ERRNO | errno.EACCES, _RET_ERRNO | errno.ENOSYS
    program = [
        (_LD_ABS, 0, 0, 4),  # seccomp_data.arch
        (_JEQ, 1, 0, table["audit_arch"]),
        (_RET, 0, 0, _RET_KILL_PROCESS),
        (_LD_ABS, 0, 0, 0),  # seccomp_data.nr
    ]
    if architecture == "x86_64":
        program += [(_JGE, 0, 1, 0x40000000), (_RET, 0, 0, _RET_KILL_PROCESS)]  # x32 ABI
    simple = [(table["socket"], eacces)]
    simple += [(table[name], eperm) for name in _DENIED_EPERM if name in table]
    simple += [(table[name], enosys) for name in _DENIED_ENOSYS]
    for number, action in simple:
        program += [(_JEQ, 0, 1, number), (_RET, 0, 0, action)]

    def argument_check(number: int, argument: int, test: int, value: int, matched: int, other: int) -> None:
        # Each block ends in a return because loading the argument replaces the syscall
        # number in the accumulator.
        program.extend([
            (_JEQ, 0, 4, number),
            (_LD_ABS, 0, 0, 16 + 8 * argument),  # low 32 bits of the argument
            (test, 0, 1, value),
            (_RET, 0, 0, matched),
            (_RET, 0, 0, other),
        ])

    argument_check(table["ioctl"], 1, _JEQ, _TIOCSTI, eperm, _RET_ALLOW)  # terminal injection
    argument_check(table["socketpair"], 0, _JEQ, _AF_UNIX, _RET_ALLOW, eacces)
    argument_check(table["clone"], 0, _JSET, _CLONE_THREAD, _RET_ALLOW, eperm)  # threads only
    for name in ("kill", "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo"):
        argument_check(table[name], 0, _JEQ, own_pid, _RET_ALLOW, eperm)  # only this process
    for name in _SELF_ONLY:
        argument_check(table[name], 0, _JEQ, 0, _RET_ALLOW, eperm)
    program.append((_RET, 0, 0, _RET_ALLOW))
    return program


def _seccomp(libc, architecture: str) -> None:
    instructions = seccomp_program(architecture, os.getpid())
    array = (_SockFilter * len(instructions))(*(_SockFilter(*item) for item in instructions))
    program = _SockFprog(len(instructions), ctypes.cast(array, ctypes.POINTER(_SockFilter)))
    table = _SYSCALLS[architecture]
    _syscall(libc, table["seccomp"], _SECCOMP_SET_MODE_FILTER, _SECCOMP_FILTER_FLAG_TSYNC, ctypes.byref(program))


def resource_limits(config: dict, *, sandbox: bool = True) -> list[str]:
    """POSIX resource limits; process mode (``sandbox=False``) keeps only memory and core."""
    if os.name == "nt":
        return []  # the job object PDT creates carries the memory limit
    import resource

    applied = []
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core dumps of file contents
    applied.append("rlimit-core")
    if sandbox:
        # Regular files cannot grow; EFBIG instead of SIGXFSZ. Pipes are unaffected.
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        applied.append("rlimit-fsize")
    limit = config.get("memory_limit_bytes") or 0
    if limit and _LINUX:  # macOS does not enforce RLIMIT_AS
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        applied.append("rlimit-as")
    return applied


def _linux_lock_down(config: dict, directories, files, mechanisms, errors) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    mechanisms.extend(resource_limits(config))
    _prctl(libc, _PR_SET_PDEATHSIG, signal.SIGKILL)
    if os.getppid() != config["parent_pid"]:
        os._exit(70)  # PDT exited before the death signal was armed
    _prctl(libc, _PR_SET_NO_NEW_PRIVS, 1)
    mechanisms.append("no-new-privs")
    try:
        mechanisms.append(f"landlock-abi-{_landlock(libc, directories, files)}")
    except OSError as exc:
        errors.append(f"landlock unavailable: {exc.strerror or exc}")
    architecture = _seccomp_architecture()
    if architecture is None:
        errors.append(f"seccomp filter unavailable for {platform.machine()} in this interpreter")
        return
    try:
        _seccomp(libc, architecture)
        mechanisms.append("seccomp-bpf")
    except OSError as exc:
        errors.append(f"seccomp unavailable: {exc.strerror or exc}")


# --------------------------------------------------------------------------- macOS

def seatbelt_profile(directories: list[str], files: list[str]) -> str:
    """Seatbelt (SBPL) source for the host. Deny rules only, so rule order is irrelevant."""
    def quote(path: str) -> str:
        return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'

    readable = " ".join(
        [f"(require-not (subpath {quote(path)}))" for path in directories]
        + [f"(require-not (literal {quote(path)}))" for path in files]
    )
    return "\n".join((
        "(version 1)",
        "(allow default)",
        "(deny network*)",
        "(deny process-exec*)",
        "(deny process-fork)",
        "(deny mach-lookup)",
        "(deny signal (target others))",
        '(deny file-write* (require-not (literal "/dev/null")))',
        f"(deny file-read-data (require-all {readable}))",
    ))


def _macos_lock_down(config: dict, directories, files, mechanisms, errors) -> None:
    mechanisms.extend(resource_limits(config))
    libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    sandbox_init = libsystem.sandbox_init
    sandbox_init.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char_p)]
    sandbox_init.restype = ctypes.c_int
    error = ctypes.c_char_p()
    profile = seatbelt_profile(directories, files).encode("utf-8", "surrogateescape")
    if sandbox_init(profile, 0, ctypes.byref(error)) != 0:
        message = (error.value or b"unknown error").decode("utf-8", "replace")
        libsystem.sandbox_free_error(error)
        errors.append(f"seatbelt unavailable: {message}")
        return
    mechanisms.append("seatbelt")


# --------------------------------------------------------------------------- Windows

_TOKEN_QUERY = 0x0008
_TOKEN_ADJUST_DEFAULT = 0x0080
_TOKEN_INTEGRITY_LEVEL = 25
_SE_GROUP_INTEGRITY = 0x20
_UNTRUSTED_INTEGRITY_SID = "S-1-16-0"
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
_JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_BASIC_UI_RESTRICTIONS = 4
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_UILIMIT_ALL = 0xFF
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
# (policy id, flags) for SetProcessMitigationPolicy.
_MITIGATIONS = (
    ("no-child-processes", 13, 0x1),        # ProcessChildProcessPolicy
    ("no-extension-points", 6, 0x1),        # ProcessExtensionPointDisablePolicy
    ("no-remote-or-low-label-images", 10, 0x3),  # ProcessImageLoadPolicy
)


def _windows_api():
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.SetProcessMitigationPolicy.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    return wintypes, kernel32, advapi32


def _win_check(result) -> None:
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", ctypes.c_uint32)]


class _TokenMandatoryLabel(ctypes.Structure):
    _fields_ = [("Label", _SidAndAttributes)]


class _JobBasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _JobExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobBasicLimits), ("IoInfo", ctypes.c_uint64 * 6),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class WindowsJob:
    """A kill-on-close job that holds one plugin host (created by PDT, not the host).

    ``confine`` (sandbox mode) also forbids child processes and restricts UI access;
    without it the job only bounds memory and ties the host's lifetime to PDT.
    """

    def __init__(self, memory_limit_bytes: int, *, confine: bool = True) -> None:
        _, self._kernel32, _ = _windows_api()
        self.handle = self._kernel32.CreateJobObjectW(None, None)
        _win_check(self.handle)
        try:
            limits = _JobExtendedLimits()
            flags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            if confine:
                flags |= _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                limits.BasicLimitInformation.ActiveProcessLimit = 1
            if memory_limit_bytes:
                flags |= _JOB_OBJECT_LIMIT_PROCESS_MEMORY
                limits.ProcessMemoryLimit = memory_limit_bytes
            limits.BasicLimitInformation.LimitFlags = flags
            _win_check(self._kernel32.SetInformationJobObject(
                self.handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits), ctypes.sizeof(limits),
            ))
            if confine:
                ui = ctypes.c_uint32(_JOB_OBJECT_UILIMIT_ALL)
                _win_check(self._kernel32.SetInformationJobObject(
                    self.handle, _JOB_OBJECT_BASIC_UI_RESTRICTIONS, ctypes.byref(ui), ctypes.sizeof(ui),
                ))
        except OSError:
            self.close()
            raise

    def assign(self, pid: int) -> None:
        process = self._kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
        _win_check(process)
        try:
            _win_check(self._kernel32.AssignProcessToJobObject(self.handle, process))
        finally:
            self._kernel32.CloseHandle(process)

    def terminate(self) -> None:
        if self.handle:
            self._kernel32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if self.handle:
            self._kernel32.CloseHandle(self.handle)  # kill-on-close ends any survivor
            self.handle = None


def _set_untrusted_integrity(wintypes, kernel32, advapi32) -> None:
    token = wintypes.HANDLE()
    _win_check(advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY | _TOKEN_ADJUST_DEFAULT, ctypes.byref(token),
    ))
    try:
        sid = ctypes.c_void_p()
        _win_check(advapi32.ConvertStringSidToSidW(_UNTRUSTED_INTEGRITY_SID, ctypes.byref(sid)))
        try:
            label = _TokenMandatoryLabel(_SidAndAttributes(sid, _SE_GROUP_INTEGRITY))
            size = ctypes.sizeof(label) + advapi32.GetLengthSid(sid)
            _win_check(advapi32.SetTokenInformation(
                token, _TOKEN_INTEGRITY_LEVEL, ctypes.byref(label), size,
            ))
        finally:
            kernel32.LocalFree(sid)
    finally:
        kernel32.CloseHandle(token)


def _windows_lock_down(config: dict, mechanisms, errors) -> None:
    wintypes, kernel32, advapi32 = _windows_api()
    try:
        _set_untrusted_integrity(wintypes, kernel32, advapi32)
        mechanisms.append("untrusted-integrity")
    except OSError as exc:
        errors.append(f"untrusted integrity level unavailable: {exc}")
    for name, policy, flags in _MITIGATIONS:
        value = ctypes.c_uint32(flags)
        if kernel32.SetProcessMitigationPolicy(policy, ctypes.byref(value), ctypes.sizeof(value)):
            mechanisms.append(name)
        else:
            errors.append(f"mitigation {name} unavailable: {ctypes.WinError(ctypes.get_last_error())}")


# --------------------------------------------------------------------------- shared

def lock_down(config: dict, directories: list[str], files: list[str]) -> dict:
    """Apply this platform's sandbox to the current (single-threaded) process."""
    mechanisms: list[str] = []
    errors: list[str] = []
    if _LINUX:
        _linux_lock_down(config, directories, files, mechanisms, errors)
    elif _MACOS:
        _macos_lock_down(config, directories, files, mechanisms, errors)
    elif _WINDOWS:
        _windows_lock_down(config, mechanisms, errors)
    else:
        errors.append(f"no sandbox backend for {sys.platform}")
    return {"platform": sys.platform, "mechanisms": mechanisms, "errors": errors}


# Windows reports denials as ERROR_ACCESS_DENIED, ERROR_CHILD_PROCESS_BLOCKED (the
# mitigation policy), a job's ERROR_NOT_ENOUGH_QUOTA or WSAEACCES; POSIX as EPERM/EACCES
# (or EROFS for writes).
_DENIAL_WINERRORS = {5, 367, 1816, 10013}
_DENIAL_ERRNOS = {errno.EPERM, errno.EACCES, errno.EROFS, 10013}


def is_denial(exc: BaseException) -> bool:
    if isinstance(exc, PermissionError):
        return True
    if isinstance(exc, OSError):
        return getattr(exc, "winerror", None) in _DENIAL_WINERRORS or exc.errno in _DENIAL_ERRNOS
    return False


def _denied(action: Callable[[], object]) -> bool:
    try:
        action()
    except Exception as exc:
        return is_denial(exc)
    return False


def prepare_probes() -> socket.socket | None:
    """Before lock-down: a loopback listener that the network probe tries to reach."""
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        return listener
    except OSError:
        return None


def _write_probe(path: str) -> None:
    with open(path, "xb") as stream:
        stream.write(b"x")


def _read_probe(path: str) -> None:
    with open(path, "rb") as stream:
        stream.read(1)


def _spawn_probe() -> None:
    # Inherit the standard handles: opening the null device can itself be denied (on
    # Windows at untrusted integrity), which would hide whether process creation is.
    subprocess.run([sys.executable, "-I", "-S", "-c", "pass"], timeout=30, check=False)


def _network_denied(listener: socket.socket | None) -> bool:
    if listener is None:
        return False
    port = listener.getsockname()[1]
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return is_denial(exc)
    try:
        client.settimeout(5)
        client.connect(("127.0.0.1", port))
    except OSError as exc:
        return is_denial(exc)
    finally:
        client.close()
    return False


def run_probes(config: dict, listener: socket.socket | None) -> dict[str, bool]:
    """After lock-down: attempt each forbidden action; True means it was denied."""
    try:
        token = f"host-{os.getpid()}"
        writes = _denied(lambda: _write_probe(os.path.join(config["probe_write_dir"], token)))
        # The host must not be able to write even to its own staging directory.
        writes = writes and _denied(lambda: _write_probe(os.path.join(config["scratch"], token)))
        results = {
            FILESYSTEM_WRITES: writes,
            FILESYSTEM_READS: _denied(lambda: _read_probe(config["probe_canary"])),
            NETWORK: _network_denied(listener),
            PROCESS_CREATION: _denied(_spawn_probe),
        }
    finally:
        if listener is not None:
            listener.close()
    # The staging directory must stay readable, or the sandbox is unusable.
    _read_probe(os.path.join(config["scratch"], "readable.probe"))
    return results
