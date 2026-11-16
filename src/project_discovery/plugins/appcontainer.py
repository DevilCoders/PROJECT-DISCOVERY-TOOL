"""Windows AppContainer launch for sandboxed plugin hosts (the coordinator's side).

On Windows, ``--plugin-isolation sandbox`` starts every plugin host inside an
AppContainer that holds no capabilities. The operating system then denies the host all
network access (loopback included), access to other processes, and every file whose
access list does not name the container. PDT names the container only on folders that
PDT itself creates:

* a copy of the Python runtime's standard library, made once per Python build and
  cached under ``%LOCALAPPDATA%\\ProjectDiscoveryTool\\plugin-runtime`` (no
  third-party packages are copied there);
* a per-scan copy of PDT's own package, the plugin's top-level module or package and
  the installed files of the plugin distribution's dependencies;
* each host's staging folder, which receives the private copy of every analyzed file.

The user's Python installation, site-packages and project files are never
re-permissioned. Inside the container the host still lowers itself to untrusted
integrity and applies mitigation policies, and PDT's job object forbids child
processes (see :mod:`project_discovery.plugins.sandbox`).
"""
from __future__ import annotations

import atexit
import ctypes
import hashlib
import importlib.metadata
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import threading
import uuid
from pathlib import Path

APPCONTAINER_NAME = "ProjectDiscoveryTool.PluginHost"
# A plugin whose files and dependencies exceed this is refused rather than copied.
MAX_STAGED_BYTES = 512 * 1024 * 1024
MAX_STAGED_DISTRIBUTIONS = 200
_COMPLETE = ".pdt-complete"
# Standard-library folders a plugin host never needs.
_RUNTIME_SKIPPED = frozenset({
    "site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3",
})
# Variables a host is given. CreateProcess refuses an AppContainer without the profile
# variables, which Windows then points at the container's own folder.
_ENVIRONMENT = (
    "PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP",
)
_PDT_DISTRIBUTION = "project-discovery-tool"

_ERROR_ALREADY_EXISTS_HRESULT = -2147024713  # HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x4
_GENERIC_READ_EXECUTE = 0x80000000 | 0x20000000
_GRANT_ACCESS = 1
_SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3
_TRUSTEE_IS_SID = 0
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
_STARTF_USESTDHANDLES = 0x00000100
_CREATE_SUSPENDED = 0x00000004
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_CREATE_NO_WINDOW = 0x08000000
_WAIT_TIMEOUT = 0x00000102
_INFINITE = 0xFFFFFFFF


class AppContainerError(OSError):
    """The AppContainer, its runtime copy or a staged plugin could not be prepared."""


def available() -> bool:
    """Whether this Windows offers AppContainers (Windows 8 / Server 2012 and later)."""
    if os.name != "nt":
        return False
    try:
        return hasattr(ctypes.WinDLL("userenv"), "CreateAppContainerProfile")
    except OSError:
        return False


class _Trustee(ctypes.Structure):
    _fields_ = [
        ("pMultipleTrustee", ctypes.c_void_p), ("MultipleTrusteeOperation", ctypes.c_int),
        ("TrusteeForm", ctypes.c_int), ("TrusteeType", ctypes.c_int), ("ptstrName", ctypes.c_void_p),
    ]


class _ExplicitAccess(ctypes.Structure):
    _fields_ = [
        ("grfAccessPermissions", ctypes.c_uint32), ("grfAccessMode", ctypes.c_int),
        ("grfInheritance", ctypes.c_uint32), ("Trustee", _Trustee),
    ]


class _SecurityCapabilities(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", ctypes.c_void_p), ("Capabilities", ctypes.c_void_p),
        ("CapabilityCount", ctypes.c_uint32), ("Reserved", ctypes.c_uint32),
    ]


def _api():
    from ctypes import wintypes as w

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    userenv.CreateAppContainerProfile.restype = ctypes.c_long
    userenv.CreateAppContainerProfile.argtypes = [
        w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, ctypes.c_void_p, w.DWORD, ctypes.POINTER(ctypes.c_void_p),
    ]
    userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [w.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    userenv.GetAppContainerFolderPath.restype = ctypes.c_long
    userenv.GetAppContainerFolderPath.argtypes = [w.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetNamedSecurityInfoW.restype = w.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = [
        w.LPCWSTR, ctypes.c_int, w.DWORD, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.SetEntriesInAclW.restype = w.DWORD
    advapi32.SetEntriesInAclW.argtypes = [w.ULONG, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.SetNamedSecurityInfoW.restype = w.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_int, w.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [w.HANDLE]
    kernel32.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p, w.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p,
    ]
    kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel32.CreateProcessW.argtypes = [
        w.LPCWSTR, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD,
        ctypes.c_void_p, w.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p,
    ]
    kernel32.ResumeThread.argtypes = [w.HANDLE]
    kernel32.ResumeThread.restype = w.DWORD
    kernel32.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    kernel32.WaitForSingleObject.restype = w.DWORD
    kernel32.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
    kernel32.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    return w, kernel32, advapi32, userenv, ole32


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32), ("lpReserved", ctypes.c_wchar_p), ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p), ("dwX", ctypes.c_uint32), ("dwY", ctypes.c_uint32),
        ("dwXSize", ctypes.c_uint32), ("dwYSize", ctypes.c_uint32), ("dwXCountChars", ctypes.c_uint32),
        ("dwYCountChars", ctypes.c_uint32), ("dwFillAttribute", ctypes.c_uint32), ("dwFlags", ctypes.c_uint32),
        ("wShowWindow", ctypes.c_uint16), ("cbReserved2", ctypes.c_uint16), ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", ctypes.c_void_p), ("hStdOutput", ctypes.c_void_p), ("hStdError", ctypes.c_void_p),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [("StartupInfo", _StartupInfo), ("lpAttributeList", ctypes.c_void_p)]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_uint32), ("dwThreadId", ctypes.c_uint32),
    ]


class AppContainer:
    """The per-user AppContainer profile that plugin hosts run in.

    The profile is created on first use and kept, as browsers keep theirs. Its only
    storage is the container's own folder, which hosts cannot write to once they have
    lowered themselves to untrusted integrity; files found there are removed before
    the first host of a PDT process starts.
    """

    def __init__(self, name: str = APPCONTAINER_NAME) -> None:
        self.name = name
        _, kernel32, advapi32, userenv, _ = _api()
        sid = ctypes.c_void_p()
        result = userenv.CreateAppContainerProfile(
            name, "PDT plugin host", "Sandbox for third-party PDT analyzer plugins", None, 0, ctypes.byref(sid),
        )
        if result == _ERROR_ALREADY_EXISTS_HRESULT:
            result = userenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(sid))
        if result != 0:
            raise AppContainerError(f"could not create the AppContainer profile (HRESULT {result & 0xFFFFFFFF:#010x})")
        self.sid = sid  # Freed by the operating system when PDT exits.
        text = ctypes.c_void_p()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            self.sid_string = ctypes.wstring_at(text.value)
        finally:
            kernel32.LocalFree(text)

    def grant_read(self, path: Path) -> None:
        """Let the container read and execute ``path`` and everything created inside it."""
        _, kernel32, advapi32, _, _ = _api()
        dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
        result = advapi32.GetNamedSecurityInfoW(
            str(path), _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION, None, None,
            ctypes.byref(dacl), None, ctypes.byref(descriptor),
        )
        if result:
            raise ctypes.WinError(result)
        try:
            entry = _ExplicitAccess(
                _GENERIC_READ_EXECUTE, _GRANT_ACCESS, _SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                _Trustee(None, 0, _TRUSTEE_IS_SID, 0, self.sid),
            )
            updated = ctypes.c_void_p()
            result = advapi32.SetEntriesInAclW(1, ctypes.byref(entry), dacl, ctypes.byref(updated))
            if result:
                raise ctypes.WinError(result)
            try:
                result = advapi32.SetNamedSecurityInfoW(
                    str(path), _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION, None, None, updated, None,
                )
                if result:
                    raise ctypes.WinError(result)
            finally:
                kernel32.LocalFree(updated)
        finally:
            kernel32.LocalFree(descriptor)

    def storage_folder(self) -> Path | None:
        """The container's own folder (``%LOCALAPPDATA%\\Packages\\<name>\\AC``)."""
        _, _, _, userenv, ole32 = _api()
        text = ctypes.c_void_p()
        if userenv.GetAppContainerFolderPath(self.sid_string, ctypes.byref(text)) != 0:
            return None
        try:
            return Path(ctypes.wstring_at(text.value))
        finally:
            ole32.CoTaskMemFree(text)

    def clear_storage(self) -> None:
        """Remove files from the container's folder, so no host can inherit data from another."""
        folder = self.storage_folder()
        if folder is None or not folder.is_dir():
            return
        for directory, _, names in os.walk(folder):
            for name in names:
                try:
                    os.unlink(os.path.join(directory, name))
                except OSError:
                    pass


def _runtime_root() -> Path:
    override = os.environ.get("PDT_PLUGIN_RUNTIME_DIR")
    if override:
        return Path(override)
    local = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    return Path(local) / "ProjectDiscoveryTool" / "plugin-runtime"


def _runtime_key(base: Path) -> str:
    digest = hashlib.sha256(f"{sys.version}|{os.path.normcase(str(base))}".encode())
    for item in sorted(base.iterdir(), key=lambda path: path.name.lower()):
        if item.is_file() and (item.suffix.lower() == ".dll" or item.name.lower() == "python.exe"):
            stat = item.stat()
            digest.update(f"|{item.name.lower()}:{stat.st_size}:{stat.st_mtime_ns}".encode())
    return digest.hexdigest()[:16]


def _publish(temporary: Path, target: Path) -> Path:
    """Move a fully built folder into place; a concurrent PDT may have published it first."""
    try:
        os.replace(temporary, target)
    except OSError:
        if not (target / _COMPLETE).is_file():
            raise
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
    return target


def stage_runtime(container: AppContainer) -> Path:
    """Return a copy of this interpreter's runtime that the container may read."""
    base = Path(sys.base_prefix)
    version = sys.version_info
    root = _runtime_root()
    root.mkdir(parents=True, exist_ok=True)
    target = root / f"cpython-{version.major}.{version.minor}-{_runtime_key(base)}"
    if (target / _COMPLETE).is_file():
        return target
    temporary = root / f".partial-{uuid.uuid4().hex}"
    temporary.mkdir()
    try:
        container.grant_read(temporary)  # inherited by everything copied below
        for item in base.iterdir():
            if item.is_file() and (item.suffix.lower() == ".dll" or item.name.lower() == "python.exe"):
                shutil.copy2(item, temporary / item.name)
        if not (temporary / "python.exe").is_file():
            raise AppContainerError(f"no python.exe in {base}")
        if (base / "DLLs").is_dir():
            shutil.copytree(base / "DLLs", temporary / "DLLs")
        shutil.copytree(
            base / "Lib", temporary / "Lib",
            ignore=lambda directory, names: (
                [name for name in names if name in _RUNTIME_SKIPPED]
                if os.path.normcase(directory) == os.path.normcase(str(base / "Lib")) else []
            ),
        )
        (temporary / _COMPLETE).write_text(sys.version, encoding="utf-8")
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return _publish(temporary, target)


def _module_sources(value: str) -> list[tuple[Path, str]]:
    """The plugin's top-level module or package, located without running its code."""
    top_level = value.split(":", 1)[0].strip().split(".", 1)[0]
    try:
        spec = importlib.util.find_spec(top_level)
    except (ImportError, ValueError):
        return []
    if spec is None:
        return []
    if spec.submodule_search_locations:
        return [(Path(item), top_level) for item in spec.submodule_search_locations if os.path.isdir(item)]
    if spec.origin and os.path.isfile(spec.origin):
        return [(Path(spec.origin), Path(spec.origin).name)]
    return []


def _canonical(name: str) -> str:
    return "".join("-" if char in "_." else char for char in name.lower())


def _distribution_closure(name: str | None) -> list[importlib.metadata.Distribution]:
    """The plugin's distribution and everything it requires, as installed here."""
    if not name:
        return []
    from packaging.requirements import InvalidRequirement, Requirement

    found: dict[str, importlib.metadata.Distribution] = {}
    pending = [name]
    while pending:
        canonical = _canonical(pending.pop())
        if canonical in found or canonical == _PDT_DISTRIBUTION:
            continue
        try:
            distribution = importlib.metadata.distribution(canonical)
        except importlib.metadata.PackageNotFoundError:
            continue
        found[canonical] = distribution
        if len(found) > MAX_STAGED_DISTRIBUTIONS:
            raise AppContainerError(f"the plugin requires more than {MAX_STAGED_DISTRIBUTIONS} distributions")
        for text in distribution.requires or ():
            try:
                requirement = Requirement(text)
            except InvalidRequirement:
                continue
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                pending.append(requirement.name)
    return list(found.values())


def _site_sources(entry_point: dict | None) -> list[tuple[Path, str]]:
    import project_discovery

    sources: list[tuple[Path, str]] = [(Path(project_discovery.__file__).parent, "project_discovery")]
    if entry_point is None:
        return sources
    sources += _module_sources(entry_point["value"])
    for distribution in _distribution_closure(entry_point.get("distribution")):
        for file in distribution.files or ():
            relative = Path(str(file))
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                continue
            source = Path(distribution.locate_file(file))
            if source.is_file():
                sources.append((source, relative.as_posix()))
    return sources


def _files_of(sources: list[tuple[Path, str]]):
    for source, relative in sources:
        if source.is_dir():
            for directory, _, names in os.walk(source):
                for name in names:
                    path = Path(directory, name)
                    yield path, (Path(relative) / path.relative_to(source)).as_posix()
        elif source.is_file():
            yield source, relative


def stage_site(container: AppContainer, work_dir: Path, entry_point: dict | None) -> Path:
    """Copy PDT's package and the plugin with its dependencies into a readable folder."""
    files = sorted(set(_files_of(_site_sources(entry_point))), key=lambda item: item[1])
    digest = hashlib.sha256((entry_point or {}).get("value", "").encode())
    total = 0
    for source, relative in files:
        stat = source.stat()
        total += stat.st_size
        if total > MAX_STAGED_BYTES:
            raise AppContainerError(
                f"the plugin and its dependencies exceed {MAX_STAGED_BYTES // (1024 * 1024)} MiB; "
                "run it with --plugin-isolation process instead"
            )
        digest.update(f"|{relative}:{stat.st_size}:{stat.st_mtime_ns}".encode())
    target = work_dir / f"appcontainer-site-{digest.hexdigest()[:16]}"
    if (target / _COMPLETE).is_file():
        return target
    temporary = work_dir / f".site-{uuid.uuid4().hex}"
    temporary.mkdir(parents=True)
    try:
        container.grant_read(temporary)
        for source, relative in files:
            destination = temporary / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                shutil.copy2(source, destination)
        (temporary / _COMPLETE).write_text("", encoding="utf-8")
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return _publish(temporary, target)


class _Prepared:
    def __init__(self) -> None:
        self.container = AppContainer()
        self.container.clear_storage()
        self.runtime = stage_runtime(self.container)
        # Hosts must fail to reach this listener; it never accepts a connection.
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(64)
        self.probe_port = self.listener.getsockname()[1]
        atexit.register(self.listener.close)


_prepared: _Prepared | None = None
_prepared_lock = threading.Lock()


def prepared() -> _Prepared:
    """The AppContainer, runtime copy and probe listener shared by this PDT process."""
    global _prepared
    with _prepared_lock:
        if _prepared is None:
            _prepared = _Prepared()
        return _prepared


def host_environment(scratch: Path) -> dict[str, str]:
    environment = {key: os.environ[key] for key in _ENVIRONMENT if key in os.environ}
    for key in ("USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP"):
        environment.setdefault(key, str(scratch))
    environment["HOME"] = str(scratch)
    return environment


class AppContainerProcess:
    """The part of ``subprocess.Popen`` that plugin hosts use, for a host in an AppContainer.

    The process is created suspended, assigned to ``job`` and only then resumed, so no
    host code runs outside the job. Only the three pipe handles are inherited.
    """

    def __init__(self, args: list[str], *, executable: str, cwd: str, env: dict[str, str],
                 container: AppContainer, job=None) -> None:
        import msvcrt

        _, kernel32, _, _, _ = _api()
        self._kernel32 = kernel32
        self.args = args
        self.returncode: int | None = None
        self._handle = None
        stdin_read, stdin_write = os.pipe()
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        child_ends = (stdin_read, stdout_write, stderr_write)
        parent_ends = (stdin_write, stdout_read, stderr_read)
        handles = [msvcrt.get_osfhandle(fd) for fd in child_ends]
        attributes = None
        try:
            for handle in handles:
                os.set_handle_inheritable(handle, True)
            size = ctypes.c_size_t()
            kernel32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
            attributes = ctypes.create_string_buffer(size.value)
            if not kernel32.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            capabilities = _SecurityCapabilities(container.sid, None, 0, 0)
            if not kernel32.UpdateProcThreadAttribute(
                attributes, 0, _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                ctypes.byref(capabilities), ctypes.sizeof(capabilities), None, None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            inherited = (ctypes.c_void_p * len(handles))(*handles)
            if not kernel32.UpdateProcThreadAttribute(
                attributes, 0, _PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, ctypes.sizeof(inherited), None, None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            startup = _StartupInfoEx()
            startup.StartupInfo.cb = ctypes.sizeof(startup)
            startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
            startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = handles
            startup.lpAttributeList = ctypes.cast(attributes, ctypes.c_void_p)
            block = "".join(
                f"{key}={value}\0" for key, value in sorted(env.items(), key=lambda item: item[0].upper())
            ) + "\0"
            environment = ctypes.create_unicode_buffer(block, len(block))
            information = _ProcessInformation()
            flags = (
                _CREATE_SUSPENDED | _EXTENDED_STARTUPINFO_PRESENT | _CREATE_UNICODE_ENVIRONMENT
                | _CREATE_NO_WINDOW | _CREATE_NEW_PROCESS_GROUP
            )
            if not kernel32.CreateProcessW(
                executable, ctypes.create_unicode_buffer(subprocess.list2cmdline(args)), None, None, True,
                flags, environment, cwd, ctypes.byref(startup), ctypes.byref(information),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            self._handle = information.hProcess
            self.pid = information.dwProcessId
            try:
                if job is not None:
                    job.assign_handle(self._handle)
                if kernel32.ResumeThread(information.hThread) == 0xFFFFFFFF:
                    raise ctypes.WinError(ctypes.get_last_error())
            except BaseException:
                kernel32.TerminateProcess(self._handle, 1)
                self.close_handle()
                raise
            finally:
                kernel32.CloseHandle(information.hThread)
        except BaseException:
            for fd in parent_ends:
                os.close(fd)
            raise
        finally:
            if attributes is not None:
                kernel32.DeleteProcThreadAttributeList(attributes)
            for fd in child_ends:
                os.close(fd)
        self.stdin = os.fdopen(stdin_write, "wb")
        self.stdout = os.fdopen(stdout_read, "rb")
        self.stderr = os.fdopen(stderr_read, "rb")

    def poll(self) -> int | None:
        try:
            return self.wait(0)
        except subprocess.TimeoutExpired:
            return None

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is not None or self._handle is None:
            return self.returncode
        milliseconds = _INFINITE if timeout is None else max(0, int(timeout * 1000))
        if self._kernel32.WaitForSingleObject(self._handle, milliseconds) == _WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(self.args, timeout)
        from ctypes import wintypes

        code = wintypes.DWORD()
        if not self._kernel32.GetExitCodeProcess(self._handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.returncode = code.value
        return self.returncode

    def kill(self) -> None:
        if self.returncode is None and self._handle is not None:
            self._kernel32.TerminateProcess(self._handle, 1)

    terminate = kill

    def close_handle(self) -> None:
        if self._handle is not None:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None

    def __del__(self) -> None:
        try:
            self.close_handle()
        except Exception:
            pass
