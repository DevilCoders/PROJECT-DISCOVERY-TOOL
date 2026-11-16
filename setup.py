"""Optional C, C++ and Rust native builds; Assembly acceleration on Linux x86-64."""
from __future__ import annotations

import sys
import sysconfig

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext as setuptools_build_ext
from setuptools_rust import Binding, RustExtension


class PDTBuildExt(setuptools_build_ext):
    """Teach setuptools' C compiler to pass preprocessed assembly sources to GCC/Clang."""

    def build_extensions(self) -> None:
        if self.compiler.compiler_type == "unix":
            if ".S" not in self.compiler.src_extensions:
                self.compiler.src_extensions.append(".S")
            self.compiler.language_map[".S"] = "c"
        super().build_extensions()


def target_platform() -> str:
    """The platform being built for, which a cross-build sets (_PYTHON_HOST_PLATFORM, as
    crossenv and cibuildwheel do): "linux-x86_64", "linux-aarch64", "win-arm64", ..."""
    return sysconfig.get_platform().lower()


native_sources = ["native/c/pdt_native.c"]
macros = []
# The build host's architecture says nothing about a cross-build's target: x86-64 assembly in
# an aarch64 build fails, and the optional extension would then be silently left out.
if target_platform() in {"linux-x86_64", "linux-amd64"}:
    native_sources.append("native/asm/pdt_simd_x86_64.S")
    macros.append(("PDT_HAVE_X86_64_ASM", "1"))

native_extension = Extension(
    "project_discovery._native",
    sources=native_sources,
    define_macros=macros,
    extra_compile_args=["/O2"] if sys.platform == "win32" else ["-O3", "-std=c11"],
    libraries=["dl"] if sys.platform.startswith("linux") else [],
    optional=True,
)
cpp_extension = Extension(
    "project_discovery._native_cpp",
    sources=["native/cpp/pdt_signatures.cpp"],
    language="c++",
    extra_compile_args=["/O2", "/std:c++17"] if sys.platform == "win32" else ["-O3", "-std=c++17"],
    optional=True,
)

rust_walker = RustExtension(
    "project_discovery._walker",
    path="native/rust/Cargo.toml",
    binding=Binding.PyO3,
    # setuptools-rust builds in-place and editable extensions unoptimized unless told
    # otherwise; the walker is on the inventory hot path.
    debug=False,
    optional=True,
)

setup(
    ext_modules=[native_extension, cpp_extension],
    rust_extensions=[rust_walker],
    cmdclass={"build_ext": PDTBuildExt},
)
