"""Optional C, C++ and Rust native builds; Assembly acceleration on Linux x86-64."""
from __future__ import annotations

import platform
import sys

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


native_sources = ["native/c/pdt_native.c"]
macros = []
if sys.platform.startswith("linux") and platform.machine().lower() in {"x86_64", "amd64"}:
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
