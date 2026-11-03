"""Optional native build: portable C on all platforms, Assembly on Linux x86-64."""
from __future__ import annotations

import platform
import sys

from setuptools import Extension, setup


native_sources = ["native/pdt_native.c"]
macros = []
if sys.platform.startswith("linux") and platform.machine().lower() in {"x86_64", "amd64"}:
    native_sources.append("native/pdt_simd_x86_64.S")
    macros.append(("PDT_HAVE_X86_64_ASM", "1"))

native_extension = Extension(
    "project_discovery._native",
    sources=native_sources,
    define_macros=macros,
    extra_compile_args=["/O2"] if sys.platform == "win32" else ["-O3", "-std=c11"],
    optional=True,
)
cpp_extension = Extension(
    "project_discovery._native_cpp",
    sources=["native/pdt_signatures.cpp"],
    language="c++",
    extra_compile_args=["/O2", "/std:c++17"] if sys.platform == "win32" else ["-O3", "-std=c++17"],
    optional=True,
)

setup(ext_modules=[native_extension, cpp_extension])
