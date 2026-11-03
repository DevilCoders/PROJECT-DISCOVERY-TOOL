#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

#if defined(PDT_HAVE_X86_64_ASM) && (defined(__GNUC__) || defined(__clang__))
extern size_t pdt_asm_count_byte(const unsigned char *data, size_t length,
                                 unsigned char needle);
#define PDT_ASM_COMPILED 1
#else
#define PDT_ASM_COMPILED 0
#endif

static size_t pdt_count_byte_scalar(const unsigned char *data, size_t length,
                                    unsigned char needle) {
    size_t count = 0;
    size_t index;
    for (index = 0; index < length; ++index) {
        count += (size_t)(data[index] == needle);
    }
    return count;
}

static int pdt_use_assembly(void) {
#if PDT_ASM_COMPILED && (defined(__x86_64__) || defined(_M_X64))
    static int enabled = -1;
    if (enabled < 0) {
        __builtin_cpu_init();
        enabled = __builtin_cpu_supports("sse2") &&
                  __builtin_cpu_supports("popcnt");
    }
    return enabled;
#else
    return 0;
#endif
}

static const char *pdt_backend_name(void) {
    return pdt_use_assembly() ? "x86_64-sse2-popcnt-asm" : "portable-c";
}

static size_t pdt_count_byte(const unsigned char *data, size_t length,
                             unsigned char needle) {
#if PDT_ASM_COMPILED
    if (pdt_use_assembly()) {
        return pdt_asm_count_byte(data, length, needle);
    }
#endif
    return pdt_count_byte_scalar(data, length, needle);
}

static PyObject *pdt_native_count_byte(PyObject *self, PyObject *args) {
    PyObject *object;
    Py_buffer view;
    int needle;
    size_t count;

    (void)self;
    if (!PyArg_ParseTuple(args, "Oi:count_byte", &object, &needle)) {
        return NULL;
    }
    if (needle < 0 || needle > 255) {
        PyErr_SetString(PyExc_ValueError, "needle must be between 0 and 255");
        return NULL;
    }
    if (PyObject_GetBuffer(object, &view, PyBUF_CONTIG_RO) < 0) {
        return NULL;
    }

    /* Keep the GIL while reading buffers that may be backed by mutable bytearrays. */
    count = pdt_count_byte((const unsigned char *)view.buf,
                           (size_t)view.len, (unsigned char)needle);
    PyBuffer_Release(&view);
    return PyLong_FromSize_t(count);
}

static PyObject *pdt_native_capabilities(PyObject *self, PyObject *Py_UNUSED(args)) {
    const char *architecture = "unknown";
    long hardware_threads = 1;

    (void)self;
#if defined(__x86_64__) || defined(_M_X64)
    architecture = "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    architecture = "aarch64";
#elif defined(__i386__) || defined(_M_IX86)
    architecture = "x86";
#elif defined(__arm__) || defined(_M_ARM)
    architecture = "arm";
#endif

#if defined(_WIN32)
    {
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        if (info.dwNumberOfProcessors > 0) {
            hardware_threads = (long)info.dwNumberOfProcessors;
        }
    }
#else
    {
        long value = sysconf(_SC_NPROCESSORS_ONLN);
        if (value > 0) {
            hardware_threads = value;
        }
    }
#endif

    return Py_BuildValue(
        "{s:s,s:s,s:l,s:O}",
        "architecture", architecture,
        "backend", pdt_backend_name(),
        "hardware_threads", hardware_threads,
        "assembly_compiled", PDT_ASM_COMPILED ? Py_True : Py_False
    );
}

static PyMethodDef pdt_native_methods[] = {
    {"count_byte", pdt_native_count_byte, METH_VARARGS,
     "Count a byte using the runtime-selected native backend."},
    {"capabilities", pdt_native_capabilities, METH_NOARGS,
     "Return native architecture, backend and hardware capability information."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef pdt_native_module = {
    PyModuleDef_HEAD_INIT,
    "_native",
    "PDT native C core with optional x86-64 Assembly acceleration.",
    -1,
    pdt_native_methods
};

PyMODINIT_FUNC PyInit__native(void) {
    return PyModule_Create(&pdt_native_module);
}
