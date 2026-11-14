#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <cstddef>
#include <cstring>

namespace {

// `length` bytes that must appear at `offset`.
struct Test {
    std::size_t offset;
    const unsigned char* bytes;
    std::size_t length;
};

// A catalog rule: every test must match. Python validates the header of the matched
// candidate and reads its subtype; a rejected candidate continues the scan after it.
struct Rule {
    const char* label;
    const Test* tests;
    std::size_t count;
};

// kRules, kRuleCount and kRulesDigest, generated from the Python signature catalog.
#include "pdt_signature_rules.h"

bool matches(const Rule& rule, const unsigned char* data, std::size_t length) {
    for (std::size_t index = 0; index < rule.count; ++index) {
        const Test& test = rule.tests[index];
        if (test.offset > length || test.length > length - test.offset ||
            std::memcmp(data + test.offset, test.bytes, test.length) != 0) {
            return false;
        }
    }
    return true;
}

// The index of the first rule at or after `start` that the sample matches, or -1.
Py_ssize_t first_match(const unsigned char* data, std::size_t length, std::size_t start) {
    for (std::size_t index = start; index < kRuleCount; ++index) {
        if (matches(kRules[index], data, length)) {
            return static_cast<Py_ssize_t>(index);
        }
    }
    return -1;
}

Py_ssize_t match_buffer(PyObject* object, Py_ssize_t start) {
    Py_buffer view{};
    if (PyObject_GetBuffer(object, &view, PyBUF_CONTIG_RO) < 0) {
        return -2;
    }
    const Py_ssize_t index = first_match(
        static_cast<const unsigned char*>(view.buf), static_cast<std::size_t>(view.len),
        static_cast<std::size_t>(start));
    PyBuffer_Release(&view);
    return index;
}

PyObject* match_rule(PyObject*, PyObject* args) {
    PyObject* object = nullptr;
    Py_ssize_t start = 0;
    if (!PyArg_ParseTuple(args, "O|n:match_rule", &object, &start)) return nullptr;
    if (start < 0) {
        PyErr_SetString(PyExc_ValueError, "start must not be negative");
        return nullptr;
    }
    const Py_ssize_t index = match_buffer(object, start);
    if (index == -2) return nullptr;
    if (index < 0) Py_RETURN_NONE;
    return PyLong_FromSsize_t(index);
}

PyObject* detect_signature(PyObject*, PyObject* args) {
    PyObject* object = nullptr;
    if (!PyArg_ParseTuple(args, "O:detect_signature", &object)) return nullptr;
    const Py_ssize_t index = match_buffer(object, 0);
    if (index == -2) return nullptr;
    if (index < 0) Py_RETURN_NONE;
    return PyUnicode_FromString(kRules[index].label);
}

PyMethodDef methods[] = {
    {"match_rule", match_rule, METH_VARARGS,
     "Index of the first catalog rule, from an optional start index, that a sample matches."},
    {"detect_signature", detect_signature, METH_VARARGS,
     "Candidate label of the first catalog rule that a bounded byte sample matches."},
    {nullptr, nullptr, 0, nullptr}
};

PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "_native_cpp",
    "PDT C++ file-signature classifier.",
    -1,
    methods
};

}  // namespace

PyMODINIT_FUNC PyInit__native_cpp() {
    PyObject* created = PyModule_Create(&module);
    if (created == nullptr) return nullptr;
    if (PyModule_AddStringConstant(created, "RULES_DIGEST", kRulesDigest) < 0 ||
        PyModule_AddIntConstant(created, "RULE_COUNT", static_cast<long>(kRuleCount)) < 0) {
        Py_DECREF(created);
        return nullptr;
    }
    return created;
}
