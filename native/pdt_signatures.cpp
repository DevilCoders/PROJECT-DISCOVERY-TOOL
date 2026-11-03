#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <cstring>
#include <string_view>

namespace {

bool starts_with(std::string_view data, std::string_view signature) {
    return data.size() >= signature.size() &&
           std::memcmp(data.data(), signature.data(), signature.size()) == 0;
}

PyObject* classify(std::string_view data) {
    const auto emit = [](const char* value) { return PyUnicode_FromString(value); };

    if (starts_with(data, "PK\x03\x04") || starts_with(data, "PK\x05\x06") ||
        starts_with(data, "PK\x07\x08")) return emit("archive/zip");
    if (starts_with(data, "\x1f\x8b")) return emit("archive/gzip");
    if (starts_with(data, "BZh")) return emit("archive/bzip2");
    if (starts_with(data, "\xfd" "7zXZ\x00")) return emit("archive/xz");
    if (starts_with(data, "\x28\xb5\x2f\xfd")) return emit("archive/zstandard");
    if (starts_with(data, "7z\xbc\xaf\x27\x1c")) return emit("archive/7z");
    if (starts_with(data, "Rar!\x1a\x07")) return emit("archive/rar");
    if (starts_with(data, "MSCF")) return emit("archive/cab");
    if (starts_with(data, "!<arch>")) return emit("archive/ar");
    if (starts_with(data, "\xed\xab\xee\xdb")) return emit("archive/rpm");
    if (data.size() >= 262 && data.substr(257, 5) == "ustar") return emit("archive/tar");
    if (starts_with(data, "%PDF-")) return emit("document/pdf");
    if (starts_with(data, "\x7f" "ELF")) return emit("executable/elf");
    if (starts_with(data, "MZ")) return emit("executable/pe");
    if (starts_with(data, "\xfe\xed\xfa\xce") || starts_with(data, "\xce\xfa\xed\xfe") ||
        starts_with(data, "\xfe\xed\xfa\xcf") || starts_with(data, "\xcf\xfa\xed\xfe") ||
        starts_with(data, "\xca\xfe\xba\xbe")) return emit("executable/mach-o-or-fat");
    if (starts_with(data, std::string_view("SQLite format 3\0", 16))) return emit("database/sqlite");
    if (starts_with(data, "\x89PNG\r\n\x1a\n")) return emit("image/png");
    if (starts_with(data, "\xff\xd8\xff")) return emit("image/jpeg");
    if (starts_with(data, "GIF87a") || starts_with(data, "GIF89a")) return emit("image/gif");
    if (starts_with(data, "BM")) return emit("image/bmp");
    if (starts_with(data, std::string_view("II*\0", 4)) || starts_with(data, std::string_view("MM\0*", 4))) return emit("image/tiff");
    if (data.size() >= 12 && data.substr(0, 4) == "RIFF" && data.substr(8, 4) == "WEBP")
        return emit("image/webp");
    if (data.size() >= 12 && data.substr(0, 4) == "RIFF" && data.substr(8, 4) == "WAVE")
        return emit("audio/wav");
    if (starts_with(data, "ID3") || starts_with(data, "\xff\xfb") ||
        starts_with(data, "\xff\xf3") || starts_with(data, "\xff\xf2"))
        return emit("audio/mpeg");
    if (data.size() >= 12 && data.substr(4, 4) == "ftyp") return emit("video/mp4");
    if (starts_with(data, "wOF2")) return emit("font/woff2");
    if (starts_with(data, "wOFF")) return emit("font/woff");
    if (starts_with(data, "OTTO")) return emit("font/otf");
    if (starts_with(data, std::string_view("\0\1\0\0", 4))) return emit("font/ttf");
    Py_RETURN_NONE;
}

PyObject* detect_signature(PyObject*, PyObject* args) {
    PyObject* object = nullptr;
    Py_buffer view{};
    if (!PyArg_ParseTuple(args, "O:detect_signature", &object)) return nullptr;
    if (PyObject_GetBuffer(object, &view, PyBUF_CONTIG_RO) < 0) return nullptr;
    const auto* bytes = static_cast<const char*>(view.buf);
    const auto length = static_cast<std::size_t>(view.len);
    PyObject* result = classify(std::string_view(bytes, length));
    PyBuffer_Release(&view);
    return result;
}

PyMethodDef methods[] = {
    {"detect_signature", detect_signature, METH_VARARGS,
     "Classify a bounded byte sample using the C++ signature catalog."},
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
    return PyModule_Create(&module);
}
