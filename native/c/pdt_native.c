#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#define PDT_CL_CALL __stdcall
typedef HMODULE pdt_library_handle;
#else
#include <dlfcn.h>
#define PDT_CL_CALL
typedef void *pdt_library_handle;
#endif

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

#define PDT_GPU_MIN_BYTES ((size_t)8 * 1024 * 1024)
#define PDT_CL_SUCCESS 0
#define PDT_CL_DEVICE_NOT_FOUND (-1)
#define PDT_CL_DEVICE_TYPE_GPU ((uint64_t)1 << 2)
#define PDT_CL_DEVICE_NAME 0x102B
#define PDT_CL_DEVICE_VENDOR 0x102C
#define PDT_CL_DEVICE_MAX_COMPUTE_UNITS 0x1002
#define PDT_CL_DEVICE_MAX_MEM_ALLOC_SIZE 0x1010
#define PDT_CL_DEVICE_GLOBAL_MEM_SIZE 0x101F
#define PDT_CL_MEM_READ_ONLY ((uint64_t)1 << 2)
#define PDT_CL_MEM_WRITE_ONLY ((uint64_t)1 << 1)
#define PDT_CL_MEM_COPY_HOST_PTR ((uint64_t)1 << 5)
#define PDT_CL_TRUE 1

typedef int32_t pdt_cl_int;
typedef uint32_t pdt_cl_uint;
typedef uint64_t pdt_cl_ulong;
typedef intptr_t pdt_cl_context_properties;
typedef pdt_cl_ulong pdt_cl_device_type;
typedef pdt_cl_ulong pdt_cl_mem_flags;
typedef uint32_t pdt_cl_bool;
typedef struct _pdt_cl_platform_id *pdt_cl_platform_id;
typedef struct _pdt_cl_device_id *pdt_cl_device_id;
typedef struct _pdt_cl_context *pdt_cl_context;
typedef struct _pdt_cl_command_queue *pdt_cl_command_queue;
typedef struct _pdt_cl_program *pdt_cl_program;
typedef struct _pdt_cl_kernel *pdt_cl_kernel;
typedef struct _pdt_cl_mem *pdt_cl_mem;

typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_get_platform_ids_fn)(
    pdt_cl_uint, pdt_cl_platform_id *, pdt_cl_uint *);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_get_device_ids_fn)(
    pdt_cl_platform_id, pdt_cl_device_type, pdt_cl_uint,
    pdt_cl_device_id *, pdt_cl_uint *);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_get_device_info_fn)(
    pdt_cl_device_id, pdt_cl_uint, size_t, void *, size_t *);
typedef pdt_cl_context (PDT_CL_CALL *pdt_cl_create_context_fn)(
    const pdt_cl_context_properties *, pdt_cl_uint, const pdt_cl_device_id *,
    void *, void *, pdt_cl_int *);
typedef pdt_cl_command_queue (PDT_CL_CALL *pdt_cl_create_command_queue_fn)(
    pdt_cl_context, pdt_cl_device_id, pdt_cl_ulong, pdt_cl_int *);
typedef pdt_cl_program (PDT_CL_CALL *pdt_cl_create_program_with_source_fn)(
    pdt_cl_context, pdt_cl_uint, const char **, const size_t *, pdt_cl_int *);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_build_program_fn)(
    pdt_cl_program, pdt_cl_uint, const pdt_cl_device_id *, const char *,
    void *, void *);
typedef pdt_cl_kernel (PDT_CL_CALL *pdt_cl_create_kernel_fn)(
    pdt_cl_program, const char *, pdt_cl_int *);
typedef pdt_cl_mem (PDT_CL_CALL *pdt_cl_create_buffer_fn)(
    pdt_cl_context, pdt_cl_mem_flags, size_t, void *, pdt_cl_int *);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_set_kernel_arg_fn)(
    pdt_cl_kernel, pdt_cl_uint, size_t, const void *);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_enqueue_ndrange_kernel_fn)(
    pdt_cl_command_queue, pdt_cl_kernel, pdt_cl_uint, const size_t *,
    const size_t *, const size_t *, pdt_cl_uint, const void *, void *);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_enqueue_read_buffer_fn)(
    pdt_cl_command_queue, pdt_cl_mem, pdt_cl_bool, size_t, size_t, void *,
    pdt_cl_uint, const void *, void *);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_finish_fn)(pdt_cl_command_queue);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_release_mem_object_fn)(pdt_cl_mem);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_release_kernel_fn)(pdt_cl_kernel);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_release_command_queue_fn)(pdt_cl_command_queue);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_release_program_fn)(pdt_cl_program);
typedef pdt_cl_int (PDT_CL_CALL *pdt_cl_release_context_fn)(pdt_cl_context);

typedef struct {
    pdt_library_handle library;
    pdt_cl_get_platform_ids_fn get_platform_ids;
    pdt_cl_get_device_ids_fn get_device_ids;
    pdt_cl_get_device_info_fn get_device_info;
    pdt_cl_create_context_fn create_context;
    pdt_cl_create_command_queue_fn create_command_queue;
    pdt_cl_create_program_with_source_fn create_program_with_source;
    pdt_cl_build_program_fn build_program;
    pdt_cl_create_kernel_fn create_kernel;
    pdt_cl_create_buffer_fn create_buffer;
    pdt_cl_set_kernel_arg_fn set_kernel_arg;
    pdt_cl_enqueue_ndrange_kernel_fn enqueue_ndrange_kernel;
    pdt_cl_enqueue_read_buffer_fn enqueue_read_buffer;
    pdt_cl_finish_fn finish;
    pdt_cl_release_mem_object_fn release_mem_object;
    pdt_cl_release_kernel_fn release_kernel;
    pdt_cl_release_command_queue_fn release_command_queue;
    pdt_cl_release_program_fn release_program;
    pdt_cl_release_context_fn release_context;
    pdt_cl_device_id device;
    pdt_cl_context context;
    pdt_cl_program program;
    pdt_cl_uint compute_units;
    pdt_cl_ulong global_memory_bytes;
    pdt_cl_ulong max_allocation_bytes;
    char name[256];
    char vendor[256];
    int initialized;
    int available;
} pdt_opencl_runtime;

static pdt_opencl_runtime pdt_opencl;
static unsigned long long pdt_gpu_dispatches = 0;
static unsigned long long pdt_gpu_fallbacks = 0;

/* Why the GPU path is unavailable (set once by pdt_opencl_initialize) and why each large
   immutable buffer fell back to the CPU. The names are reported in scan metrics. */
enum {
    PDT_GPU_REASON_LOADER = 0,     /* no OpenCL ICD loader, or a required symbol missing */
    PDT_GPU_REASON_DEVICE,         /* no platform, no GPU device or unknown device limits */
    PDT_GPU_REASON_CONTEXT,        /* context creation failed */
    PDT_GPU_REASON_KERNEL_BUILD,   /* program creation or kernel compilation failed */
    PDT_GPU_REASON_MEMORY_LIMIT,   /* the buffer exceeds the device allocation or memory budget */
    PDT_GPU_REASON_HOST_MEMORY,    /* a host-side allocation failed */
    PDT_GPU_REASON_DISPATCH,       /* queue, kernel, buffer, argument, enqueue, read or finish failed */
    PDT_GPU_REASON_COUNT
};
static const char *const pdt_gpu_reason_names[PDT_GPU_REASON_COUNT] = {
    "loader", "device", "context", "kernel_build", "memory_limit", "host_memory", "dispatch",
};
static int pdt_gpu_unavailable_reason = -1; /* -1: available or not yet initialized */
static unsigned long long pdt_gpu_fallback_reasons[PDT_GPU_REASON_COUNT];
/* Tests force a fallback reason for every eligible buffer (_set_gpu_test_fault); -1: none. */
static int pdt_gpu_test_fault = -1;

static void *pdt_load_library_symbol(pdt_library_handle library, const char *name) {
#if defined(_WIN32)
    return (void *)GetProcAddress(library, name);
#else
    return dlsym(library, name);
#endif
}

static pdt_library_handle pdt_opencl_library(void) {
#if defined(_WIN32)
    /* Never let the DLL search order reach the current directory or PATH: PDT is run
       inside untrusted repositories, and a planted OpenCL.dll would execute in-process.
       GPU vendors install the OpenCL ICD loader into System32. */
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif
    return LoadLibraryExA("OpenCL.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
#elif defined(__APPLE__)
    /* Only the absolute system framework path: a relative dlopen path is resolved
       against the current directory. */
    return dlopen(
        "/System/Library/Frameworks/OpenCL.framework/OpenCL", RTLD_NOW | RTLD_LOCAL
    );
#else
    pdt_library_handle handle = dlopen("libOpenCL.so.1", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        handle = dlopen("libOpenCL.so", RTLD_NOW | RTLD_LOCAL);
    }
    return handle;
#endif
}

#define PDT_BIND_OPENCL(field, symbol_name)                                      \
    do {                                                                          \
        void *pdt_symbol = pdt_load_library_symbol(pdt_opencl.library, symbol_name); \
        if (pdt_symbol == NULL) {                                                  \
            pdt_gpu_unavailable_reason = PDT_GPU_REASON_LOADER;                   \
            return 0;                                                             \
        }                                                                         \
        memcpy(&pdt_opencl.field, &pdt_symbol, sizeof(pdt_opencl.field));          \
    } while (0)

static int pdt_opencl_initialize(void) {
    static const char *kernel_source =
        "__kernel void pdt_count_byte(__global const uchar *data, ulong length, "
        "uchar needle, __global ulong *partial, __local ulong *scratch) { "
        "size_t lid=get_local_id(0); size_t gid=get_global_id(0); "
        "size_t stride=get_global_size(0); ulong total=0; "
        "for (ulong i=(ulong)gid; i<length; i+=(ulong)stride) "
        "total += (data[i] == needle); "
        "scratch[lid]=total; barrier(CLK_LOCAL_MEM_FENCE); "
        "for (size_t step=get_local_size(0)/2; step>0; step>>=1) { "
        "if (lid<step) scratch[lid]+=scratch[lid+step]; "
        "barrier(CLK_LOCAL_MEM_FENCE); } "
        "if (lid==0) partial[get_group_id(0)]=scratch[0]; }";
    pdt_cl_uint platform_count = 0;
    pdt_cl_platform_id *platforms = NULL;
    pdt_cl_device_id selected = NULL;
    pdt_cl_uint selected_units = 0;
    pdt_cl_ulong selected_memory = 0;
    pdt_cl_ulong selected_max_allocation = 0;
    pdt_cl_uint p;

    if (pdt_opencl.initialized) {
        return pdt_opencl.available;
    }
    pdt_opencl.initialized = 1;
    pdt_opencl.library = pdt_opencl_library();
    if (pdt_opencl.library == NULL) {
        pdt_gpu_unavailable_reason = PDT_GPU_REASON_LOADER;
        return 0;
    }

    PDT_BIND_OPENCL(get_platform_ids, "clGetPlatformIDs");
    PDT_BIND_OPENCL(get_device_ids, "clGetDeviceIDs");
    PDT_BIND_OPENCL(get_device_info, "clGetDeviceInfo");
    PDT_BIND_OPENCL(create_context, "clCreateContext");
    PDT_BIND_OPENCL(create_command_queue, "clCreateCommandQueue");
    PDT_BIND_OPENCL(create_program_with_source, "clCreateProgramWithSource");
    PDT_BIND_OPENCL(build_program, "clBuildProgram");
    PDT_BIND_OPENCL(create_kernel, "clCreateKernel");
    PDT_BIND_OPENCL(create_buffer, "clCreateBuffer");
    PDT_BIND_OPENCL(set_kernel_arg, "clSetKernelArg");
    PDT_BIND_OPENCL(enqueue_ndrange_kernel, "clEnqueueNDRangeKernel");
    PDT_BIND_OPENCL(enqueue_read_buffer, "clEnqueueReadBuffer");
    PDT_BIND_OPENCL(finish, "clFinish");
    PDT_BIND_OPENCL(release_mem_object, "clReleaseMemObject");
    PDT_BIND_OPENCL(release_kernel, "clReleaseKernel");
    PDT_BIND_OPENCL(release_command_queue, "clReleaseCommandQueue");
    PDT_BIND_OPENCL(release_program, "clReleaseProgram");
    PDT_BIND_OPENCL(release_context, "clReleaseContext");

    if (pdt_opencl.get_platform_ids(0, NULL, &platform_count) != PDT_CL_SUCCESS ||
        platform_count == 0) {
        pdt_gpu_unavailable_reason = PDT_GPU_REASON_DEVICE;
        return 0;
    }
    platforms = (pdt_cl_platform_id *)calloc(platform_count, sizeof(*platforms));
    if (platforms == NULL) {
        pdt_gpu_unavailable_reason = PDT_GPU_REASON_HOST_MEMORY;
        return 0;
    }
    if (pdt_opencl.get_platform_ids(platform_count, platforms, NULL) != PDT_CL_SUCCESS) {
        free(platforms);
        pdt_gpu_unavailable_reason = PDT_GPU_REASON_DEVICE;
        return 0;
    }

    for (p = 0; p < platform_count; ++p) {
        pdt_cl_uint device_count = 0;
        pdt_cl_device_id *devices;
        pdt_cl_uint d;
        pdt_cl_int status = pdt_opencl.get_device_ids(
            platforms[p], PDT_CL_DEVICE_TYPE_GPU, 0, NULL, &device_count
        );
        if (status != PDT_CL_SUCCESS && status != PDT_CL_DEVICE_NOT_FOUND) {
            continue;
        }
        if (device_count == 0) {
            continue;
        }
        devices = (pdt_cl_device_id *)calloc(device_count, sizeof(*devices));
        if (devices == NULL) {
            continue;
        }
        if (pdt_opencl.get_device_ids(
                platforms[p], PDT_CL_DEVICE_TYPE_GPU, device_count, devices, NULL
            ) == PDT_CL_SUCCESS) {
            for (d = 0; d < device_count; ++d) {
                pdt_cl_uint units = 0;
                pdt_cl_ulong memory = 0;
                pdt_cl_ulong max_allocation = 0;
                pdt_cl_int units_status = pdt_opencl.get_device_info(
                    devices[d], PDT_CL_DEVICE_MAX_COMPUTE_UNITS,
                    sizeof(units), &units, NULL
                );
                pdt_cl_int memory_status = pdt_opencl.get_device_info(
                    devices[d], PDT_CL_DEVICE_GLOBAL_MEM_SIZE,
                    sizeof(memory), &memory, NULL
                );
                pdt_cl_int allocation_status = pdt_opencl.get_device_info(
                    devices[d], PDT_CL_DEVICE_MAX_MEM_ALLOC_SIZE,
                    sizeof(max_allocation), &max_allocation, NULL
                );
                /* Unknown device limits are not treated as unlimited memory. */
                if (units_status != PDT_CL_SUCCESS ||
                    memory_status != PDT_CL_SUCCESS ||
                    allocation_status != PDT_CL_SUCCESS ||
                    units == 0 || memory == 0 || max_allocation == 0) {
                    continue;
                }
                if (selected == NULL || units > selected_units ||
                    (units == selected_units && memory > selected_memory)) {
                    selected = devices[d];
                    selected_units = units;
                    selected_memory = memory;
                    selected_max_allocation = max_allocation;
                }
            }
        }
        free(devices);
    }
    free(platforms);
    if (selected == NULL) {
        pdt_gpu_unavailable_reason = PDT_GPU_REASON_DEVICE;
        return 0;
    }

    pdt_opencl.device = selected;
    pdt_opencl.compute_units = selected_units;
    pdt_opencl.global_memory_bytes = selected_memory;
    pdt_opencl.max_allocation_bytes = selected_max_allocation;
    (void)pdt_opencl.get_device_info(
        selected, PDT_CL_DEVICE_NAME, sizeof(pdt_opencl.name) - 1,
        pdt_opencl.name, NULL
    );
    (void)pdt_opencl.get_device_info(
        selected, PDT_CL_DEVICE_VENDOR, sizeof(pdt_opencl.vendor) - 1,
        pdt_opencl.vendor, NULL
    );
    pdt_opencl.name[sizeof(pdt_opencl.name) - 1] = '\0';
    pdt_opencl.vendor[sizeof(pdt_opencl.vendor) - 1] = '\0';

    {
        pdt_cl_int status = PDT_CL_SUCCESS;
        const char *sources[1] = {kernel_source};
        pdt_opencl.context = pdt_opencl.create_context(
            NULL, 1, &pdt_opencl.device, NULL, NULL, &status
        );
        if (status != PDT_CL_SUCCESS || pdt_opencl.context == NULL) {
            pdt_opencl.context = NULL;
            pdt_gpu_unavailable_reason = PDT_GPU_REASON_CONTEXT;
            return 0;
        }
        pdt_opencl.program = pdt_opencl.create_program_with_source(
            pdt_opencl.context, 1, sources, NULL, &status
        );
        if (status != PDT_CL_SUCCESS || pdt_opencl.program == NULL) {
            pdt_opencl.release_context(pdt_opencl.context);
            pdt_opencl.context = NULL;
            pdt_opencl.program = NULL;
            pdt_gpu_unavailable_reason = PDT_GPU_REASON_KERNEL_BUILD;
            return 0;
        }
        status = pdt_opencl.build_program(
            pdt_opencl.program, 1, &pdt_opencl.device, NULL, NULL, NULL
        );
        if (status != PDT_CL_SUCCESS) {
            pdt_opencl.release_program(pdt_opencl.program);
            pdt_opencl.release_context(pdt_opencl.context);
            pdt_opencl.program = NULL;
            pdt_opencl.context = NULL;
            pdt_gpu_unavailable_reason = PDT_GPU_REASON_KERNEL_BUILD;
            return 0;
        }
    }

    pdt_opencl.available = 1;
    pdt_gpu_unavailable_reason = -1;
    return 1;
}

static int pdt_opencl_count_byte(
    const unsigned char *data, size_t length, unsigned char needle,
    unsigned long long *result, int *reason
) {
    const size_t local_size = 256;
    size_t groups;
    size_t global_size;
    pdt_cl_command_queue queue = NULL;
    pdt_cl_kernel kernel = NULL;
    pdt_cl_mem input_buffer = NULL;
    pdt_cl_mem partial_buffer = NULL;
    pdt_cl_ulong *partials = NULL;
    pdt_cl_ulong device_length = (pdt_cl_ulong)length;
    size_t partial_bytes;
    pdt_cl_int status = PDT_CL_SUCCESS;
    pdt_cl_uint index;
    unsigned long long total = 0;

    *reason = PDT_GPU_REASON_DISPATCH;
    if (!pdt_opencl.available) {
        *reason = pdt_gpu_unavailable_reason >= 0 ? pdt_gpu_unavailable_reason : PDT_GPU_REASON_DEVICE;
        return 0;
    }
    if ((pdt_opencl.max_allocation_bytes != 0 &&
         (pdt_cl_ulong)length > pdt_opencl.max_allocation_bytes) ||
        (pdt_opencl.global_memory_bytes != 0 &&
         (pdt_cl_ulong)length > pdt_opencl.global_memory_bytes / 4)) {
        *reason = PDT_GPU_REASON_MEMORY_LIMIT;
        return 0;
    }

    groups = (size_t)(pdt_opencl.compute_units ? pdt_opencl.compute_units : 1) * 8;
    if (groups < 128) groups = 128;
    if (groups > 2048) groups = 2048;
    global_size = groups * local_size;
    partial_bytes = groups * sizeof(pdt_cl_ulong);
    partials = (pdt_cl_ulong *)calloc(groups, sizeof(pdt_cl_ulong));
    if (partials == NULL) {
        *reason = PDT_GPU_REASON_HOST_MEMORY;
        return 0;
    }

    queue = pdt_opencl.create_command_queue(
        pdt_opencl.context, pdt_opencl.device, 0, &status
    );
    if (status != PDT_CL_SUCCESS || queue == NULL) {
        if (status == PDT_CL_SUCCESS) status = -1;
        goto cleanup;
    }
    kernel = pdt_opencl.create_kernel(pdt_opencl.program, "pdt_count_byte", &status);
    if (status != PDT_CL_SUCCESS || kernel == NULL) {
        if (status == PDT_CL_SUCCESS) status = -1;
        goto cleanup;
    }
    input_buffer = pdt_opencl.create_buffer(
        pdt_opencl.context,
        PDT_CL_MEM_READ_ONLY | PDT_CL_MEM_COPY_HOST_PTR,
        length, (void *)data, &status
    );
    if (status != PDT_CL_SUCCESS || input_buffer == NULL) {
        if (status == PDT_CL_SUCCESS) status = -1;
        goto cleanup;
    }
    partial_buffer = pdt_opencl.create_buffer(
        pdt_opencl.context, PDT_CL_MEM_WRITE_ONLY, partial_bytes, NULL, &status
    );
    if (status != PDT_CL_SUCCESS || partial_buffer == NULL) {
        if (status == PDT_CL_SUCCESS) status = -1;
        goto cleanup;
    }

    status = pdt_opencl.set_kernel_arg(kernel, 0, sizeof(input_buffer), &input_buffer);
    if (status != PDT_CL_SUCCESS) goto cleanup;
    status = pdt_opencl.set_kernel_arg(kernel, 1, sizeof(device_length), &device_length);
    if (status != PDT_CL_SUCCESS) goto cleanup;
    status = pdt_opencl.set_kernel_arg(kernel, 2, sizeof(needle), &needle);
    if (status != PDT_CL_SUCCESS) goto cleanup;
    status = pdt_opencl.set_kernel_arg(kernel, 3, sizeof(partial_buffer), &partial_buffer);
    if (status != PDT_CL_SUCCESS) goto cleanup;
    status = pdt_opencl.set_kernel_arg(
        kernel, 4, local_size * sizeof(pdt_cl_ulong), NULL
    );
    if (status != PDT_CL_SUCCESS) goto cleanup;

    Py_BEGIN_ALLOW_THREADS
    status = pdt_opencl.enqueue_ndrange_kernel(
        queue, kernel, 1, NULL, &global_size, &local_size, 0, NULL, NULL
    );
    if (status == PDT_CL_SUCCESS) {
        status = pdt_opencl.enqueue_read_buffer(
            queue, partial_buffer, PDT_CL_TRUE, 0, partial_bytes,
            partials, 0, NULL, NULL
        );
    }
    if (status == PDT_CL_SUCCESS) {
        status = pdt_opencl.finish(queue);
    }
    Py_END_ALLOW_THREADS

    if (status != PDT_CL_SUCCESS) {
        goto cleanup;
    }
    for (index = 0; index < (pdt_cl_uint)groups; ++index) {
        total += (unsigned long long)partials[index];
    }
    *result = total;

cleanup:
    if (partial_buffer != NULL) pdt_opencl.release_mem_object(partial_buffer);
    if (input_buffer != NULL) pdt_opencl.release_mem_object(input_buffer);
    if (kernel != NULL) pdt_opencl.release_kernel(kernel);
    if (queue != NULL) pdt_opencl.release_command_queue(queue);
    free(partials);
    return status == PDT_CL_SUCCESS;
}

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
    int value = __atomic_load_n(&enabled, __ATOMIC_ACQUIRE);
    if (value < 0) {
        int detected;
        __builtin_cpu_init();
        detected = __builtin_cpu_supports("sse2") &&
                   __builtin_cpu_supports("popcnt");
        __atomic_store_n(&enabled, detected, __ATOMIC_RELEASE);
        value = detected;
    }
    return value;
#else
    return 0;
#endif
}

static const char *pdt_backend_name(void) {
    return pdt_use_assembly() ? "x86_64-sse2-popcnt-asm" : "portable-c";
}

static size_t pdt_count_byte_cpu(const unsigned char *data, size_t length,
                                 unsigned char needle) {
#if PDT_ASM_COMPILED
    if (pdt_use_assembly()) {
        return pdt_asm_count_byte(data, length, needle);
    }
#endif
    return pdt_count_byte_scalar(data, length, needle);
}

static size_t pdt_count_byte_cpu_buffer(PyObject *object,
                                       const unsigned char *data,
                                       size_t length,
                                       unsigned char needle) {
    size_t count;
    if (PyBytes_Check(object)) {
        Py_BEGIN_ALLOW_THREADS
        count = pdt_count_byte_cpu(data, length, needle);
        Py_END_ALLOW_THREADS
        return count;
    }
    return pdt_count_byte_cpu(data, length, needle);
}

static PyObject *pdt_native_count_byte(PyObject *self, PyObject *args) {
    PyObject *object;
    Py_buffer view;
    int needle;
    size_t count;
    unsigned long long gpu_count = 0;

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

    /* The OpenCL path releases the GIL while the device reads the host buffer.
       Use it only for immutable bytes; mutable exporters stay on the GIL-held CPU
       path so another Python thread cannot mutate their contents concurrently. */
    if (PyBytes_Check(object) && (size_t)view.len >= PDT_GPU_MIN_BYTES) {
        int reason = PDT_GPU_REASON_DISPATCH;
        int dispatched = 0;
        if (pdt_gpu_test_fault >= 0) {
            reason = pdt_gpu_test_fault;
        } else if (!pdt_opencl_initialize()) {
            reason = pdt_gpu_unavailable_reason >= 0 ? pdt_gpu_unavailable_reason : PDT_GPU_REASON_DEVICE;
        } else {
            dispatched = pdt_opencl_count_byte(
                (const unsigned char *)view.buf, (size_t)view.len,
                (unsigned char)needle, &gpu_count, &reason
            );
        }
        if (dispatched) {
            count = (size_t)gpu_count;
            ++pdt_gpu_dispatches;
        } else {
            ++pdt_gpu_fallbacks;
            ++pdt_gpu_fallback_reasons[reason];
            count = pdt_count_byte_cpu_buffer(
                object, (const unsigned char *)view.buf, (size_t)view.len,
                (unsigned char)needle
            );
        }
    } else {
        count = pdt_count_byte_cpu_buffer(
            object, (const unsigned char *)view.buf, (size_t)view.len,
            (unsigned char)needle
        );
    }

    PyBuffer_Release(&view);
    return PyLong_FromSize_t(count);
}

static PyObject *pdt_native_set_gpu_test_fault(PyObject *self, PyObject *args) {
    const char *name = NULL;
    int index;

    (void)self;
    if (!PyArg_ParseTuple(args, "z:_set_gpu_test_fault", &name)) {
        return NULL;
    }
    if (name == NULL) {
        pdt_gpu_test_fault = -1;
        Py_RETURN_NONE;
    }
    for (index = 0; index < PDT_GPU_REASON_COUNT; ++index) {
        if (strcmp(name, pdt_gpu_reason_names[index]) == 0) {
            pdt_gpu_test_fault = index;
            Py_RETURN_NONE;
        }
    }
    PyErr_SetString(PyExc_ValueError, "unknown GPU fallback reason");
    return NULL;
}

static PyObject *pdt_gpu_reason_counts(void) {
    PyObject *counts = PyDict_New();
    int index;

    if (counts == NULL) {
        return NULL;
    }
    for (index = 0; index < PDT_GPU_REASON_COUNT; ++index) {
        PyObject *value = PyLong_FromUnsignedLongLong(pdt_gpu_fallback_reasons[index]);
        if (value == NULL || PyDict_SetItemString(counts, pdt_gpu_reason_names[index], value) < 0) {
            Py_XDECREF(value);
            Py_DECREF(counts);
            return NULL;
        }
        Py_DECREF(value);
    }
    return counts;
}

static PyObject *pdt_native_capabilities(PyObject *self, PyObject *Py_UNUSED(args)) {
    const char *architecture = "unknown";
    long hardware_threads = 1;
    int gpu_available;
    PyObject *reasons;

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

    gpu_available = pdt_opencl_initialize();
    reasons = pdt_gpu_reason_counts();
    if (reasons == NULL) {
        return NULL;
    }
    return Py_BuildValue(
        "{s:s,s:s,s:l,s:O,s:O,s:O,s:s,s:s,s:I,s:s,s:K,s:K,s:K,s:K,s:K,s:s,s:N}",
        "architecture", architecture,
        "backend", pdt_backend_name(),
        "hardware_threads", hardware_threads,
        "assembly_compiled", PDT_ASM_COMPILED ? Py_True : Py_False,
        "gpu_available", gpu_available ? Py_True : Py_False,
        "opencl_available", gpu_available ? Py_True : Py_False,
        "gpu_backend", gpu_available ? "opencl" : "none",
        "gpu_name", gpu_available ? pdt_opencl.name : "",
        "gpu_compute_units", gpu_available ? pdt_opencl.compute_units : 0,
        "gpu_vendor", gpu_available ? pdt_opencl.vendor : "",
        "gpu_global_memory_bytes",
            (unsigned long long)(gpu_available ? pdt_opencl.global_memory_bytes : 0),
        "gpu_max_allocation_bytes",
            (unsigned long long)(gpu_available ? pdt_opencl.max_allocation_bytes : 0),
        "gpu_threshold_bytes", (unsigned long long)PDT_GPU_MIN_BYTES,
        "gpu_dispatches", pdt_gpu_dispatches,
        "gpu_fallbacks", pdt_gpu_fallbacks,
        "gpu_unavailable_reason",
            gpu_available || pdt_gpu_unavailable_reason < 0 ? "" : pdt_gpu_reason_names[pdt_gpu_unavailable_reason],
        "gpu_fallback_reasons", reasons
    );
}

static PyMethodDef pdt_native_methods[] = {
    {"count_byte", pdt_native_count_byte, METH_VARARGS,
     "Count a byte using automatic OpenCL GPU or runtime-selected CPU acceleration."},
    {"capabilities", pdt_native_capabilities, METH_NOARGS,
     "Return CPU, OpenCL GPU and native backend capability information."},
    {"_set_gpu_test_fault", pdt_native_set_gpu_test_fault, METH_VARARGS,
     "Tests only: force every eligible buffer onto the CPU with this fallback reason (None clears)."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef pdt_native_module = {
    PyModuleDef_HEAD_INIT,
    "_native",
    "PDT native C core with optional OpenCL GPU and x86-64 Assembly acceleration.",
    -1,
    pdt_native_methods
};

PyMODINIT_FUNC PyInit__native(void) {
    return PyModule_Create(&pdt_native_module);
}
