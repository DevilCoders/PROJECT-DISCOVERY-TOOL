/* A fake OpenCL ICD loader for tests: one GPU device whose behavior PDT_FAKE_OPENCL selects.
 *
 *   ok            a working device; kernels run on the host with the real kernel's semantics
 *   small_memory  works, with a 16 MiB allocation limit and 64 MiB of memory
 *   no_platform   no OpenCL platform
 *   no_device     a platform without a GPU device
 *   no_limits     a device that does not report its memory limits
 *   context       context creation fails
 *   build         kernel compilation fails
 *   dispatch      enqueueing a kernel fails
 *   buffer        buffer allocation fails
 *
 * Built with -DPDT_FAKE_MISSING_SYMBOL, the library lacks clFinish (an incomplete loader).
 * PDT loads it as libOpenCL.so.1 through LD_LIBRARY_PATH (Linux only).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef int32_t cl_int;
typedef uint32_t cl_uint;
typedef uint64_t cl_ulong;

struct fake_buffer { size_t size; unsigned char *data; };
struct fake_kernel { struct fake_buffer *input; cl_ulong length; unsigned char needle; struct fake_buffer *partial; };

static int platform_object, device_object, context_object, queue_object, program_object;
static struct fake_kernel kernel_object;

static const char *mode(void) {
    const char *value = getenv("PDT_FAKE_OPENCL");
    return value != NULL ? value : "ok";
}

static int is(const char *name) { return strcmp(mode(), name) == 0; }

static void set_error(cl_int *error, cl_int value) { if (error != NULL) *error = value; }

cl_int clGetPlatformIDs(cl_uint entries, void **platforms, cl_uint *count) {
    cl_uint available = is("no_platform") ? 0 : 1;
    if (count != NULL) *count = available;
    if (platforms != NULL && entries > 0 && available) platforms[0] = &platform_object;
    return 0;
}

cl_int clGetDeviceIDs(void *platform, cl_ulong type, cl_uint entries, void **devices, cl_uint *count) {
    (void)platform; (void)type;
    if (is("no_device")) {
        if (count != NULL) *count = 0;
        return -1; /* CL_DEVICE_NOT_FOUND */
    }
    if (count != NULL) *count = 1;
    if (devices != NULL && entries > 0) devices[0] = &device_object;
    return 0;
}

static cl_int copy_value(const void *value, size_t size, size_t capacity, void *out, size_t *written) {
    if (out != NULL) memcpy(out, value, size < capacity ? size : capacity);
    if (written != NULL) *written = size;
    return 0;
}

cl_int clGetDeviceInfo(void *device, cl_uint name, size_t capacity, void *out, size_t *written) {
    cl_uint units = 4;
    cl_ulong allocation = is("small_memory") ? (cl_ulong)16 << 20 : (cl_ulong)1 << 30;
    cl_ulong memory = is("small_memory") ? (cl_ulong)64 << 20 : (cl_ulong)4 << 30;
    (void)device;
    if (is("no_limits")) allocation = memory = 0;
    switch (name) {
    case 0x1002: return copy_value(&units, sizeof(units), capacity, out, written);
    case 0x1010: return copy_value(&allocation, sizeof(allocation), capacity, out, written);
    case 0x101F: return copy_value(&memory, sizeof(memory), capacity, out, written);
    case 0x102B: return copy_value("PDT Fake GPU", 13, capacity, out, written);
    case 0x102C: return copy_value("PDT tests", 10, capacity, out, written);
    default: return -30; /* CL_INVALID_VALUE */
    }
}

void *clCreateContext(const intptr_t *properties, cl_uint count, void *const *devices,
                      void *notify, void *data, cl_int *error) {
    (void)properties; (void)count; (void)devices; (void)notify; (void)data;
    if (is("context")) { set_error(error, -6); return NULL; } /* CL_OUT_OF_HOST_MEMORY */
    set_error(error, 0);
    return &context_object;
}

void *clCreateCommandQueue(void *context, void *device, cl_ulong properties, cl_int *error) {
    (void)context; (void)device; (void)properties;
    set_error(error, 0);
    return &queue_object;
}

void *clCreateProgramWithSource(void *context, cl_uint count, const char **sources,
                                const size_t *lengths, cl_int *error) {
    (void)context; (void)count; (void)sources; (void)lengths;
    set_error(error, 0);
    return &program_object;
}

cl_int clBuildProgram(void *program, cl_uint count, void *const *devices, const char *options,
                      void *notify, void *data) {
    (void)program; (void)count; (void)devices; (void)options; (void)notify; (void)data;
    return is("build") ? -11 : 0; /* CL_BUILD_PROGRAM_FAILURE */
}

void *clCreateKernel(void *program, const char *name, cl_int *error) {
    (void)program;
    if (strcmp(name, "pdt_count_byte") != 0) { set_error(error, -46); return NULL; } /* CL_INVALID_KERNEL_NAME */
    memset(&kernel_object, 0, sizeof(kernel_object));
    set_error(error, 0);
    return &kernel_object;
}

void *clCreateBuffer(void *context, cl_ulong flags, size_t size, void *host, cl_int *error) {
    struct fake_buffer *buffer;
    (void)context;
    if (is("buffer")) { set_error(error, -4); return NULL; } /* CL_MEM_OBJECT_ALLOCATION_FAILURE */
    buffer = (struct fake_buffer *)calloc(1, sizeof(*buffer));
    if (buffer == NULL || (buffer->data = (unsigned char *)calloc(size ? size : 1, 1)) == NULL) {
        free(buffer);
        set_error(error, -6);
        return NULL;
    }
    buffer->size = size;
    if ((flags & ((cl_ulong)1 << 5)) && host != NULL) memcpy(buffer->data, host, size); /* COPY_HOST_PTR */
    set_error(error, 0);
    return buffer;
}

cl_int clSetKernelArg(void *kernel, cl_uint index, size_t size, const void *value) {
    struct fake_kernel *target = (struct fake_kernel *)kernel;
    switch (index) {
    case 0: memcpy(&target->input, value, sizeof(target->input)); return 0;
    case 1: memcpy(&target->length, value, sizeof(target->length)); return 0;
    case 2: memcpy(&target->needle, value, sizeof(target->needle)); return 0;
    case 3: memcpy(&target->partial, value, sizeof(target->partial)); return 0;
    case 4: return value == NULL && size > 0 ? 0 : -51; /* __local scratch; else CL_INVALID_ARG_SIZE */
    default: return -49; /* CL_INVALID_ARG_INDEX */
    }
}

cl_int clEnqueueNDRangeKernel(void *queue, void *kernel, cl_uint dimensions, const size_t *offset,
                              const size_t *global, const size_t *local, cl_uint events,
                              const void *wait, void *event) {
    struct fake_kernel *target = (struct fake_kernel *)kernel;
    cl_ulong *partials;
    size_t groups, index;
    (void)queue; (void)offset; (void)events; (void)wait; (void)event;
    if (is("dispatch")) return -5; /* CL_OUT_OF_RESOURCES */
    if (dimensions != 1 || global == NULL || local == NULL || *local == 0 || *global % *local != 0) return -54;
    groups = *global / *local;
    if (target->partial == NULL || target->partial->size < groups * sizeof(cl_ulong) || target->input == NULL ||
        target->input->size < target->length) {
        return -48; /* CL_INVALID_KERNEL_ARGS */
    }
    /* The kernel's work item gid counts the bytes gid, gid + global, ...; groups sum their items. */
    partials = (cl_ulong *)target->partial->data;
    memset(partials, 0, groups * sizeof(cl_ulong));
    for (index = 0; index < target->length; ++index) {
        partials[(index % *global) / *local] += target->input->data[index] == target->needle;
    }
    return 0;
}

cl_int clEnqueueReadBuffer(void *queue, void *memory, cl_uint blocking, size_t offset, size_t size,
                           void *out, cl_uint events, const void *wait, void *event) {
    struct fake_buffer *buffer = (struct fake_buffer *)memory;
    (void)queue; (void)blocking; (void)events; (void)wait; (void)event;
    if (offset + size > buffer->size) return -30;
    memcpy(out, buffer->data + offset, size);
    return 0;
}

#ifndef PDT_FAKE_MISSING_SYMBOL
cl_int clFinish(void *queue) { (void)queue; return 0; }
#endif

cl_int clReleaseMemObject(void *memory) {
    struct fake_buffer *buffer = (struct fake_buffer *)memory;
    free(buffer->data);
    free(buffer);
    return 0;
}

cl_int clReleaseKernel(void *kernel) { (void)kernel; return 0; }
cl_int clReleaseCommandQueue(void *queue) { (void)queue; return 0; }
cl_int clReleaseProgram(void *program) { (void)program; return 0; }
cl_int clReleaseContext(void *context) { (void)context; return 0; }
