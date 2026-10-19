#include "atfield_readiness.h"

#include <errno.h>
#include <fcntl.h>
#include <limits>
#include <new>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

extern "C" sgx_status_t atfield_sgx_set_ecall_page_readiness_backend(
    sgx_enclave_id_t enclave_id,
    uint32_t backend);

extern "C" sgx_status_t atfield_install_readiness_file(
    sgx_enclave_id_t enclave_id,
    const char *path,
    atfield_readiness_backend_t backend,
    int *system_error_out)
{
    if (system_error_out != NULL)
        *system_error_out = 0;
    if (path == NULL ||
        (backend != ATFIELD_READINESS_BACKEND_KERNEL &&
         backend != ATFIELD_READINESS_BACKEND_USERSPACE))
        return SGX_ERROR_INVALID_PARAMETER;

    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1)
    {
        if (system_error_out != NULL)
            *system_error_out = errno;
        return SGX_ERROR_UNEXPECTED;
    }

    struct stat before;
    if (fstat(fd, &before) == -1)
    {
        const int error = errno;
        close(fd);
        if (system_error_out != NULL)
            *system_error_out = error;
        return SGX_ERROR_UNEXPECTED;
    }
    if (!S_ISREG(before.st_mode) || before.st_size < 32 ||
        (uintmax_t)before.st_size > (uintmax_t)std::numeric_limits<size_t>::max())
    {
        close(fd);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::vector<uint8_t> bytes;
    try
    {
        bytes.resize((size_t)before.st_size);
    }
    catch (...)
    {
        close(fd);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    size_t offset = 0;
    while (offset < bytes.size())
    {
        const ssize_t count = read(fd, bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
        {
            const int error = count < 0 ? errno : EIO;
            close(fd);
            if (system_error_out != NULL)
                *system_error_out = error;
            return SGX_ERROR_UNEXPECTED;
        }
        offset += (size_t)count;
    }

    struct stat after;
    if (fstat(fd, &after) == -1)
    {
        const int error = errno;
        close(fd);
        if (system_error_out != NULL)
            *system_error_out = error;
        return SGX_ERROR_UNEXPECTED;
    }
    close(fd);
    if (after.st_size != before.st_size)
    {
        if (system_error_out != NULL)
            *system_error_out = EAGAIN;
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_page_readiness_table_t table;
    table.data = bytes.data();
    table.size = bytes.size();
    sgx_status_t status = sgx_set_ecall_page_readiness_table(enclave_id, &table);
    if (status != SGX_SUCCESS)
        return status;

    return atfield_sgx_set_ecall_page_readiness_backend(enclave_id, (uint32_t)backend);
}
