#ifndef ATFIELD_READINESS_H
#define ATFIELD_READINESS_H

#include "sgx_urts.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum atfield_readiness_backend_t
{
    ATFIELD_READINESS_BACKEND_KERNEL = 0,
    ATFIELD_READINESS_BACKEND_USERSPACE = 1
} atfield_readiness_backend_t;

/* Load a ReadyTable v3 file, install its deep copy, then select backend.
 * system_error_out receives errno for file I/O failures, or zero otherwise.
 * No backend fallback occurs. */
sgx_status_t atfield_install_readiness_file(
    sgx_enclave_id_t enclave_id,
    const char *path,
    atfield_readiness_backend_t backend,
    int *system_error_out);

#ifdef __cplusplus
}
#endif

#endif
