#ifndef ATFIELD_READINESS_CONTRACT_H
#define ATFIELD_READINESS_CONTRACT_H

#include <string.h>

/* Existing pure-production launchers may install a table without a declared
 * digest. Final v2 opts into strict mode and must provide its frozen digest. */
static inline int atfield_readiness_sha_invalid(int required, const char *expected_sha) {
    const int present = expected_sha && *expected_sha;
    if (!present) return required != 0;
    return strlen(expected_sha) != 64;
}

#endif
