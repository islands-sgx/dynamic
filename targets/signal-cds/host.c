#include <sgx_urts.h>

#ifdef ATFIELD_PROTECT
#include "../../common/atfield_readiness_host.h"
#endif

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sabd.h"
#include "sabd_enclave_u.h"

#ifndef ENCLAVE_PATH
#define ENCLAVE_PATH "enclave.signed.so"
#endif

#define SABD_MAX_ADDRESS_BOOK_IDS ((size_t)1 << 13)

typedef struct {
    size_t records;
    size_t queries;
    size_t requests;
    bool upstream_cmockery;
    long int upstream_seed;
    size_t upstream_in_jids;
} options_t;

static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s [--records N] [--queries N] [--requests N]\n",
            program);
}

static bool parse_size(const char *text, size_t *value)
{
    if (text == NULL || text[0] < '0' || text[0] > '9')
        return false;
    for (const char *digit = text; *digit != '\0'; digit++)
        if (*digit < '0' || *digit > '9')
            return false;

    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0' || parsed > SIZE_MAX)
        return false;
    *value = (size_t)parsed;
    return true;
}

static bool parse_options(int argc, char **argv, options_t *options)
{
    options->records = 8;
    options->queries = 6;
    options->requests = 2;
    options->upstream_cmockery = false;
    options->upstream_seed = 0x12345678L;
    options->upstream_in_jids = 10000;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return false;
        }
        if (strcmp(argv[i], "--upstream-cmockery-test") == 0) {
            options->upstream_cmockery = true;
            continue;
        }
        if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            options->upstream_seed = strtol(argv[++i], NULL, 0);
            continue;
        }
        if (strcmp(argv[i], "--in-jids") == 0 && i + 1 < argc) {
            if (!parse_size(argv[++i], &options->upstream_in_jids)) return false;
            continue;
        }
        if (i + 1 >= argc) {
            usage(argv[0]);
            return false;
        }

        size_t *destination = NULL;
        if (strcmp(argv[i], "--records") == 0)
            destination = &options->records;
        else if (strcmp(argv[i], "--queries") == 0)
            destination = &options->queries;
        else if (strcmp(argv[i], "--requests") == 0)
            destination = &options->requests;
        else {
            usage(argv[0]);
            return false;
        }

        if (!parse_size(argv[++i], destination)) {
            usage(argv[0]);
            return false;
        }
    }

    if (options->queries > SABD_MAX_ADDRESS_BOOK_IDS ||
        options->records > SIZE_MAX / sizeof(jid_t) ||
        options->queries > SIZE_MAX / sizeof(jid_t)) {
        usage(argv[0]);
        return false;
    }
    return true;
}

static jid_t record_id(size_t index)
{
    return UINT64_C(0x1000000000000000) | ((jid_t)index + 1);
}

static int lookup(sgx_enclave_id_t enclave_id, const jid_t *in_jids,
                  size_t in_jid_count, const jid_t *ab_jids,
                  size_t ab_jid_count, uint8_t *results)
{
    sgx_status_t enclave_result = SGX_ERROR_UNEXPECTED;
    sgx_status_t status =
        ecall_lookup_hash(enclave_id, &enclave_result, in_jids, in_jid_count,
                          ab_jids, (uint32_t)ab_jid_count, results);
    if (status != SGX_SUCCESS || enclave_result != SGX_SUCCESS) {
        fprintf(stderr, "lookup failed: SGX=%#x result=%#x\n",
                (unsigned int)status, (unsigned int)enclave_result);
        return 1;
    }
    return 0;
}

static int check_membership(sgx_enclave_id_t enclave_id,
                            const jid_t *in_jids, size_t in_jid_count,
                            const jid_t *ab_jids, size_t ab_jid_count)
{
    if (ab_jid_count > SIZE_MAX / sizeof(jid_t))
        return 1;

    uint8_t *results = NULL;
    if (ab_jid_count != 0) {
        results = (uint8_t *)malloc(ab_jid_count);
        if (results == NULL)
            return 1;
        memset(results, 0x7f, ab_jid_count);
    }

    int failed = lookup(enclave_id, in_jids, in_jid_count, ab_jids,
                        ab_jid_count, results);
    for (size_t i = 0; !failed && i < ab_jid_count; i++) {
        uint8_t expected = 0;
        for (size_t j = 0; j < in_jid_count; j++)
            expected |= (uint8_t)(ab_jids[i] == in_jids[j]);
        if (results[i] != expected) {
            fprintf(stderr, "membership mismatch at record %zu\n", i);
            failed = 1;
        }
    }

    free(results);
    return failed;
}

static int check_fixed_cases(sgx_enclave_id_t enclave_id)
{
    const jid_t in_records[] = {
        UINT64_C(0x1200000000000001),
        UINT64_C(0x1200000000000002),
        UINT64_C(0x1200000000000001),
    };
    const jid_t queries[] = {
        UINT64_C(0x1200000000000001),
        UINT64_C(0x1f00000000000000),
        UINT64_C(0x1200000000000001),
    };

    return check_membership(enclave_id, in_records, 3, queries, 3) != 0 ||
           check_membership(enclave_id, NULL, 0, queries, 3) != 0 ||
           check_membership(enclave_id, in_records, 3, NULL, 0) != 0;
}

static int check_requested_cases(sgx_enclave_id_t enclave_id,
                                 const options_t *options)
{
    if (options->records > SIZE_MAX / sizeof(jid_t) ||
        options->queries > SABD_MAX_ADDRESS_BOOK_IDS ||
        options->queries > SIZE_MAX / sizeof(jid_t))
        return 1;

    jid_t *in_jids = NULL;
    jid_t *ab_jids = NULL;
    if (options->records != 0) {
        in_jids = (jid_t *)malloc(options->records * sizeof(jid_t));
        if (in_jids == NULL)
            return 1;
        for (size_t i = 0; i < options->records; i++)
            in_jids[i] = record_id(i);
        if (options->records > 1)
            in_jids[options->records - 1] = in_jids[0];
    }
    if (options->queries != 0) {
        ab_jids = (jid_t *)malloc(options->queries * sizeof(jid_t));
        if (ab_jids == NULL) {
            free(in_jids);
            return 1;
        }
        for (size_t i = 0; i < options->queries; i++) {
            if (i == 0 && options->records != 0)
                ab_jids[i] = in_jids[0];
            else if (i == 2 && options->queries > 1)
                ab_jids[i] = ab_jids[0];
            else
                ab_jids[i] =
                    UINT64_C(0xf000000000000000) | ((jid_t)i + 1);
        }
        if (options->queries > 1)
            ab_jids[1] = UINT64_C(0xe000000000000001);
    }

    int failed = 0;
    for (size_t i = 0; i < options->requests && !failed; i++)
        failed = check_membership(enclave_id, in_jids, options->records,
                                  ab_jids, options->queries);

    free(ab_jids);
    free(in_jids);
    return failed;
}

static int check_boundary(sgx_enclave_id_t enclave_id)
{
    const jid_t in_jids[] = {record_id(0), record_id(1)};
    if (SABD_MAX_ADDRESS_BOOK_IDS > SIZE_MAX / sizeof(jid_t))
        return 1;

    jid_t *ab_jids =
        (jid_t *)malloc(SABD_MAX_ADDRESS_BOOK_IDS * sizeof(jid_t));
    if (ab_jids == NULL)
        return 1;
    for (size_t i = 0; i < SABD_MAX_ADDRESS_BOOK_IDS; i++)
        ab_jids[i] = record_id(i);

    int failed = check_membership(enclave_id, in_jids,
                                  sizeof(in_jids) / sizeof(in_jids[0]),
                                  ab_jids, SABD_MAX_ADDRESS_BOOK_IDS);
    free(ab_jids);
    return failed;
}


/* Ported directly from upstream signalapp/ContactDiscoveryService/enclave/src/sabd-enclave-test.c:
 * Preserves drand48_data / mrand48_r JID generation, setup_sabd_lookup_test,
 * test_sabd_lookup_batch_too_large, test_sabd_lookup_many_duplicates,
 * test_sabd_lookup_small_all_in_jids, test_sabd_lookup_small_no_in_jids,
 * test_sabd_lookup_small_random, and test_sabd_lookup_large with original assertions.
 */
static int upstream_test_sabd_lookup(
    sgx_enclave_id_t enclave_id,
    const jid_t *test_in_jids,
    size_t in_jid_count,
    const jid_t *ab_jids,
    uint32_t ab_jid_count,
    const uint8_t *expected_in_ab_jids_result)
{
    uint8_t *in_ab_jids_result = (uint8_t *)calloc(ab_jid_count ? ab_jid_count : 1, 1);
    if (!in_ab_jids_result) return 1;
    sgx_status_t enclave_result = SGX_ERROR_UNEXPECTED;
    sgx_status_t st = ecall_lookup_hash(
        enclave_id, &enclave_result, test_in_jids, in_jid_count, ab_jids, ab_jid_count, in_ab_jids_result);
    if (st != SGX_SUCCESS || enclave_result != SGX_SUCCESS) {
        free(in_ab_jids_result);
        return 1;
    }
    for (uint32_t idx = 0; idx < ab_jid_count; idx++) {
        in_ab_jids_result[idx] = (uint8_t)(!!(in_ab_jids_result[idx]));
    }
    int mismatch = (ab_jid_count > 0 && memcmp(in_ab_jids_result, expected_in_ab_jids_result, ab_jid_count) != 0);
    free(in_ab_jids_result);
    return mismatch ? 1 : 0;
}

static int run_upstream_cmockery_suite(sgx_enclave_id_t enclave_id, long int seed, size_t in_jid_count)
{
    const uint32_t test_ab_jid_count = 2048;
    struct drand48_data drand_state;
    srand48_r(seed, &drand_state);

    jid_t *test_in_jids = (jid_t *)calloc(in_jid_count ? in_jid_count : 1, sizeof(jid_t));
    jid_t *test_ab_jids = (jid_t *)calloc(test_ab_jid_count, sizeof(jid_t));
    uint8_t *test_expected = (uint8_t *)calloc(test_ab_jid_count, 1);
    if (!test_in_jids || !test_ab_jids || !test_expected) {
        free(test_in_jids);
        free(test_ab_jids);
        free(test_expected);
        return 1;
    }

    for (size_t i = 0; i < in_jid_count; i++) {
        long int r1 = 0, r2 = 0;
        mrand48_r(&drand_state, &r1);
        mrand48_r(&drand_state, &r2);
        jid_t jid = (uint32_t)r1 | (((uint64_t)(uint32_t)r2) << 32);
        if (jid <= 1) jid += 2;
        test_in_jids[i] = jid;
    }
    for (uint32_t ab_idx = 0; ab_idx < test_ab_jid_count; ab_idx++) {
        long int r = 0;
        mrand48_r(&drand_state, &r);
        uint32_t rand_idx = (uint32_t)((unsigned long)r % (in_jid_count * 2));
        if (rand_idx < in_jid_count) {
            test_ab_jids[ab_idx] = test_in_jids[rand_idx];
            test_expected[ab_idx] = 1;
        } else {
            test_ab_jids[ab_idx] = 1;
            test_expected[ab_idx] = 0;
        }
    }

    int failed = 0;
    /* 1. test_sabd_lookup_batch_too_large: ab_jid_count = (1 << 14) + 1 -> SGX_ERROR_INVALID_PARAMETER */
    {
        uint32_t too_large = (1U << 14) + 1U;
        jid_t *ab_big = (jid_t *)calloc(too_large, sizeof(jid_t));
        uint8_t *res_big = (uint8_t *)calloc(too_large, 1);
        sgx_status_t encl_ret = SGX_SUCCESS;
        sgx_status_t st = ecall_lookup_hash(enclave_id, &encl_ret, test_in_jids, in_jid_count, ab_big, too_large, res_big);
        if (st != SGX_SUCCESS || encl_ret != SGX_ERROR_INVALID_PARAMETER) failed = 1;
        free(ab_big);
        free(res_big);
    }

    /* 2. test_sabd_lookup_many_duplicates (2048 queries, even indices duplicated) */
    if (!failed) {
        jid_t *ab_dup = (jid_t *)malloc(test_ab_jid_count * sizeof(jid_t));
        uint8_t *exp_dup = (uint8_t *)malloc(test_ab_jid_count);
        memcpy(ab_dup, test_ab_jids, test_ab_jid_count * sizeof(jid_t));
        memcpy(exp_dup, test_expected, test_ab_jid_count);
        for (uint32_t i = 0; i < test_ab_jid_count; i += 2) {
            ab_dup[i] = ab_dup[0];
            exp_dup[i] = exp_dup[0];
        }
        failed = upstream_test_sabd_lookup(enclave_id, test_in_jids, in_jid_count, ab_dup, test_ab_jid_count, exp_dup);
        free(ab_dup);
        free(exp_dup);
    }

    /* 3 & 4. test_sabd_lookup_small_all_in_jids (use_in=1) and test_sabd_lookup_small_no_in_jids (use_in=0) */
    for (int use_in = 1; use_in >= 0 && !failed; use_in--) {
        uint32_t max_small = 32;
        jid_t ab_small[32];
        uint8_t exp_small[32];
        uint32_t cnt = 0;
        for (uint32_t idx = 0; idx < test_ab_jid_count && cnt < max_small; idx++) {
            if (test_expected[idx] == (uint8_t)use_in) {
                exp_small[cnt] = (uint8_t)use_in;
                ab_small[cnt++] = test_ab_jids[idx];
            }
        }
        for (uint32_t c = 0; c <= cnt && !failed; c++) {
            failed = upstream_test_sabd_lookup(enclave_id, test_in_jids, in_jid_count, ab_small, c, exp_small);
        }
    }

    /* 5. test_sabd_lookup_small_random (ab_jid_count = 0..25) */
    for (uint32_t c = 0; c <= 25 && !failed; c++) {
        failed = upstream_test_sabd_lookup(enclave_id, test_in_jids, in_jid_count, test_ab_jids, c, test_expected);
    }

    /* 6. test_sabd_lookup_large (ab_jid_count = 2048) */
    if (!failed) {
        failed = upstream_test_sabd_lookup(enclave_id, test_in_jids, in_jid_count, test_ab_jids, test_ab_jid_count, test_expected);
    }

    free(test_in_jids);
    free(test_ab_jids);
    free(test_expected);
    return failed;
}

int main(int argc, char **argv)
{
    options_t options;
    if (!parse_options(argc, argv, &options))
        return argc == 2 && strcmp(argv[1], "--help") == 0 ? 0 : 64;

    sgx_launch_token_t token = {0};
    int token_updated = 0;
    sgx_enclave_id_t enclave_id = 0;
    sgx_status_t status = sgx_create_enclave(
        ENCLAVE_PATH, SGX_DEBUG_FLAG, &token, &token_updated, &enclave_id, NULL);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "sgx_create_enclave failed: %#x\n",
                (unsigned int)status);
        return 1;
    }

#ifdef ATFIELD_PROTECT
    if (!atfield_host_install_readiness(enclave_id)) {
        (void)sgx_destroy_enclave(enclave_id);
        return 1;
    }
#endif

    int failed = 0;
    if (options.upstream_cmockery) {
        failed = run_upstream_cmockery_suite(enclave_id, options.upstream_seed, options.upstream_in_jids);
    } else {
        const options_t defaults = {8, 6, 2, false, 0, 0};
        failed = check_fixed_cases(enclave_id) != 0 ||
                 check_requested_cases(enclave_id, &defaults) != 0;
        if (!failed && argc > 1)
            failed = check_requested_cases(enclave_id, &options) != 0;
        if (!failed && options.queries != SABD_MAX_ADDRESS_BOOK_IDS)
            failed = check_boundary(enclave_id) != 0;
    }

    status = sgx_destroy_enclave(enclave_id);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "sgx_destroy_enclave failed: %#x\n",
                (unsigned int)status);
        failed = 1;
    }
    if (failed)
        return 1;

    puts("Signal CDS lookup functional checks: PASS");
    return 0;
}
