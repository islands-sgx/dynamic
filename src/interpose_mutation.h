#ifndef ATFIELD_INTERPOSE_MUTATION_H
#define ATFIELD_INTERPOSE_MUTATION_H
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#define ATFIELD_MUTATION_MAX_REPLACEMENTS 16
#define ATFIELD_MUTATION_MAX_PARAMS 64
#define ATFIELD_MUTATION_MAX_OMITTED ATFIELD_MUTATION_MAX_PARAMS
#define ATFIELD_MUTATION_DIGEST_HEX 64
#define ATFIELD_MUTATION_MAX_SPEC_BYTES (1024u * 1024u)
#define ATFIELD_MUTATION_SPEC_VERSION 1
#define ATFIELD_MUTATION_HEADER_BYTES 88
#define ATFIELD_MUTATION_RULE_HEADER_BYTES 24
#define ATFIELD_MUTATION_SCALAR_TLV_BYTES 32
#define ATFIELD_MUTATION_OP_REPLACE_SCALAR 1u
#define ATFIELD_MUTATION_OP_MUTATE_BUFFER 2u
#define ATFIELD_MUTATION_OP_EXTEND_HISTORY 3u
#define ATFIELD_BUF_OP_XOR_BYTE 1u
#define ATFIELD_BUF_OP_FILL_SLICE 2u
#define ATFIELD_BUF_OP_WRITE_LE 3u
#define ATFIELD_CAPTURE_MAX_BUF_PREFIX_BYTES 128u
#define ATFIELD_MARSHAL_MAX_ECALLS 64
#define ATFIELD_MARSHAL_MAX_TYPE_NAME 63
#define ATFIELD_MARSHAL_MAX_SPEC_BYTES (1024u * 1024u)
#define ATFIELD_MARSHAL_HEADER_BYTES 120
#define ATFIELD_MARSHAL_ECALL_HEADER_BYTES 28
#define ATFIELD_MARSHAL_PARAM_HEADER_BYTES 56
#define ATFIELD_CALL_CAPTURE_SCHEMA "atfield-call-capture-v1"
#define ATFIELD_MUTATION_RECORD_SCHEMA "atfield-native-mutation-record-v1"
typedef enum { ATFIELD_MUTATION_SCALAR_UNSIGNED=0, ATFIELD_MUTATION_SCALAR_SIGNED=1 } atfield_mutation_scalar_kind_t;
typedef enum { ATFIELD_MUTATION_DIR_VALUE=0, ATFIELD_MUTATION_DIR_IN=1, ATFIELD_MUTATION_DIR_OUT=2, ATFIELD_MUTATION_DIR_INOUT=3 } atfield_mutation_direction_t;
typedef enum { ATFIELD_MUTATION_CAT_INTEGER=1, ATFIELD_MUTATION_CAT_CHARACTER=2, ATFIELD_MUTATION_CAT_ENUM=3, ATFIELD_MUTATION_CAT_BOOLEAN=4, ATFIELD_MUTATION_CAT_POINTER=5, ATFIELD_MUTATION_CAT_RECORD=12, ATFIELD_MUTATION_CAT_UNION=13, ATFIELD_MUTATION_CAT_ARRAY=14 } atfield_mutation_category_t;
typedef enum { ATFIELD_MUTATION_TYPE_BUILTIN=1, ATFIELD_MUTATION_TYPE_NAMED=2, ATFIELD_MUTATION_TYPE_ENUM=3, ATFIELD_MUTATION_TYPE_STRUCT=4, ATFIELD_MUTATION_TYPE_UNION=5, ATFIELD_MUTATION_TYPE_POINTER=6 } atfield_mutation_type_kind_t;
typedef enum { ATFIELD_MUTATION_BOUND_NONE=0, ATFIELD_MUTATION_BOUND_SIZE=1, ATFIELD_MUTATION_BOUND_COUNT=2, ATFIELD_MUTATION_BOUND_STRING=3 } atfield_mutation_bound_kind_t;
typedef enum { ATFIELD_MUTATION_BOUND_SOURCE_NONE=0, ATFIELD_MUTATION_BOUND_SOURCE_LITERAL=1, ATFIELD_MUTATION_BOUND_SOURCE_PARAM=2 } atfield_mutation_bound_source_t;
typedef enum { ATFIELD_MUTATION_STORAGE_DIRECT=0, ATFIELD_MUTATION_STORAGE_POINTEE=1 } atfield_mutation_storage_t;

/* Projection of verified atfield-marshal-layout-v1 plus the bound EDL ABI type. */
typedef struct {
    uint32_t parameter_index;
    size_t ms_offset;
    size_t ms_size;
    uint8_t is_pointer;
    uint8_t array_decay;
    uint8_t pointer_depth;
    uint8_t direction;
    uint8_t type_category;
    int8_t signedness; /* -1 unknown, 0 unsigned, 1 signed */
    uint8_t type_kind;
    uint8_t replay_supported;
    uint8_t scalar_mutation_supported;
    uint8_t is_user_check;
    uint8_t size_source;
    uint8_t count_source;
    uint16_t size_parameter_index;
    uint16_t count_parameter_index;
    uint64_t size_literal;
    uint64_t count_literal;
    uint64_t fixed_array_element_count;
    size_t element_size;
    uint8_t element_type_category;
    int8_t element_signedness;
    uint8_t element_type_kind;
    uint8_t is_string;
    uint8_t is_wstring;
} atfield_mutation_param_layout_t;
typedef struct {
    uint32_t schema_version;
    uint8_t compiler_probed;
    int selector_ordinal;
    size_t marshal_size;
    const char *bundle_manifest_sha256;
    const char *marshal_layout_sha256;
    const char *edl_abi_sha256;
    size_t parameter_count;
    const atfield_mutation_param_layout_t *parameters;
    uint8_t replay_supported;
    uint8_t has_retval;
    size_t retval_offset;
    size_t retval_size;
    uint8_t retval_type_category;
    int8_t retval_signedness;
    uint8_t retval_type_kind;
} atfield_mutation_layout_t;
typedef struct {
    uint16_t op_type;
    uint16_t sub_op;
    uint32_t parameter_index;
    uint8_t kind;
    uint8_t width_bytes;
    uint32_t byte_offset;
    uint32_t slice_length;
    uint64_t expected_bits;
    uint64_t replacement_bits;
} atfield_mutation_scalar_op_t;
typedef struct {
    uint64_t target_generation;
    uint8_t exec_mode;
    int selector_ordinal;
    uint64_t occurrence;
    uint32_t hit_count;
    uint8_t applied;
    uint8_t operation_count;
    atfield_mutation_scalar_op_t operations[ATFIELD_MUTATION_MAX_REPLACEMENTS];
    void *cloned_buffers[ATFIELD_MUTATION_MAX_PARAMS];
    size_t cloned_sizes[ATFIELD_MUTATION_MAX_PARAMS];
    void *orig_ptrs[ATFIELD_MUTATION_MAX_PARAMS];
} atfield_mutation_rule_t;
typedef struct {
    uint32_t parameter_index;
    uint8_t direction;
    uint8_t is_string;
    uint32_t element_size;
    uint32_t byte_length;
    uint32_t prefix_length;
    uint64_t fnv1a64;
    uint8_t prefix_bytes[ATFIELD_CAPTURE_MAX_BUF_PREFIX_BYTES];
} atfield_captured_buffer_t;
typedef struct {
    uint32_t parameter_index;
    uint8_t storage;
    uint8_t kind;
    uint8_t width_bytes;
    uint64_t before_bits;
    uint64_t effective_bits;
    uint8_t has_effective;
} atfield_mutation_value_t;
typedef struct {
    uint32_t parameter_index;
    char reason[48];
} atfield_mutation_omission_t;
typedef struct {
    uint8_t target;
    uint8_t matched;
    uint8_t applied;
    char reason[64];
    uint32_t parameter_index;
    uint8_t kind;
    uint8_t width_bytes;
    uint8_t has_observed;
    uint64_t expected_bits;
    uint64_t observed_bits;
    uint64_t replacement_bits;
} atfield_mutation_result_t;
typedef struct {
    uint8_t initialized;
    uint8_t capture_complete;
    uint8_t layout_validated;
    uint8_t has_marshaled_block;
    uint64_t generation;
    uint64_t call_seq;
    int selector_ordinal;
    uint64_t selector_seq;
    size_t marshal_size;
    char bundle_manifest_sha256[ATFIELD_MUTATION_DIGEST_HEX+1];
    char marshal_layout_sha256[ATFIELD_MUTATION_DIGEST_HEX+1];
    atfield_mutation_value_t inputs[ATFIELD_MUTATION_MAX_PARAMS];
    size_t input_count;
    atfield_mutation_value_t outputs[ATFIELD_MUTATION_MAX_PARAMS];
    size_t output_count;
    atfield_mutation_omission_t omitted[ATFIELD_MUTATION_MAX_OMITTED];
    size_t omitted_count;
    uint8_t has_retval;
    atfield_mutation_value_t retval;
    atfield_mutation_result_t mutation;
    atfield_captured_buffer_t buffer_inputs[ATFIELD_MUTATION_MAX_PARAMS];
    size_t buffer_input_count;
} atfield_call_capture_record_t;
typedef struct {
    uint8_t enabled;
    uint8_t failed;
    FILE *fp;
    char run_id[129];
    char bundle_manifest_sha256[ATFIELD_MUTATION_DIGEST_HEX+1];
    char marshal_layout_sha256[ATFIELD_MUTATION_DIGEST_HEX+1];
    uint64_t ecall_count;
    uint64_t mutation_target_count;
    uint64_t mutation_matched_count;
    uint64_t mutation_applied_count;
    char failure_reason[64];
} atfield_call_capture_t;
typedef struct {
    uint8_t loaded;
    size_t ecall_count;
    char bundle_manifest_sha256[ATFIELD_MUTATION_DIGEST_HEX+1];
    char marshal_layout_sha256[ATFIELD_MUTATION_DIGEST_HEX+1];
    char edl_abi_sha256[ATFIELD_MUTATION_DIGEST_HEX+1];
    atfield_mutation_layout_t ecalls[ATFIELD_MARSHAL_MAX_ECALLS];
    atfield_mutation_param_layout_t parameters[ATFIELD_MARSHAL_MAX_ECALLS][ATFIELD_MUTATION_MAX_PARAMS];
    char error[64];
} atfield_marshal_spec_t;
typedef struct {
    uint8_t enabled;
    uint8_t configured;
    uint8_t invalid;
    uint8_t run_bound;
    uint8_t finalized;
    uint64_t bound_eid;
    uint64_t bound_generation;
    pthread_t owner_thread;
    char invalid_reason[64];
    char bundle_manifest_sha256[ATFIELD_MUTATION_DIGEST_HEX+1];
    char marshal_layout_sha256[ATFIELD_MUTATION_DIGEST_HEX+1];
    atfield_mutation_rule_t rule; /* v1 contains exactly one rule */
} atfield_mutation_state_t;
void atfield_mutation_init_disabled(atfield_mutation_state_t *state);
void atfield_marshal_spec_init(atfield_marshal_spec_t *spec);
int atfield_marshal_spec_load(atfield_marshal_spec_t *spec, const char *path, const char *bundle_manifest_sha256, const char *marshal_layout_sha256, const char *edl_abi_sha256);
const atfield_mutation_layout_t *atfield_marshal_spec_get(const atfield_marshal_spec_t *spec, int selector_ordinal);
const char *atfield_marshal_spec_error(const atfield_marshal_spec_t *spec);
int atfield_mutation_load_spec(atfield_mutation_state_t *state, const char *path, const char *bundle_manifest_sha256, const char *marshal_layout_sha256);
int atfield_mutation_load_spec_bytes(atfield_mutation_state_t *state, const uint8_t *bytes, size_t length, const char *bundle_manifest_sha256, const char *marshal_layout_sha256);
int atfield_mutation_bind_run(atfield_mutation_state_t *state, uint64_t eid, uint64_t generation);
/* Every ECALL can be captured. Return 1 only when a validated working clone was changed.
 * Return 0 for pass-through, -1 for invalid/pass-through. The original ECALL is called once either way. */
int atfield_mutation_before_ecall(atfield_mutation_state_t *state, uint64_t eid, uint64_t generation, uint64_t call_seq, int selector_ordinal, uint64_t selector_seq, const atfield_mutation_layout_t *layout, const void *original_ms, void *working_ms, size_t working_capacity, atfield_call_capture_record_t *record);
int atfield_mutation_after_ecall(atfield_mutation_state_t *state, const atfield_mutation_layout_t *layout, const void *completed_ms, void *original_ms, atfield_call_capture_record_t *record);
int atfield_mutation_finalize(atfield_mutation_state_t *state);
int atfield_mutation_is_valid(const atfield_mutation_state_t *state);
const char *atfield_mutation_invalid_reason(const atfield_mutation_state_t *state);
int atfield_call_capture_open(atfield_call_capture_t *capture, const char *path, const char *run_id, const char *bundle_manifest_sha256, const char *marshal_layout_sha256);
int atfield_call_capture_write_ecall(atfield_call_capture_t *capture, const atfield_call_capture_record_t *record, int transport_status);
int atfield_call_capture_close(atfield_call_capture_t *capture, atfield_mutation_state_t *mutation);
#endif
