/* Reuse the native suite's ABI fixture, but consume a spec encoded by TypeScript
 * and emit the production writer's JSONL. No mutation records are synthesized. */
#define main native_unit_test_main
#include "../test_interpose_mutation.c"
#undef main

int main(int argc, char **argv) {
    CHECK(argc == 6);
    atfield_marshal_spec_t spec;
    uint8_t projection[512];
    size_t projection_size;
    load_projection(&spec, (projection_options_t){0,0,1,1,1}, projection, &projection_size);
    spec.parameters[0][3].direction = ATFIELD_MUTATION_DIR_INOUT;
    spec.ecalls[0].bundle_manifest_sha256 = argv[3];
    spec.ecalls[0].marshal_layout_sha256 = argv[4];
    const atfield_mutation_layout_t *layout = atfield_marshal_spec_get(&spec, 0);
    CHECK(layout != NULL);
    atfield_mutation_state_t state;
    CHECK(atfield_mutation_load_spec(&state, argv[1], argv[3], argv[4]) == 0);
    CHECK(atfield_mutation_bind_run(&state, 7, 1) == 0);
    CHECK(setenv("ATFIELD_CAPTURE_BUFFERS", "1", 1) == 0);
    atfield_call_capture_t capture;
    CHECK(atfield_call_capture_open(&capture, argv[2],
        argv[5], argv[3], argv[4]) == 0);
    int32_t backing[2] = {(int32_t)0x11223344, 0x55667788};
    marshal_t ms, working;
    init_ms(&ms, 42, sizeof(backing), backing);
    int last_rc = 0;
    int zero_expansion = 1;
    for (uint64_t seq = 0; seq <= state.rule.occurrence; seq++) {
        atfield_call_capture_record_t record;
        last_rc = atfield_mutation_before_ecall(&state, 7, 1, seq, 0, seq, layout,
            &ms, &working, sizeof(working), &record);
        marshal_t *effective = last_rc == 1 ? &working : &ms;
        if (last_rc == 1 && effective->bound_size > sizeof(backing)) {
            CHECK(memcmp(effective->buffer, backing, sizeof(backing)) == 0);
            const uint8_t *bytes = effective->buffer;
            for (size_t i = sizeof(backing); i < effective->bound_size; i++) {
                if (bytes[i] != 0) zero_expansion = 0;
            }
            /* Exercise the full expanded output capacity before cleanup. */
            ((uint8_t *)effective->buffer)[effective->bound_size - 1] = 0x5a;
        }
        CHECK(atfield_mutation_after_ecall(&state, layout, effective, &ms, &record) == 0);
        CHECK(atfield_call_capture_write_ecall(&capture, &record, 0) == 0);
    }
    const int final = atfield_call_capture_close(&capture, &state);
    printf("{\"beforeRc\":%d,\"finalize\":%d,\"reason\":\"%s\","
           "\"zeroExpansion\":%s,\"perBufferBytes\":%zu,\"totalBytes\":%zu}\n",
        last_rc, final, atfield_mutation_invalid_reason(&state),
        zero_expansion ? "true" : "false", state.rule.expansion_buffer_budget,
        state.rule.expansion_total_budget);
    return 0;
}
