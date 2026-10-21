import type {
  CapturedObjectSnapshot,
  CapturedRecord,
  Edger8rAbiSchema,
  ReplayContracts,
} from "../sequence/types";

export type ReplaySignedness = "signed" | "unsigned";
export type ReplayLayoutDirection = "value" | "val" | "in" | "out" | "inout";

export interface ReplayMarshalParameterV1 {
  parameter_index: number;
  name: string;
  ms_offset: number;
  ms_size: number;
  source_type: string;
  is_pointer: boolean;
  width_bytes: number;
  signedness: ReplaySignedness | "not_applicable";
  direction: ReplayLayoutDirection;
  element_width_bytes?: number;
  bound_parameter_index?: number | null;
}

export interface ReplayMarshalLayoutV1 {
  schema: "atfield-marshal-layout-v1";
  compiler_probed: true;
  selector_ordinal: number;
  marshal_size: number;
  parameters: readonly ReplayMarshalParameterV1[];
}

export interface ReplayBundleInputs {
  manifest_sha256: string;
  abi: Edger8rAbiSchema;
  marshal_layout_sha256: string;
  marshal_layout: ReplayMarshalLayoutV1;
  contracts?: ReplayContracts;
}

export interface ReplayBufferCaptureEvidence {
  object_id: string;
  generation: number;
  base_slice: { offset: number; length: number };
  capacity: number;
  sha256: string;
}

export interface ReplayBaselineCall extends CapturedRecord {
  selector_seq: number;
  buffer_evidence?: Readonly<Record<number, ReplayBufferCaptureEvidence>>;
}

export type IntegerInput = bigint | number | string;

export interface ScalarReplayCandidate {
  kind: "scalar";
  param_index: number;
  expected_value: IntegerInput;
  replacement_value: IntegerInput;
}

export interface BytesReplayCandidate {
  kind: "bytes";
  param_index: number;
  expected_length: number;
  expected_sha256: string;
  replacement_bytes: readonly number[];
}

export type ReplayCandidate = ScalarReplayCandidate | BytesReplayCandidate;

export interface ReplayLimits {
  max_depth: number;
  max_total_bytes: number;
  max_objects: number;
  max_array_elements: number;
  max_candidates: number;
}

export interface PlannedScalarParameter {
  kind: "scalar";
  param_index: number;
  name: string;
  width_bytes: number;
  signedness: ReplaySignedness;
  direction: "value";
  expected_bits: string;
  effective_bits: string;
}

export interface ReplayBufferShape {
  object_id: string;
  object_generation: number;
  offset: number;
  byte_length: number;
  element_width_bytes: number;
  element_count: number;
  object_capacity: number;
  object_sha256: string;
  slice_sha256: string;
}

export interface PlannedBufferParameter {
  kind: "buffer";
  param_index: number;
  name: string;
  direction: "in" | "out" | "inout";
  is_null: boolean;
  element_width_bytes: number;
  element_count: number;
  array_dimensions: readonly number[];
  byte_length: number;
  copy_back: boolean;
  owned_storage: "single_pointer_copy";
  rebuild_owned_buffer: boolean;
  object_id: string | null;
  object_generation: number | null;
  offset: number;
  expected_shape: ReplayBufferShape | null;
  effective_shape: ReplayBufferShape | null;
  effective_slice_sha256: string | null;
}

export interface ReplayMemoryObject {
  object_id: string;
  generation: number;
  kind: "buffer" | "record";
  capacity: number;
  baseline_sha256: string;
  initial_sha256: string;
  initial_bytes_hex: string;
}

export interface ReplayScalarOperation {
  op: "replace_scalar";
  param_index: number;
  width_bytes: number;
  signedness: ReplaySignedness;
  expected_bits: string;
  replacement_bits: string;
}

export interface ReplayBufferOperation {
  op: "replace_buffer";
  param_index: number;
  expected_shape: ReplayBufferShape;
  replacement_shape: ReplayBufferShape;
  replacement_bytes_hex: string;
  replacement_sha256: string;
}

export interface ReplayPlanV1 {
  schema: "atfield-replay-plan-v1";
  version: 1;
  binding: {
    bundle_manifest_sha256: string;
    marshal_layout_sha256: string;
  };
  target: {
    selector_ordinal: number;
    selector_seq: number;
    instance_generation: number;
    call_seq: number;
    ecall_name: string;
  };
  action: "reconstruct_captured_call_once";
  parameters: readonly (PlannedScalarParameter | PlannedBufferParameter)[];
  memory: readonly ReplayMemoryObject[];
  scalar_ops: readonly ReplayScalarOperation[];
  buffer_ops: readonly ReplayBufferOperation[];
}

export interface ReplayPlanOptions {
  limits?: Partial<ReplayLimits>;
}

export class ReplayPlanningError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ReplayPlanningError";
    this.code = code;
  }
}

export type { CapturedObjectSnapshot };
