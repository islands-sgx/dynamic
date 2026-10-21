export const ABI_SCHEMA_NAME = "atfield-edl-abi-v1" as const;

export type JsonScalar = string | number | boolean | null;
export type ValueKind = "scalar" | "buffer" | "record" | "opaque";
export type Direction = "value" | "in" | "out" | "inout" | "unspecified";

export interface AbiTypeNode {
  kind: "builtin" | "pointer" | "named" | "struct" | "union" | "enum";
  name?: string;
  signedness?: string;
  resolved?: boolean;
  to?: AbiTypeNode;
}

export interface AbiAttributeSet {
  size: BoundExpression | null;
  count: BoundExpression | null;
  string: boolean;
  wstring: boolean;
  user_check: boolean;
  isptr: boolean;
  isary: boolean;
  readonly: boolean;
}
export type BoundExpression = { kind: "integer"; value: number } | { kind: "identifier"; name: string };

export interface AbiField {
  name: string;
  type: AbiTypeNode;
  pointer_depth: number;
  array_dimensions: readonly number[];
  form?: "value" | "pointer";
  direction?: Direction;
  attributes?: AbiAttributeSet | null;
}

export interface AbiTypeDefinition {
  kind: "struct" | "union" | "enum" | "named";
  name: string;
  fields?: readonly AbiField[];
  values?: readonly { name: string; value: BoundExpression | null }[];
  resolved?: boolean;
}

export interface AbiParameter extends AbiField {
  form: "value" | "pointer";
  direction: Direction;
  attributes: AbiAttributeSet | null;
}

export interface AbiEcall {
  ordinal: number;
  name: string;
  visibility: string;
  switchless: boolean;
  return_type: AbiTypeNode;
  parameters: readonly AbiParameter[];
}

export interface Edger8rAbiSchema {
  schema: typeof ABI_SCHEMA_NAME;
  tool: Record<string, unknown>;
  input: Record<string, unknown>;
  types: readonly AbiTypeDefinition[];
  ecalls: readonly AbiEcall[];
  ocalls: readonly unknown[];
  [key: string]: unknown;
}

export interface CapturedScalar { kind: "scalar"; value: JsonScalar; }
export interface CapturedObjectRef {
  kind: "object_ref";
  object_id: string;
  generation?: number;
  offset?: number;
  length?: number;
}
export type CapturedValue = CapturedScalar | CapturedObjectRef | JsonScalar;

export interface CapturedObjectSnapshot {
  kind: ValueKind;
  generation: number;
  value?: JsonScalar;
  capacity?: number;
  actual_length?: number;
  bytes?: readonly number[];
  fields?: Readonly<Record<string, CapturedValue>>;
  active_member?: string;
}
export interface CapturedRecord {
  instance_generation: number;
  call_seq: number;
  ordinal: number;
  arguments: Readonly<Record<string, CapturedValue>>;
  outputs: Readonly<Record<string, CapturedValue>>;
  objects: Readonly<Record<string, CapturedObjectSnapshot>>;
}

export interface ReplayContract {
  pure?: boolean;
  idempotent?: boolean;
  sizeQuery?: {
    bufferParameter: string;
    lengthParameter: string;
    stability?:
      | { kind: "abi-contract" | "external-contract"; evidenceId: string }
      | { kind: "fresh-instance-differential"; minimumInstances: number };
  };
}
export type ReplayContracts = Readonly<Record<number, ReplayContract>>;

