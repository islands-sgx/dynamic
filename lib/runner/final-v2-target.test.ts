import { expect, test } from "bun:test";
import type { ProfileBundle } from "../bundle/profile-bundle.ts";
import { assertFinalV2AexMetadata, assertFinalV2BundleIdentity, assertMeasurementConfigDerived, assertWorksetDigestBound, deriveMeasurementConfigXml } from "./final-v2-target.ts";
import { sha256 } from "../bundle/profile-bundle.ts";

const profileSha="11".repeat(32);
const signedProfileSha="22".repeat(32);
const bundle={manifestSha256:"33".repeat(32),layoutEpoch:"44".repeat(32),capacityQ:0x8000} as unknown as ProfileBundle;
const identity={profile_bundle_manifest_sha256:bundle.manifestSha256,layout_epoch:bundle.layoutEpoch,workset_schema:"atfield-workset-v2",capacity_q:bundle.capacityQ,production_aex_notify:true,measurement_aex_notify:false,measurement_signing_metadata_delta:"aex-notify-only"};
test("Final v2 selection binds the exact Profile bundle, epoch, and Q",()=>{
  expect(()=>assertFinalV2BundleIdentity(bundle,identity as never)).not.toThrow();
  expect(()=>assertFinalV2BundleIdentity(bundle,{...identity,profile_bundle_manifest_sha256:"55".repeat(32)} as never)).toThrow(/different Profile bundle/);
  expect(()=>assertFinalV2BundleIdentity(bundle,{...identity,layout_epoch:"66".repeat(32)} as never)).toThrow(/layout\/Q/);
  expect(()=>assertFinalV2BundleIdentity(bundle,{...identity,capacity_q:0x1000} as never)).toThrow(/layout\/Q/);
  expect(()=>assertFinalV2BundleIdentity(bundle,{...identity,workset_schema:"atfield-workset-v1"} as never)).toThrow(/layout\/Q/);
});

test("same layout and Q do not let a different workset digest reuse the frozen target",()=>{
  const common={schema:"atfield-workset-v2",layout_epoch:"aa".repeat(32),capacity_q:8192,fields_sha256:"bb".repeat(32)};
  const frozenSha=sha256(new TextEncoder().encode(JSON.stringify({...common,seed:"wolf"})));
  const otherSha=sha256(new TextEncoder().encode(JSON.stringify({...common,seed:"yes"})));
  expect(otherSha).not.toBe(frozenSha);
  expect(()=>assertWorksetDigestBound(frozenSha,frozenSha,"ready.workset_sha256")).not.toThrow();
  expect(()=>assertWorksetDigestBound(frozenSha,otherSha,"ready.workset_sha256")).toThrow(/does not match the frozen workset digest/);
});

test("diagnostic SGX config is derived from production by only disabling AEX notify",()=>{
  const production=["<EnclaveConfiguration>","  <HeapMaxSize>0x100000</HeapMaxSize>","  <EnableAEXNotify>1</EnableAEXNotify>","</EnclaveConfiguration>",""].join(String.fromCharCode(10));
  const diagnostic=deriveMeasurementConfigXml(production);
  expect(diagnostic).toBe(production.replace("<EnableAEXNotify>1</EnableAEXNotify>","<EnableAEXNotify>0</EnableAEXNotify>"));
  expect(()=>assertMeasurementConfigDerived(production,diagnostic)).not.toThrow();
  expect(()=>assertMeasurementConfigDerived(production,diagnostic.replace("0x100000","0x200000"))).toThrow(/only by EnableAEXNotify=0/);
  const duplicate=production.replace("</EnclaveConfiguration>","  <EnableAEXNotify>1</EnableAEXNotify>"+String.fromCharCode(10)+"</EnclaveConfiguration>");
  expect(()=>deriveMeasurementConfigXml(duplicate)).toThrow(/one explicit EnableAEXNotify=1/);
});
test("Final signed metadata requires AEX notify on production and off only on measurement",()=>{
  const base={version:5,metadata_size:0x1068,ssa_frame_pages:1,enclave_size:0x200000,attributes_xfrm:0xe7,layout_entries:[{id:1,rva:0,pages:1}]};
  expect(()=>assertFinalV2AexMetadata({...base,attributes_flags:0x404},{...base,attributes_flags:0x4})).not.toThrow();
  expect(()=>assertFinalV2AexMetadata({...base,attributes_flags:0x4},{...base,attributes_flags:0x4})).toThrow(/AEX_NOTIFY/);
  expect(()=>assertFinalV2AexMetadata({...base,attributes_flags:0x404},{...base,attributes_flags:0x404})).toThrow(/AEX_NOTIFY/);
  expect(()=>assertFinalV2AexMetadata({...base,attributes_flags:0x804},{...base,attributes_flags:0x4})).toThrow(/only by disabling AEX_NOTIFY/);
  expect(()=>assertFinalV2AexMetadata({...base,attributes_flags:0x404},{...base,attributes_flags:0x4,layout_entries:[{id:2,rva:0,pages:1}]})).toThrow(/layout differs/);
});
