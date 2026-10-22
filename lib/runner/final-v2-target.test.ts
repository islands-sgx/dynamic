import { expect, test } from "bun:test";
import type { ProfileBundle } from "../bundle/profile-bundle.ts";
import { assertFinalV2BundleIdentity, assertWorksetDigestBound } from "./final-v2-target.ts";
import { sha256 } from "../bundle/profile-bundle.ts";

const profileSha="11".repeat(32);
const signedProfileSha="22".repeat(32);
const bundle={manifestSha256:"33".repeat(32),layoutEpoch:"44".repeat(32),capacityQ:0x8000} as unknown as ProfileBundle;
const identity={profile_bundle_manifest_sha256:bundle.manifestSha256,layout_epoch:bundle.layoutEpoch,workset_schema:"atfield-workset-v2",capacity_q:bundle.capacityQ};
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
