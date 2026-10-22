import { expect, test } from "bun:test";
import type { ProfileBundle } from "../bundle/profile-bundle.ts";
import { validateSelectedEnclaveSha256 } from "./trace.ts";

const profile="11".repeat(32);
const signedProfile="22".repeat(32);
const finalMeasurement="33".repeat(32);
const bundle={identity:{profileElfSha256:profile,signedProfileElfSha256:signedProfile}} as unknown as ProfileBundle;
test("a Final measurement hash is accepted only when its frozen identity is explicit",()=>{
  expect(validateSelectedEnclaveSha256(signedProfile,bundle)).toBe(signedProfile);
  expect(()=>validateSelectedEnclaveSha256(finalMeasurement,bundle)).toThrow(/Profile bundle/);
  expect(validateSelectedEnclaveSha256(finalMeasurement,bundle,finalMeasurement)).toBe(finalMeasurement);
  expect(()=>validateSelectedEnclaveSha256(signedProfile,bundle,finalMeasurement)).toThrow(/frozen run target/);
});
