import { expect, test } from "bun:test";
import { finalV2S3Verdict, parseRunCliArgs, summarizeTraceEcalls } from "./run.ts";

test("CLI selects the frozen Final v2 target explicitly",()=>{
  expect(parseRunCliArgs(["--bundle","profile.json","--final-v2-target","frozen-target.json","--gate-mode","c-preserve-tlb","--mode","verify-pretouch"])).toMatchObject({
    bundlePath:"profile.json",finalV2TargetPath:"frozen-target.json",gateMode:"c-preserve-tlb",mode:"verify-pretouch",
  });
});
test("Final v2 acceptance uses raw S3_BODY emptiness and never subtracts S2",()=>{
  expect(finalV2S3Verdict("final-v2","complete",0,1,0)).toBe("PASS");
  expect(finalV2S3Verdict("final-v2","complete",1,1,0)).toBe("FAIL");
  expect(finalV2S3Verdict("final-v2","complete",0,0,0)).toBe("FAIL");
  expect(finalV2S3Verdict("final-v2","complete",0,1,1)).toBe("FAIL");
  expect(finalV2S3Verdict("final-v2","incomplete",0,1,0)).toBe("INCOMPLETE");
  expect(finalV2S3Verdict("profile","complete",5,0,1)).toBe("NOT_APPLICABLE");
});

test("Final call summaries aggregate clean empty S3 calls and retain only anomalous details",()=>{
  const phase=(page_effects:unknown[])=>({page_size:4096,complete:true,page_effects});
  const clean={record_type:"ecall",call_seq:0,measurement_valid:true,measurement_invalid_reasons:[],readiness_installed:true,sgx_status:0,abi_return_value:0,out_status_i32:0,fields:[{field_id:"f1",phases:{S2_PRETOUCH:phase([{rva:"0x1000",a:true,d:false}]),S3_BODY:phase([])}}],aex:{unexpected_count:0,outside_window_count:0}};
  const bad={...clean,call_seq:1,fields:[{field_id:"f1",phases:{S2_PRETOUCH:phase([]),S3_BODY:phase([{rva:"0x1000",a:true,d:false}])}}]};
  const result=summarizeTraceEcalls([JSON.stringify(clean),JSON.stringify(bad)].join("\n"));
  expect(result.total_ecalls).toBe(2);
  expect(result.valid_empty_s3_ecalls).toBe(1);
  expect(result.abnormal_ecalls).toHaveLength(1);
  expect(result.abnormal_ecalls[0]).toMatchObject({call_seq:1,fields:[{field_id:"f1",s2:{page_size:4096,complete:true,page_effects:[]},s3:{page_size:4096,complete:true,page_effects:[{rva:"0x1000",a:true,d:false}]}}]});
});


test("Final v2 gate rejects SGX, measurement, readiness, and AEX failures but leaves business results diagnostic",()=>{
  const phase=(page_effects:unknown[])=>({page_size:4096,complete:true,page_effects});
  const clean={record_type:"ecall",call_seq:0,measurement_valid:true,measurement_invalid_reasons:[],readiness_installed:true,sgx_status:0,abi_return_value:0,out_status_i32:0,fields:[{field_id:"f1",phases:{S3_BODY:phase([])}}],aex:{unexpected_count:0,outside_window_count:0}};
  const businessResult={...clean,abi_return_value:7,out_status_i32:-2,business_result:{status:1,value:"rejected"}};
  const cleanSummary=summarizeTraceEcalls(JSON.stringify(businessResult));
  expect(cleanSummary.final_v2_verification_failures).toHaveLength(0);
  expect(cleanSummary.abnormal_ecalls).toHaveLength(1);
  expect(cleanSummary.nonzero_business_result_ecalls).toBe(1);
  expect(finalV2S3Verdict("final-v2","complete",0,1,cleanSummary.final_v2_verification_failures.length)).toBe("PASS");

  const failed={...clean,sgx_status:1,measurement_valid:false,readiness_installed:false,aex:{unexpected_count:1,outside_window_count:1}};
  const failedSummary=summarizeTraceEcalls(JSON.stringify(failed));
  expect(failedSummary.final_v2_verification_failures).toHaveLength(1);
  expect(failedSummary.final_v2_verification_failures[0]).toMatchObject({
    call_seq:0,
    reasons:["nonzero SGX transport status","invalid measurement","readiness not installed","missing or unexpected AEX classification"],
  });
  expect(finalV2S3Verdict("final-v2","complete",0,1,failedSummary.final_v2_verification_failures.length)).toBe("FAIL");
});
