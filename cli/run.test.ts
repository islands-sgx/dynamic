import { expect, test } from "bun:test";
import { finalV2S3Verdict, parseRunCliArgs, summarizeTraceEcalls } from "./run.ts";

test("CLI selects the frozen Final v2 target explicitly",()=>{
  expect(parseRunCliArgs(["--bundle","profile.json","--final-v2-target","frozen-target.json","--gate-mode","c-preserve-tlb","--mode","verify-pretouch"])).toMatchObject({
    bundlePath:"profile.json",finalV2TargetPath:"frozen-target.json",gateMode:"c-preserve-tlb",mode:"verify-pretouch",
  });
});
test("Final v2 acceptance uses raw S3_BODY emptiness and never subtracts S2",()=>{
  expect(finalV2S3Verdict("final-v2","complete",0,1)).toBe("PASS");
  expect(finalV2S3Verdict("final-v2","complete",1,1)).toBe("FAIL");
  expect(finalV2S3Verdict("final-v2","complete",0,0)).toBe("FAIL");
  expect(finalV2S3Verdict("final-v2","incomplete",0,1)).toBe("INCOMPLETE");
  expect(finalV2S3Verdict("profile","complete",5,0)).toBe("NOT_APPLICABLE");
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
