import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const appSource=await readFile(new URL("../app.js",import.meta.url),"utf8");
const element=()=>({
  value:"",
  checked:false,
  hidden:false,
  className:"",
  textContent:"",
  addEventListener(){},
  append(){},
  prepend(){},
  replaceChildren(){}
});
const elements=new Map();
const document={
  createElement:element,
  createTextNode:(text)=>({textContent:text}),
  getElementById:(id)=>{
    if(!elements.has(id)) elements.set(id,element());
    return elements.get(id);
  }
};
const context=vm.createContext({document,location:{origin:"http://localhost"},AbortController,TextEncoder,structuredClone});
vm.runInContext(appSource,context);

test("loads the pinned engagement",()=>{
  const profile=context.getAuditEngagement({engagementId:"europeum-core-services-api-2026-09"});
  assert.equal(profile.commit,"60a26443bde7f9487239aaa73d52f555fd871c30");
  assert.equal(profile.reward.maximum,5000);
});

test("scope allows API source and rejects excluded paths",()=>{
  assert.equal(context.isEuropeumPathInScope("api/src/payments/service.ts"),true);
  assert.equal(context.isEuropeumPathInScope("api/tests/payments.spec.ts"),false);
  assert.equal(context.isEuropeumPathInScope("api/src/payments/service.spec.ts"),false);
  assert.equal(context.isEuropeumPathInScope("contracts/Treasury.sol"),false);
  assert.equal(context.isEuropeumPathInScope("../api/src/service.ts"),false);
});

test("preflight requires exact target and researcher gates",()=>{
  const base={
    engagementId:"europeum-core-services-api-2026-09",
    targetRepository:"https://gitlab.com/europeum/public/core-services",
    commit:"60a26443bde7f9487239aaa73d52f555fd871c30",
    filePath:"api/src/payments/service.ts",
    reputation:50,
    kycReady:true,
    submissionFeeAccepted:true
  };
  assert.equal(context.preflightAudit(base).eligible,true);
  assert.equal(context.preflightAudit({...base,commit:"wrong"}).targetReady,false);
  assert.equal(context.preflightAudit({...base,reputation:49}).submissionReady,false);
});

test("engagement scan fails closed outside scope",()=>{
  assert.throws(
    ()=>context.scanSecurity({content:"const ok = true",filePath:"contracts/Treasury.sol",engagementId:"europeum-core-services-api-2026-09"}),
    /outside the authorized/
  );
});

test("engagement heuristic remains an unproven candidate",()=>{
  const result=context.scanSecurity({
    content:"exec(req.body.command)",
    filePath:"api/src/jobs/runner.ts",
    engagementId:"europeum-core-services-api-2026-09"
  });
  assert.equal(result.count,1);
  assert.equal(result.findings[0].category,"command-injection");
  assert.equal(result.findings[0].qualificationStatus,"candidate_requires_runnable_poc");
  assert.equal(result.findings[0].bountyEligible,false);
  assert.equal(result.bountyQualification,"unproven");
});
