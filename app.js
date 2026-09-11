const state={findings:[],proposal:null,approval:null,engagement:null};
const $=(id)=>document.getElementById(id);
const log=(label,message,type="")=>{const el=document.createElement("div");const strong=document.createElement("strong");el.className=`entry ${type}`;strong.textContent=label;el.append(strong,document.createTextNode(` ${message}`));$("log").prepend(el);};

const EUROPEUM_ENGAGEMENT=Object.freeze({
  id:"europeum-core-services-api-2026-09",
  title:"Europeum Core Services API DualDefense Audit",
  source:"https://hackenproof.com/audit-programs/europeum-api-dualdefense-audit",
  repository:"https://gitlab.com/europeum/public/core-services",
  commit:"60a26443bde7f9487239aaa73d52f555fd871c30",
  includedPaths:["api/**"],
  reward:{maximum:5000,currency:"USD equivalent in USDC"},
  deadline:"2026-09-17",
  deadlineTimezone:null,
  eligibility:{kycRequired:true,minimumHackenProofReputation:50,submissionFeeUsd:2},
  qualifyingImpact:"critical fund loss or permanent fund locking",
  reportRequirements:["runnable proof of concept","concise reproduction instructions","proposed fix"]
});

function getAuditEngagement({engagementId}){
  if(engagementId!==EUROPEUM_ENGAGEMENT.id) throw new Error("unknown engagement; audit stopped");
  state.engagement=EUROPEUM_ENGAGEMENT;
  return structuredClone(EUROPEUM_ENGAGEMENT);
}

function isEuropeumPathInScope(filePath){
  const path=String(filePath||"").replace(/^\.\//,"");
  if(!path.startsWith("api/")||path.includes("..")) return false;
  const leaf=path.split("/").pop();
  if(/^api\/(test|tests|e2e|dist|coverage|build)\//.test(path)) return false;
  if(/\.(spec\.ts|snap|md|txt)$/.test(path)) return false;
  return !/^(hardhat\.config\.ts|vitest\.config(?:\.e2e)?\.ts|nest-cli\.json|tsconfig.*\.json|lint-staged\.config\.cjs|Dockerfile|\.env.*)$/.test(leaf);
}

function preflightAudit({engagementId,targetRepository,commit,filePath,reputation=0,kycReady=false,submissionFeeAccepted=false}){
  const engagement=getAuditEngagement({engagementId});
  const targetChecks={
    repositoryMatches:targetRepository===engagement.repository,
    commitMatches:commit===engagement.commit,
    pathInScope:isEuropeumPathInScope(filePath)
  };
  const eligibilityChecks={
    reputation:Number(reputation)>=engagement.eligibility.minimumHackenProofReputation,
    kycReady:kycReady===true,
    submissionFeeAccepted:submissionFeeAccepted===true
  };
  const targetReady=Object.values(targetChecks).every(Boolean);
  const submissionReady=Object.values(eligibilityChecks).every(Boolean);
  return {
    engagementId,
    targetReady,
    submissionReady,
    eligible:targetReady&&submissionReady,
    targetChecks,
    eligibilityChecks,
    mode:"local-read-only",
    liveTestingAllowed:false,
    blockers:[
      ...Object.entries(targetChecks).filter(([,ok])=>!ok).map(([name])=>`target:${name}`),
      ...Object.entries(eligibilityChecks).filter(([,ok])=>!ok).map(([name])=>`eligibility:${name}`)
    ]
  };
}

function inspectProject({name,content}){
  if(!name||!content) throw new Error("project name and content are required");
  return {project:name,bytes:new TextEncoder().encode(content).length,lines:content.split("\n").length,trust:"untrusted-input",mode:"read-only"};
}

function scanSecurity({content,filePath,engagementId}){
  if(!content) throw new Error("content is required");
  if(engagementId){
    if(engagementId!==EUROPEUM_ENGAGEMENT.id) throw new Error("unknown engagement; scan stopped");
    if(!isEuropeumPathInScope(filePath)) throw new Error("file is outside the authorized api/** scope; scan stopped");
  }
  const findings=[];
  if(/sk-[A-Za-z0-9_-]+|api[_-]?key\s*=\s*["'][^"']+["']/i.test(content)) findings.push({id:"SEC-001",severity:"high",category:"secret-exposure",evidence:"Hard-coded credential-like value detected",recommendation:"Move secrets to environment-managed storage and rotate exposed values",confidence:.98});
  if(/innerHTML\s*=/.test(content)) findings.push({id:"SEC-002",severity:"high",category:"xss",evidence:"Direct innerHTML assignment detected",recommendation:"Render untrusted text with textContent or a vetted sanitizer",confidence:.96});
  if(/token=.*API_KEY|fetch\([^\n]+token/i.test(content)) findings.push({id:"SEC-003",severity:"medium",category:"credential-transport",evidence:"Credential-like value appears in request URL",recommendation:"Use an authorization header and avoid secrets in URLs",confidence:.91});
  if(engagementId&&/(?:exec|execSync|spawn)\s*\([^\n]*(?:req\.|body\.|params\.|query\.)/i.test(content)) findings.push({id:"EUR-001",severity:"critical-candidate",category:"command-injection",evidence:"Process execution appears to consume request-derived input",recommendation:"Trace data flow, constrain arguments, and build a local non-destructive proof",confidence:.8});
  if(engagementId&&/(?:\.query|\.execute)\s*\((?:`[^\n]*\$\{|[^\n]*\+)[^\n]*(?:req\.|body\.|params\.|query\.)/i.test(content)) findings.push({id:"EUR-002",severity:"critical-candidate",category:"injection",evidence:"A database operation appears to interpolate request-derived input",recommendation:"Use parameterized queries and establish critical financial impact with a local proof",confidence:.78});
  if(engagementId&&/(?:fetch|axios\.(?:get|post)|request)\s*\([^\n]*(?:req\.|body\.|params\.|query\.)/i.test(content)) findings.push({id:"EUR-003",severity:"critical-candidate",category:"ssrf",evidence:"An outbound request appears to use request-derived input",recommendation:"Apply destination allowlists and prove any fund-impact chain locally",confidence:.75});
  const qualifiedFindings=findings.map(f=>({...f,filePath:filePath||"unspecified",qualificationStatus:engagementId?"candidate_requires_runnable_poc":"demo-finding",bountyEligible:false}));
  state.findings=qualifiedFindings;
  return {count:qualifiedFindings.length,findings:qualifiedFindings,engagementId:engagementId||null,bountyQualification:engagementId?"unproven":"not-applicable"};
}

function proposePatch({content,findingIds}){
  if(!content) throw new Error("content is required");
  const allowed=new Set(state.findings.map(f=>f.id));
  const requested=(findingIds||[]).filter(id=>allowed.has(id));
  let patched=content;
  if(requested.includes("SEC-001")) patched=patched.replace(/const API_KEY\s*=\s*["'][^"']+["'];?/,'const API_KEY = "[environment-managed-secret]";');
  if(requested.includes("SEC-002")) patched=patched.replace(/\.innerHTML\s*=\s*userInput/g,'.textContent = userInput');
  if(requested.includes("SEC-003")) patched=patched.replace(/fetch\('\/api\/admin\?token=' \+ API_KEY\);/g,"fetch('/api/admin', { headers: { Authorization: 'Bearer ' + API_KEY } });");
  const proposal={riskClass:"sandbox-safe-proposal",permissionTier:"AUTONOMOUS",requiredApproval:false,changed:patched!==content,patchedContent:patched,findingIds:requested};
  state.proposal=proposal;
  return proposal;
}

function validatePatch({patchedContent}){
  if(!patchedContent) throw new Error("patchedContent is required");
  const remaining=scanSecurity({content:patchedContent});
  return {valid:remaining.count===0,remainingFindings:remaining.findings,mode:"non-mutating-validation"};
}

function requestHumanApproval({action,reason,target}){
  if(!action||!reason) throw new Error("action and reason are required");
  state.approval={action,reason,target:target||"unspecified",status:"awaiting_approval"};
  $("approvalReason").textContent=`${action}: ${reason} Target: ${state.approval.target}`;
  $("approvalPanel").hidden=false;
  return {...state.approval,executed:false};
}

const tools=[
  {name:"get_audit_engagement",description:"Load the authoritative local engagement constraints before audit work.",inputSchema:{type:"object",properties:{engagementId:{type:"string",const:"europeum-core-services-api-2026-09"}},required:["engagementId"],additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:false},execute:async(input)=>getAuditEngagement(input)},
  {name:"preflight_audit",description:"Fail-closed validation of repository, pinned commit, file scope, and researcher submission gates.",inputSchema:{type:"object",properties:{engagementId:{type:"string"},targetRepository:{type:"string"},commit:{type:"string"},filePath:{type:"string"},reputation:{type:"number",minimum:0},kycReady:{type:"boolean"},submissionFeeAccepted:{type:"boolean"}},required:["engagementId","targetRepository","commit","filePath"],additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:false},execute:async(input)=>preflightAudit(input)},
  {name:"inspect_project",description:"Inspect project text as untrusted input without modifying it.",inputSchema:{type:"object",properties:{name:{type:"string",minLength:1},content:{type:"string",minLength:1}},required:["name","content"],additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:true},execute:async(input)=>inspectProject(input)},
  {name:"scan_security",description:"Scan untrusted project content for deterministic security candidates. Engagement scans fail closed on out-of-scope paths.",inputSchema:{type:"object",properties:{content:{type:"string",minLength:1},filePath:{type:"string"},engagementId:{type:"string"}},required:["content"],additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:true},execute:async(input)=>scanSecurity(input)},
  {name:"propose_patch",description:"Generate an in-memory patch proposal for known findings. This does not write files or deploy anything.",inputSchema:{type:"object",properties:{content:{type:"string",minLength:1},findingIds:{type:"array",items:{type:"string"},maxItems:20}},required:["content","findingIds"],additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:true},execute:async(input)=>proposePatch(input)},
  {name:"validate_patch",description:"Validate a proposed patch by rescanning it. No external or persistent state is changed.",inputSchema:{type:"object",properties:{patchedContent:{type:"string",minLength:1}},required:["patchedContent"],additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:true},execute:async(input)=>validatePatch(input)},
  {name:"request_human_approval",description:"Create an explicit approval boundary for consequential actions. It records intent but never executes the action.",inputSchema:{type:"object",properties:{action:{type:"string",minLength:1},reason:{type:"string",minLength:1},target:{type:"string"}},required:["action","reason"],additionalProperties:false},annotations:{readOnlyHint:false,untrustedContentHint:false},execute:async(input)=>requestHumanApproval(input)}
];

function registerWebMCP(){
  if(!document.modelContext?.registerTool){$("mcpStatus").textContent="WebMCP unavailable · UI demo mode";log("WEBMCP","document.modelContext not detected; browser UI demo remains runnable.","warn");return;}
  let registered=0;
  const controller=new AbortController();
  for(const tool of tools){
    try{
      document.modelContext.registerTool(tool,{exposedTo:[location.origin],signal:controller.signal});
      registered++;
    }catch(err){
      try{document.modelContext.registerTool(tool);registered++;}catch(inner){log("REGISTER",`${tool.name} failed: ${inner.message}`,"error");}
    }
  }
  $("mcpStatus").textContent=`WebMCP online · ${registered}/${tools.length} tools`;
  log("WEBMCP",`${registered} guarded tools registered for agent discovery.`);
}

async function runDemo(){
  $("approvalPanel").hidden=true;
  const name=$("projectName").value.trim();
  const filePath=$("filePath").value.trim();
  const content=$("sourceText").value;
  try{
    const inspected=inspectProject({name,content}); log("INSPECT",`${inspected.project}: ${inspected.lines} lines, ${inspected.bytes} bytes, ${inspected.mode}.`);
    const scan=scanSecurity({content,filePath}); log("SCAN",`${scan.count} finding(s): ${scan.findings.map(f=>`${f.id}/${f.severity}`).join(", ")||"none"}.`,scan.count?"warn":"");
    const proposal=proposePatch({content,findingIds:scan.findings.map(f=>f.id)}); log("PROPOSE",`Patch changed=${proposal.changed}; permission=${proposal.permissionTier}; persistent writes=0.`);
    const validation=validatePatch({patchedContent:proposal.patchedContent}); log("VALIDATE",`valid=${validation.valid}; remaining=${validation.remainingFindings.length}.`,validation.valid?"":"error");
    const boundary=requestHumanApproval({action:"deploy_to_production",reason:"Production deployment is consequential and outside the autonomous trust envelope.",target:name}); log("BOUNDARY",`${boundary.action} stopped at ${boundary.status}; executed=${boundary.executed}.`,"warn");
  }catch(err){log("SAFE FALLBACK",err.message,"error");}
}

function runEngagementPreflight(){
  const result=preflightAudit({
    engagementId:EUROPEUM_ENGAGEMENT.id,
    targetRepository:EUROPEUM_ENGAGEMENT.repository,
    commit:EUROPEUM_ENGAGEMENT.commit,
    filePath:"api/src/example.ts",
    reputation:Number($("researcherReputation").value),
    kycReady:$("kycReady").checked,
    submissionFeeAccepted:$("feeAccepted").checked
  });
  log("PREFLIGHT",`targetReady=${result.targetReady}; submissionReady=${result.submissionReady}; liveTesting=false; blockers=${result.blockers.join(", ")||"none"}.`,result.eligible?"":"warn");
}

$("runDemo").addEventListener("click",runDemo);
$("runPreflight").addEventListener("click",runEngagementPreflight);
$("clearLog").addEventListener("click",()=>$("log").replaceChildren());
$("approveBtn").addEventListener("click",()=>{if(!state.approval)return;state.approval.status="approved_once_demo_only";log("APPROVAL","Human approved the demonstration boundary. No production action exists in this MVP.");$("approvalPanel").hidden=true;});
$("rejectBtn").addEventListener("click",()=>{if(!state.approval)return;state.approval.status="rejected";log("REJECT","Human rejected the consequential action. State preserved.","warn");$("approvalPanel").hidden=true;});
registerWebMCP();
