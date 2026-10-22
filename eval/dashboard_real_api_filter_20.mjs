#!/usr/bin/env node
// Headed, real-API filter latency profile: 20 distinct source-IP filter clicks, no scrolling.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";

const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const require=createRequire(path.join(ROOT,"dashboard/web/package.json"));
const {chromium}=require("playwright");
const browser=await chromium.launch({headless:false,executablePath:process.env.CHROME_BIN||"/usr/bin/google-chrome",args:["--no-sandbox","--disable-dev-shm-usage","--enable-gpu","--ignore-gpu-blocklist","--enable-webgl"]});
const page=await browser.newPage({viewport:{width:1440,height:1000},deviceScaleFactor:1});
const requestLog=[];
page.on("request",request=>{if(/\/api\/(events|histogram|alerts)(\?|$)/.test(request.url()))requestLog.push(new URL(request.url()).pathname+new URL(request.url()).search)});
const percentile=(values,p)=>{const sorted=[...values].sort((a,b)=>a-b);return sorted[Math.max(0,Math.ceil(p*sorted.length)-1)]};
const sourceIps=["198.51.100.26","198.51.100.75","198.51.100.38","198.51.100.138","198.51.100.220","198.51.100.20","198.51.100.85","198.51.100.207","198.51.100.120","198.51.100.60","198.51.100.12","198.51.100.205","198.51.100.30","198.51.100.126","198.51.100.215","198.51.100.70","198.51.100.108","198.51.100.139","198.51.100.124","198.51.100.166"];
const filterBox=page.getByRole("textbox",{name:"Filter events"});
const applyButton=page.getByRole("button",{name:"Add filter"});
const samples=[];
try {
  await page.goto(process.env.DASHBOARD_URL||"http://127.0.0.1:3001/",{waitUntil:"domcontentloaded"});
  await page.getByRole("heading",{name:"Event stream"}).waitFor();
  await page.waitForLoadState("networkidle");
  const before=await page.locator("tbody tr").count();
  const initialApiRequestCount=requestLog.length;
  for(let i=0;i<20;i++){
    const filter=`src_ip=${sourceIps[i]}`;
    console.log(`filter click ${i+1}/20: ${filter}`);
    await filterBox.fill("");
    await filterBox.fill(filter);
    await page.evaluate(()=>{
      for(const name of ["dashboard:filter-handler-start","dashboard:filter-handler-end","dashboard:filter-render-complete"])performance.clearMarks(name);
    });
    const matches=url=>new URL(url).searchParams.getAll("filter").includes(filter);
    const responses=[
      page.waitForResponse(r=>r.url().includes("/api/events?")&&matches(r.url())),
      page.waitForResponse(r=>r.url().includes("/api/histogram?")&&matches(r.url())),
    ];
    const clickStart=Date.now();
    await applyButton.click();
    const [eventResponse,histResponse]=await Promise.all(responses);
    await page.waitForFunction(()=>performance.getEntriesByName("dashboard:filter-render-complete","mark").length>0);
    const wallMs=Date.now()-clickStart;
    const profile=await page.evaluate(()=>{
      const marks=name=>performance.getEntriesByName(name,"mark").map(entry=>entry.startTime);
      const hs=marks("dashboard:filter-handler-start").at(-1),he=marks("dashboard:filter-handler-end").at(-1),rendered=marks("dashboard:filter-render-complete").at(-1);
      const resources=performance.getEntriesByType("resource").filter(e=>e.startTime>=(hs??Infinity)-2&&/\/api\/(events|histogram)(\?|$)/.test(e.name));
      const start=resources.length?Math.min(...resources.map(e=>e.startTime)):null,end=resources.length?Math.max(...resources.map(e=>e.responseEnd)):null;
      return {handler_ms:hs==null||he==null?null:he-hs,scheduling_ms:start==null||he==null?null:Math.max(0,start-he),network_ms:start==null?null:end-start,render_ms:rendered==null||end==null?null:Math.max(0,rendered-end),handler_to_render_ms:hs==null||rendered==null?null:rendered-hs,resources:resources.map(e=>new URL(e.name).pathname+new URL(e.name).search)};
    });
    samples.push({click:i+1,filter,wall_ms:wallMs,...profile,event_http_status:eventResponse.status(),histogram_http_status:histResponse.status()});
    // Clear between samples so each click starts from the same unfiltered state.
    await page.getByRole("button",{name:"Clear filters"}).click();
    await page.waitForLoadState("networkidle");
  }
  const after=await page.locator("tbody tr").count();
  const apiMeta=await page.evaluate(async()=>{const response=await fetch("/api/meta");return response.json()});
  const metadata=JSON.parse(execFileSync(path.join(ROOT,"venv/bin/python"),["-c","from eval.run_metadata import snapshot; import json; print(json.dumps(snapshot()))"],{cwd:ROOT,encoding:"utf8"}));
  const wall=samples.map(s=>s.wall_ms),handler=samples.map(s=>s.handler_to_render_ms);
  const profileApiRequests=samples.flatMap(sample=>sample.resources);
  const report={created_at:new Date().toISOString(),scope:"real local FastAPI/DuckDB API populated from dev stream 01 only; 20 distinct source-IP filter clicks; no scrolling; no locked/held-out data",browser:{name:"Google Chrome",headless:false,gpu_enabled:true},api_meta:apiMeta,filter_click_count:samples.length,latency_definition:{handler_to_render:"dashboard:filter-handler-start mark through dashboard:filter-render-complete mark",wall:"click action start through both filtered responses and render-complete"},percentile_method:"nearest-rank; p50=ceil(0.50*n), p95=ceil(0.95*n)",handler_to_render_ms:{p50:percentile(handler,.50),p95:percentile(handler,.95)},wall_ms:{p50:percentile(wall,.50),p95:percentile(wall,.95)},rows_before_filter:before,rows_after_filter:after,initial_page_api_requests:requestLog.slice(0,initialApiRequestCount),filter_profile_api_requests:profileApiRequests,alerts_requested_by_filter:profileApiRequests.some(url=>url.includes("/api/alerts")),api_requests:requestLog,clicks:samples,config_snapshot:metadata};
  const stamp=new Date().toISOString().replace(/[-:]/g,"").replace(/\.\d{3}Z$/, "Z");
  const out=path.join(ROOT,"eval/runs",`dashboard-real-api-filter-20-${stamp}.json`);
  fs.writeFileSync(out,JSON.stringify(report,null,2)+"\n");
  console.log(JSON.stringify({artifact:path.relative(ROOT,out),api_meta:apiMeta,filter_click_count:samples.length,handler_to_render_ms:report.handler_to_render_ms,wall_ms:report.wall_ms,rows_before_filter:before,rows_after_filter:after,alerts_requested_by_filter:report.alerts_requested_by_filter},null,2));
} finally {
  await browser.close();
}
