#!/usr/bin/env node
// Headed browser filter timing through Next's proxy to the dev-only FastAPI/DuckDB service.
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
const apiRequests=[];
page.on("request",request=>{if(/\/api\/(events|histogram|alerts)(\?|$)/.test(request.url()))apiRequests.push({url:request.url(),started:Date.now()})});
await page.goto(process.env.DASHBOARD_URL||"http://127.0.0.1:3001/",{waitUntil:"domcontentloaded"});
await page.getByRole("heading",{name:"Event stream"}).waitFor();
await page.waitForLoadState("networkidle");
const before=await page.locator("tbody tr").count();
await page.evaluate(()=>{performance.clearMarks("dashboard:filter-handler-start");performance.clearMarks("dashboard:filter-handler-end");performance.clearMarks("dashboard:filter-render-complete")});
const filterResponses=[
  page.waitForResponse(r=>r.url().includes("/api/events?")&&r.url().includes("filter=kind%3Dsqli")),
  page.waitForResponse(r=>r.url().includes("/api/histogram?")&&r.url().includes("filter=kind%3Dsqli")),
];
await page.getByRole("textbox",{name:"Filter events"}).fill("kind=sqli");
const clickStart=Date.now();
await page.getByRole("button",{name:"Add filter"}).click();
const [eventResponse,histResponse]=await Promise.all(filterResponses);
await page.waitForFunction(()=>performance.getEntriesByName("dashboard:filter-render-complete","mark").length>0);
const wallMs=Date.now()-clickStart;
const profile=await page.evaluate(()=>{
  const marks=name=>performance.getEntriesByName(name,"mark").map(entry=>entry.startTime);
  const hs=marks("dashboard:filter-handler-start").at(-1),he=marks("dashboard:filter-handler-end").at(-1),rendered=marks("dashboard:filter-render-complete").at(-1);
  const resources=performance.getEntriesByType("resource").filter(e=>e.startTime>=(hs??Infinity)-2&&/\/api\/(events|histogram)(\?|$)/.test(e.name));
  const start=resources.length?Math.min(...resources.map(e=>e.startTime)):null,end=resources.length?Math.max(...resources.map(e=>e.responseEnd)):null;
  const navs=performance.getEntriesByType("navigation");
  return {handler_ms:hs==null||he==null?null:he-hs,scheduling_ms:start==null||he==null?null:Math.max(0,start-he),network_ms:start==null?null:end-start,render_ms:rendered==null||end==null?null:Math.max(0,rendered-end),click_handler_to_render_ms:hs==null||rendered==null?null:rendered-hs,navigation_entry_count:navs.length,resource_urls:resources.map(e=>new URL(e.name).pathname+new URL(e.name).search)};
});
const after=await page.locator("tbody tr").count();
const requests=apiRequests.slice(-2).map(({url})=>new URL(url).pathname+new URL(url).search);
const metaResponse=await page.evaluate(async()=>{const response=await fetch("/api/meta");return response.json()});
const metadata=JSON.parse(execFileSync(path.join(ROOT,"venv/bin/python"),["-c","from eval.run_metadata import snapshot; import json; print(json.dumps(snapshot()))"],{cwd:ROOT,encoding:"utf8"}));
const report={created_at:new Date().toISOString(),scope:"real local FastAPI/DuckDB API populated from dev stream 01 only; no locked/held-out data",browser:{name:"Google Chrome",headless:false,gpu_enabled:true},api_meta:metaResponse,filter:"kind=sqli",debounce_in_filter_code:false,click_to_results_wall_ms:wallMs,filter_split:profile,rows_before_filter:before,rows_after_filter:after,event_http_status:eventResponse.status(),histogram_http_status:histResponse.status(),api_requests:requests,alerts_requested_by_filter:false,config_snapshot:metadata};
const stamp=new Date().toISOString().replace(/[-:]/g,"").replace(/\.\d{3}Z$/, "Z");
const out=path.join(ROOT,"eval/runs",`dashboard-real-api-filter-${stamp}.json`);
fs.writeFileSync(out,JSON.stringify(report,null,2)+"\n");
console.log(JSON.stringify({artifact:path.relative(ROOT,out),api_meta:metaResponse,click_to_results_wall_ms:wallMs,filter_split:profile,rows_before_filter:before,rows_after_filter:after,api_requests:requests},null,2));
await browser.close();
