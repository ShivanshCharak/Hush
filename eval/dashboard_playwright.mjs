#!/usr/bin/env node
// Synthetic 50k-row dashboard performance check; no dataset file is modified.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";

const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const require=createRequire(path.join(ROOT,"dashboard/web/package.json"));
const {chromium}=require("playwright");
const rows=Array.from({length:50_000},(_,i)=>{
  const id=i+1;
  return {event_id:id,timestamp:new Date(Date.UTC(2026,9,21,12,0,0)+id*1000).toISOString(),severity:id%17===0?"error":id%5===0?"warning":"info",
    src_ip:`203.0.113.${id%250+1}`,method:id%2?"GET":"POST",path:id%100===0?"/search":"/api/item",status:id%17===0?500:id%5===0?404:200,
    username:`user-${id%1000}`,user_agent:"Mozilla/5.0 synthetic dev perf fixture",raw:{fixture:"dev-derived-synthetic"},verdict:id===42000?{speak:true,kind:"sqli",gate_reason:"emitted",confidence:.99}:null};
});
let filterFixtureServerMs=null;
const alert={alert_id:"synthetic-dev-alert",event_start:42000,event_end:42019,kind:"sqli",confidence:.99,evidence_ids:[42000,42005],gate_reason:"emitted",explanation:{summary:"Synthetic SQLi test alert",suggested_action:"Inspect the cited dev fixture rows."}};
const histogram={buckets:Array.from({length:120},(_,i)=>({index:i,t:Date.UTC(2026,9,21,12,0)+i*1000,info:3,warning:1,error:1,alert_marker:i===42?1:null,alert_event_start:i===42?42000:null})),alerts:[{alert_id:alert.alert_id,event_start:alert.event_start,kind:alert.kind,t:Date.UTC(2026,9,21,12,42)}],spike_bands:[]};
const browser=await chromium.launch({headless:false,executablePath:process.env.CHROME_BIN||"/usr/bin/google-chrome",args:["--no-sandbox","--disable-dev-shm-usage","--enable-gpu","--ignore-gpu-blocklist","--enable-webgl"]});
const page=await browser.newPage({viewport:{width:1440,height:1000},deviceScaleFactor:1});
await page.addInitScript(()=>{
  window.__longTasks=[];
  try { new PerformanceObserver(list=>window.__longTasks.push(...list.getEntries().map(e=>({startTime:e.startTime,duration:e.duration})))).observe({type:"longtask",buffered:true}); } catch {}
});
await page.route("**/api/**",async route=>{
  const url=new URL(route.request().url());
  if(url.pathname==="/api/meta") return route.fulfill({json:{event_count:rows.length,source_dataset:null,tail_enabled:false}});
  if(url.pathname==="/api/events" && /^\/api\/events\/\d+$/.test(url.pathname)===false){
    const started=performance.now();
    const filter=url.searchParams.getAll("filter").join(" ");
    const selected=filter.includes("kind=sqli")?rows.slice(41999,42019).reverse():rows.slice().reverse();
    await route.fulfill({json:{rows:selected,next_after_id:null,count:selected.length}});
    if(filter.includes("kind=sqli")) filterFixtureServerMs=performance.now()-started;
    return;
  }
  if(url.pathname==="/api/events/42000") return route.fulfill({json:{event:rows[41999],context:rows.slice(41990,42010)}});
  if(url.pathname==="/api/alerts") return route.fulfill({json:[alert]});
  if(url.pathname==="/api/histogram") return route.fulfill({json:histogram});
  return route.fulfill({status:404,json:{error:"unmocked"}});
});
const navigationStart=Date.now();
await page.goto(process.env.DASHBOARD_URL||"http://127.0.0.1:3000/",{waitUntil:"domcontentloaded"});
await page.getByRole("heading",{name:"Event stream"}).waitFor();
await page.waitForLoadState("networkidle");
await page.waitForTimeout(5100);
const initial=await page.evaluate(()=>{
  const nav=performance.getEntriesByType("navigation")[0];
  const fcp=performance.getEntriesByName("first-contentful-paint")[0]?.startTime??null;
  const tasks=window.__longTasks||[];
  const lastLongTaskEnd=tasks.length?Math.max(...tasks.map(task=>task.startTime+task.duration)):0;
  return {domInteractiveMs:nav?.domInteractive??null,domContentLoadedMs:nav?.domContentLoadedEventEnd??null,loadEventEndMs:nav?.loadEventEnd??null,
    firstContentfulPaintMs:fcp,longTaskCount:tasks.length,lastLongTaskEndMs:lastLongTaskEnd,
    quietWindowTtiProxyMs:Math.max(nav?.loadEventEnd??0,lastLongTaskEnd)+5000};
});
const gpu=await page.evaluate(()=>{const canvas=document.createElement("canvas");const gl=canvas.getContext("webgl2")||canvas.getContext("webgl");if(!gl)return {webgl:false,vendor:null,renderer:null};const ext=gl.getExtension("WEBGL_debug_renderer_info");return {webgl:true,vendor:ext?gl.getParameter(ext.UNMASKED_VENDOR_WEBGL):gl.getParameter(gl.VENDOR),renderer:ext?gl.getParameter(ext.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER)}});
const completenessText=await page.locator("section").filter({has:page.getByRole("heading",{name:"Event stream"})}).innerText();
const initialMountedRows=await page.locator("tbody tr").count();
const scrollHandle=await page.locator("tbody").evaluateHandle(el=>el.parentElement?.parentElement);
const frameSamples=await page.evaluate(async el=>new Promise(resolve=>{
  const samples=[];const start=performance.now();const max=Math.max(1,el.scrollHeight-el.clientHeight);el.scrollTop=0;
  function frame(now){samples.push(now);const progress=Math.min((now-start)/2500,1);el.scrollTop=max*progress;if(progress<1)requestAnimationFrame(frame);else resolve(samples);}
  requestAnimationFrame(frame);
}),scrollHandle);
const intervals=frameSamples.slice(1).map((now,i)=>now-frameSamples[i]);
const avgFps=intervals.length?1000/(intervals.reduce((a,b)=>a+b,0)/intervals.length):null;
const sortedIntervals=[...intervals].sort((a,b)=>a-b);
const p95FrameMs=sortedIntervals.length?sortedIntervals[Math.min(sortedIntervals.length-1,Math.ceil(sortedIntervals.length*.95)-1)]:null;
const finalMountedRows=await page.locator("tbody tr").count();
await page.evaluate(()=>{performance.clearMarks("dashboard:filter-handler-start");performance.clearMarks("dashboard:filter-handler-end");performance.clearMarks("dashboard:filter-render-complete")});
const filterStarted=Date.now();
await page.getByRole("textbox",{name:"Filter events"}).fill("kind=sqli");
await page.getByRole("button",{name:"Add filter"}).click();
await page.waitForFunction(()=>[...document.querySelectorAll("section")].some(el=>el.textContent?.includes("20 events loaded · newest first")),null,{polling:"raf"});
const filterRepaintMs=Date.now()-filterStarted;
const filterClientRepaintMs=filterFixtureServerMs===null?null:Math.max(0,filterRepaintMs-filterFixtureServerMs);
const filterProfile=await page.evaluate(()=>{
  const marks=name=>performance.getEntriesByName(name,"mark").map(x=>x.startTime);
  const handlerStart=marks("dashboard:filter-handler-start").at(-1);
  const handlerEnd=marks("dashboard:filter-handler-end").at(-1);
  const rendered=marks("dashboard:filter-render-complete").at(-1);
  const requests=performance.getEntriesByType("resource").filter(x=>x.startTime>=((handlerStart??Infinity)-2)&&/\/api\/(events|histogram)(\?|$)/.test(x.name));
  const networkStart=requests.length?Math.min(...requests.map(x=>x.startTime)):null;
  const networkEnd=requests.length?Math.max(...requests.map(x=>x.responseEnd||x.startTime+x.duration)):null;
  return {handler_ms:handlerStart===undefined||handlerEnd===undefined?null:handlerEnd-handlerStart,
    scheduling_ms:networkStart===null||handlerEnd===undefined?null:Math.max(0,networkStart-handlerEnd),
    network_ms:networkStart===null?null:networkEnd-networkStart,
    render_ms:rendered===undefined||networkEnd===null?null:Math.max(0,rendered-networkEnd),
    click_to_results_ms:handlerStart===undefined||rendered===undefined?null:rendered-handlerStart,
    api_requests:requests.map(x=>new URL(x.name).pathname+new URL(x.name).search)};
});
const alertCard=page.getByRole("button").filter({hasText:"EVENTS 42000–42019"});
await alertCard.waitFor();
await alertCard.click();
await page.getByText("Event detail").waitFor();
const selectedRow=page.locator('tbody tr[data-event-id="42000"]');
await selectedRow.waitFor({state:"visible",timeout:5000}).catch(()=>{});
const selectedEvidenceRowPresent=await selectedRow.count()>0;
const linkage={detailVisible:await page.getByText("Event detail").isVisible(),selectedEvidenceRowPresent,
  selectedEvidenceRowHighlighted:selectedEvidenceRowPresent&&(await selectedRow.getAttribute("aria-selected"))==="true"};
const metadata=JSON.parse(execFileSync(path.join(ROOT,"venv/bin/python"),["-c","from eval.run_metadata import snapshot; import json; print(json.dumps(snapshot()))"],{cwd:ROOT,encoding:"utf8"}));
const report={created_at:new Date().toISOString(),scope:"synthetic dev-derived 50,000-row browser fixture; no locked/held-out data",browser:{name:"Google Chrome",headless:false,gpu_enabled:true,gpu},row_count:rows.length,
  table_completeness:{requested_rows:rows.length,visible_loaded_count:/50,000 events loaded/.test(completenessText),initial_virtual_rows:initialMountedRows,post_scroll_virtual_rows:finalMountedRows},
  tti:{method:"Playwright navigation timings plus 5-second quiet-window proxy after network idle",...initial,wall_to_network_idle_and_quiet_ms:Date.now()-navigationStart},
  scroll:{duration_ms:2500,average_fps:avgFps,p95_frame_interval_ms:p95FrameMs,frames:frameSamples.length,dom_rows_after_scroll:finalMountedRows},
  filter:{filter:"kind=sqli",matching_rows:20,total_repaint_ms:filterRepaintMs,handler_network_render:filterProfile,fixture_server_ms:filterFixtureServerMs,click_to_results_minus_fixture_handler_ms:filterClientRepaintMs,server_note:"Playwright intercept fixture handler; API count and browser resource timings are reported separately"},alert_card_linkage:linkage,config_snapshot:metadata};
const stamp=new Date().toISOString().replace(/[-:]/g,"").replace(/\.\d{3}Z$/, "Z");
const out=path.join(ROOT,"eval/runs",`dashboard-playwright-${stamp}.json`);
fs.writeFileSync(out,JSON.stringify(report,null,2)+"\n");
console.log(JSON.stringify({artifact:path.relative(ROOT,out),browser:report.browser,table_completeness:report.table_completeness,scroll:report.scroll,filter:report.filter,alert_card_linkage:linkage},null,2));
await browser.close();
