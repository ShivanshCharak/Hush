"use client";

import { useMemo } from "react";
import { CartesianGrid, ComposedChart, Line, ReferenceArea, ResponsiveContainer, Scatter, Tooltip, XAxis, YAxis } from "recharts";

type Histogram = { buckets:{index:number;t:number;info:number;warning:number;error:number;alert_marker:number|null;alert_event_start:number|null}[]; alerts:{alert_id:string;event_start:number;kind:string;t:number}[]; spike_bands:{from:number;to:number}[] };

export default function EventHistogram({ data, onAlert, episodes, rolling }: {
  data:Histogram|undefined;
  onAlert:(id:number)=>void;
  episodes:{start_idx:number;end_idx:number;kind:string;hard_benign?:boolean}[];
  rolling:boolean;
}) {
  const rows=useMemo(()=>data?.buckets.map(b=>({...b,label:new Date(b.t).toLocaleTimeString([], {minute:"2-digit",second:"2-digit"}),total:b.info+b.warning+b.error}))||[],[data]);
  return <section className="rounded-xl border border-line bg-panel p-4 shadow-panel">
    <div className="mb-3 flex items-center justify-between"><div><h2 className="text-sm font-semibold">Request volume</h2><p className="mt-1 text-xs text-muted">{rolling?"Rolling last 3 minutes · newest events at right":"Severity counts across the selected range"}</p></div><div className="flex gap-3 text-[11px] text-muted"><span><i className="mr-1.5 inline-block h-2 w-2 rounded-full bg-white"/>Info</span><span><i className="mr-1.5 inline-block h-2 w-2 rounded-full bg-neutral-400"/>Warning</span><span><i className="mr-1.5 inline-block h-2 w-2 rounded-full bg-neutral-600"/>Error</span></div></div>
    <div className="h-40 w-full">{rows.length?<ResponsiveContainer><ComposedChart data={rows} onClick={state=>{if(state?.activePayload?.[0]?.payload?.alert_event_start)onAlert(state.activePayload[0].payload.alert_event_start)}}><CartesianGrid vertical={false} stroke="#292929"/><XAxis dataKey="label" tick={{fill:"#8a8a8a",fontSize:10}} axisLine={false} tickLine={false} minTickGap={38}/><YAxis width={28} tick={{fill:"#8a8a8a",fontSize:10}} axisLine={false} tickLine={false}/><Tooltip contentStyle={{background:"#111111",border:"1px solid #404040",borderRadius:9,fontSize:12}}/>{data?.spike_bands.map(b=><ReferenceArea key={b.from} x1={rows[b.from]?.label} x2={rows[b.to]?.label} fill="#ffffff" fillOpacity={0.08} strokeOpacity={0}/>)}<Line type="monotone" dataKey="info" stroke="#f5f5f5" strokeWidth={2} dot={false} activeDot={{r:3}} isAnimationActive={false}/><Line type="monotone" dataKey="warning" stroke="#a3a3a3" strokeWidth={1.6} dot={false} activeDot={{r:3}} isAnimationActive={false}/><Line type="monotone" dataKey="error" stroke="#525252" strokeWidth={1.6} dot={false} activeDot={{r:3}} isAnimationActive={false}/><Scatter dataKey="alert_marker" fill="#ffffff" shape="circle" isAnimationActive={false}/></ComposedChart></ResponsiveContainer>:<div className="grid h-full place-items-center text-xs text-muted">No events in this range</div>}</div>
    <div className="mt-2 flex items-center gap-3 border-t border-line pt-2 text-[10px] text-muted"><span className="flex items-center gap-1"><i className="h-2 w-2 rounded-sm bg-white/30"/>Traffic spike bands</span><span className="flex items-center gap-1"><i className="h-2 w-2 rounded-full bg-white"/>Alert markers</span>{episodes.length>0&&<span className="ml-auto">Red-team episode timeline · stream 01</span>}</div>
    {episodes.length>0&&<div className="relative mt-2 h-3 overflow-hidden rounded bg-neutral-800">{episodes.map(e=><span key={`${e.start_idx}-${e.end_idx}`} title={`${e.kind} · events ${e.start_idx}–${e.end_idx}`} className={`absolute top-0 h-full ${e.hard_benign?"bg-neutral-400":"bg-white"}`} style={{left:`${e.start_idx/100}%`,width:`${Math.max((e.end_idx-e.start_idx)/100,.15)}%`}}/>)}</div>}
  </section>;
}
