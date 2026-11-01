"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { GitCommit, ShieldAlert, ArrowRight, Activity, Flame } from "lucide-react";

type StageEvent = {
  event_id: number;
  timestamp: number;
  iso_time: string;
  kind: string;
  tactic: string;
  tactic_id: string;
  technique: string;
  technique_id: string;
  stage_rank: number;
  src_ip: string;
  username: string;
  path: string;
  status: number;
};

type AttackChain = {
  chain_id: string;
  entity_type: string;
  entity_value: string;
  duration_seconds: number;
  start_time: string;
  last_seen: string;
  stage_count: number;
  unique_attack_types: string[];
  mitre_tactics: string[];
  detected_campaigns: string[];
  risk_score: number;
  status: string;
  timeline: StageEvent[];
};

type CorrelationData = {
  chains: AttackChain[];
  graph: {
    nodes: Array<{ id: string; label: string; type: string }>;
    edges: Array<{ source: string; target: string; relation: string }>;
  };
};

function AttackChainPanelComponent({ onSelectEvent, throughId }: { onSelectEvent?: (id: number) => void; throughId?: number }) {
  const { data, isLoading } = useQuery<CorrelationData>({
    queryKey: ["correlation-chains", throughId],
    placeholderData: (previous) => previous,
    queryFn: async () => {
      const url = throughId !== undefined && throughId >= 0 ? `/api/correlation/chains?through_id=${throughId}` : "/api/correlation/chains";
      const res = await fetch(url);
      if (!res.ok) throw new Error("Failed to fetch correlation chains");
      return res.json();
    },
    refetchInterval: 5000,
  });

  const chains = data?.chains || [];

  if (isLoading) {
    return (
      <div className="rounded-xl border border-line bg-panel p-4 text-xs text-muted">
        Analyzing temporal attack chains...
      </div>
    );
  }

  if (!chains.length) {
    return null;
  }

  return (
    <div className="mb-4 space-y-3 rounded-xl border border-line bg-panel p-4 shadow-panel">
      <div className="flex items-center justify-between border-b border-line pb-3">
        <div className="flex items-center gap-2">
          <div className="grid h-7 w-7 place-items-center rounded-lg bg-red-500/10 text-red-400">
            <Flame size={16} />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Temporal Attack Chains</h3>
            <p className="text-[11px] text-muted">
              Correlated multi-stage campaigns tracked across temporal sliding windows
            </p>
          </div>
        </div>
        <span className="rounded-md border border-line bg-white/5 px-2.5 py-1 font-mono text-[11px] text-slate-300">
          {chains.length} Active {chains.length === 1 ? "Chain" : "Chains"}
        </span>
      </div>

      <div className="space-y-3">
        {chains.map((chain) => {
          const isHighRisk = chain.risk_score >= 70;
          return (
            <div
              key={chain.chain_id}
              className={`rounded-xl border p-4 transition ${
                isHighRisk
                  ? "border-red-500/40 bg-red-950/10"
                  : "border-line bg-ink/40"
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line/60 pb-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-white">
                    {chain.entity_type.toUpperCase()}: {chain.entity_value}
                  </span>
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-semibold uppercase ${
                      isHighRisk
                        ? "bg-red-500/20 text-red-300"
                        : "bg-amber-500/20 text-amber-300"
                    }`}
                  >
                    Risk Score: {chain.risk_score}/100
                  </span>
                </div>
                <div className="text-[10px] text-slate-400">
                  Duration: {chain.duration_seconds}s · {chain.timeline.length} correlated events
                </div>
              </div>

              {chain.detected_campaigns.length > 0 && (
                <div className="mt-2.5 flex flex-wrap gap-1.5">
                  {chain.detected_campaigns.map((camp, idx) => (
                    <span
                      key={idx}
                      className="inline-flex items-center gap-1 rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] font-medium text-red-200"
                    >
                      <ShieldAlert size={11} />
                      {camp}
                    </span>
                  ))}
                </div>
              )}

              {/* Multi-Stage Progression Timeline */}
              <div className="mt-3 flex items-center gap-2 overflow-x-auto py-2">
                {chain.timeline.map((stage, idx) => (
                  <div key={idx} className="flex shrink-0 items-center gap-2">
                    <button
                      onClick={() => onSelectEvent?.(stage.event_id)}
                      className="group flex flex-col items-start rounded-lg border border-line bg-panel p-2 text-left hover:border-slate-500 hover:bg-white/5 transition"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[9px] text-slate-400">
                          #{stage.event_id}
                        </span>
                        <span className="rounded bg-white/10 px-1 py-0.5 font-mono text-[9px] text-slate-200">
                          {stage.status}
                        </span>
                      </div>
                      <div className="mt-1 text-[11px] font-semibold text-white">
                        {stage.kind.replace("_", " ")}
                      </div>
                      <div className="mt-0.5 text-[9px] text-slate-400">
                        {stage.tactic} ({stage.tactic_id})
                      </div>
                    </button>
                    {idx < chain.timeline.length - 1 && (
                      <ArrowRight size={13} className="shrink-0 text-slate-600" />
                    )}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default React.memo(AttackChainPanelComponent);
