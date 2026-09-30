import React from 'react';
import { CheckCircle2, Clock, Loader2, XCircle, Search, ShieldAlert, Cpu, CheckCheck, FileText } from 'lucide-react';

const PHASES = [
  { id: 'recon', label: 'Recon', agent: 'ReconAgent', icon: Search, desc: 'Target reachability & attack surface discovery' },
  { id: 'scanning', label: 'Scanning', agent: 'ScanAgent', icon: ShieldAlert, desc: 'DAST/SAST scanner orchestration & raw artifact collection' },
  { id: 'analysis', label: 'Analysis', agent: 'AnalysisAgent', icon: Cpu, desc: 'PTFusion normalization, deduplication & CVSS 3.1 scoring' },
  { id: 'validation', label: 'Validation', agent: 'ValidationAgent', icon: CheckCheck, desc: 'Evidence-gated non-destructive validation playbook' },
  { id: 'report', label: 'Report', agent: 'ReportAgent', icon: FileText, desc: 'SUDARSHAN HTML/PDF & SIH 26163 deliverable synthesis' },
];

export default function PhaseStepper({ currentPhase, isFailed }) {
  const getPhaseIndex = (phase) => {
    switch (phase) {
      case 'recon': return 0;
      case 'scanning': return 1;
      case 'analysis': return 2;
      case 'validation': return 3;
      case 'report': return 4;
      case 'completed': return 5;
      default: return -1;
    }
  };

  const currentIndex = getPhaseIndex(currentPhase);

  return (
    <div className="bg-[#0f172a] border border-cyber-border rounded-xl p-5 shadow-xl">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
          Sequential 5-Agent Pipeline Progression (Research Gap #11)
        </h2>
        <span className="text-xs font-mono font-bold text-cyan-400 uppercase">
          Current State: {currentPhase ? currentPhase.toUpperCase() : 'IDLE'}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {PHASES.map((p, idx) => {
          const Icon = p.icon;
          const isCompleted = currentIndex > idx || currentPhase === 'completed';
          const isCurrent = currentIndex === idx && currentPhase !== 'completed';
          const isPending = currentIndex < idx;

          let cardBorder = 'border-slate-800 bg-[#0b1120]/40';
          let textColor = 'text-slate-500';
          let iconColor = 'text-slate-600';
          let statusBadge = (
            <span className="flex items-center gap-1 text-[11px] text-slate-500">
              <Clock className="w-3 h-3" /> Pending
            </span>
          );

          if (isFailed && isCurrent) {
            cardBorder = 'border-red-500/50 bg-red-950/20';
            textColor = 'text-red-400';
            iconColor = 'text-red-400';
            statusBadge = (
              <span className="flex items-center gap-1 text-[11px] text-red-400 font-bold">
                <XCircle className="w-3 h-3" /> Failed
              </span>
            );
          } else if (isCurrent) {
            cardBorder = 'border-cyan-500/60 bg-cyan-950/20 shadow-md shadow-cyan-500/10';
            textColor = 'text-cyan-300';
            iconColor = 'text-cyan-400';
            statusBadge = (
              <span className="flex items-center gap-1 text-[11px] text-cyan-400 font-bold animate-pulse">
                <Loader2 className="w-3 h-3 animate-spin" /> Running
              </span>
            );
          } else if (isCompleted) {
            cardBorder = 'border-emerald-500/40 bg-emerald-950/10';
            textColor = 'text-emerald-300';
            iconColor = 'text-emerald-400';
            statusBadge = (
              <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-bold">
                <CheckCircle2 className="w-3 h-3" /> Done
              </span>
            );
          }

          return (
            <div
              key={p.id}
              className={`p-3.5 rounded-lg border transition-all ${cardBorder}`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className={`p-2 rounded-md bg-[#0f172a] border border-slate-800 ${iconColor}`}>
                  <Icon className="w-4 h-4" />
                </div>
                {statusBadge}
              </div>
              <div className="text-sm font-bold text-slate-100">{p.label}</div>
              <div className="text-xs font-mono text-cyan-400/80 mb-1">[{p.agent}]</div>
              <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                {p.desc}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
