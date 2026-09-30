import React from 'react';
import { ShieldCheck, HelpCircle, AlertOctagon, Flame, AlertTriangle, Layers } from 'lucide-react';

export default function MetricCards({ summary, activeFilter, onSelectFilter }) {
  const cards = [
    {
      id: 'all',
      label: 'Total Findings',
      count: summary?.total ?? 0,
      icon: Layers,
      color: 'text-indigo-400',
      border: 'border-l-indigo-500',
      badge: 'All Candidates',
      subtext: 'Normalized across tools',
    },
    {
      id: 'confirmed',
      label: 'Confirmed',
      count: summary?.confirmed ?? 0,
      icon: ShieldCheck,
      color: 'text-emerald-400',
      border: 'border-l-emerald-500',
      badge: 'Verified PoC Proof',
      subtext: 'Evidence-gated (0 false positives)',
    },
    {
      id: 'unverified',
      label: 'Unverified',
      count: summary?.unverified ?? 0,
      icon: HelpCircle,
      color: 'text-amber-400',
      border: 'border-l-amber-500',
      badge: 'Tool Hypothesis',
      subtext: 'Candidate needing inspection',
    },
    {
      id: 'critical',
      label: 'Critical Severity',
      count: summary?.critical ?? 0,
      icon: AlertOctagon,
      color: 'text-red-500',
      border: 'border-l-red-500',
      badge: 'CVSS 9.0 - 10.0',
      subtext: 'Immediate action required',
    },
    {
      id: 'high',
      label: 'High Severity',
      count: summary?.high ?? 0,
      icon: Flame,
      color: 'text-rose-400',
      border: 'border-l-rose-500',
      badge: 'CVSS 7.0 - 8.9',
      subtext: 'High business exposure',
    },
    {
      id: 'medium',
      label: 'Medium Severity',
      count: summary?.medium ?? 0,
      icon: AlertTriangle,
      color: 'text-yellow-400',
      border: 'border-l-yellow-500',
      badge: 'CVSS 4.0 - 6.9',
      subtext: 'Standard hardening',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
      {cards.map((c) => {
        const Icon = c.icon;
        const isSelected = activeFilter === c.id;

        return (
          <button
            key={c.id}
            type="button"
            onClick={() => onSelectFilter && onSelectFilter(c.id)}
            className={`text-left bg-[#0f172a] border ${
              isSelected ? 'border-cyan-400 ring-2 ring-cyan-500/20 shadow-lg shadow-cyan-500/10' : 'border-cyber-border hover:border-slate-600'
            } border-l-4 ${c.border} rounded-xl p-4 transition-all hover:bg-slate-900/80`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                {c.label}
              </span>
              <Icon className={`w-4 h-4 ${c.color}`} />
            </div>

            <div className="flex items-baseline gap-2 mb-1.5">
              <span className={`text-3xl font-extrabold tracking-tight ${c.color}`}>
                {c.count}
              </span>
            </div>

            <div className="text-[10px] font-mono text-slate-400 truncate">
              {c.badge}
            </div>
          </button>
        );
      })}
    </div>
  );
}
