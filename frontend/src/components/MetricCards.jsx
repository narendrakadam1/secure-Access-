import React from 'react';
import { ShieldCheck, HelpCircle, AlertOctagon, Flame, AlertTriangle, Layers } from 'lucide-react';

export default function MetricCards({ summary, activeFilter, onSelectFilter }) {
  const cards = [
    {
      id: 'all',
      label: 'Total Findings',
      count: summary?.total ?? 0,
      icon: Layers,
      color: 'text-sky-600 dark:text-indigo-400',
      border: 'border-l-sky-500 dark:border-l-indigo-500',
      activeBorder: 'border-sky-500 dark:border-cyan-400 ring-2 ring-sky-500/20 dark:ring-cyan-500/20 shadow-md',
      badge: 'All Candidates',
    },
    {
      id: 'confirmed',
      label: 'Confirmed',
      count: summary?.confirmed ?? 0,
      icon: ShieldCheck,
      color: 'text-emerald-600 dark:text-emerald-400',
      border: 'border-l-emerald-500',
      activeBorder: 'border-emerald-500 ring-2 ring-emerald-500/20 shadow-md',
      badge: 'Verified PoC Proof',
    },
    {
      id: 'unverified',
      label: 'Unverified',
      count: summary?.unverified ?? 0,
      icon: HelpCircle,
      color: 'text-amber-500 dark:text-amber-400',
      border: 'border-l-amber-500',
      activeBorder: 'border-amber-500 ring-2 ring-amber-500/20 shadow-md',
      badge: 'Tool Hypothesis',
    },
    {
      id: 'critical',
      label: 'Critical Severity',
      count: summary?.critical ?? 0,
      icon: AlertOctagon,
      color: 'text-red-600 dark:text-red-500',
      border: 'border-l-red-500',
      activeBorder: 'border-red-500 ring-2 ring-red-500/20 shadow-md',
      badge: 'CVSS 9.0 - 10.0',
    },
    {
      id: 'high',
      label: 'High Severity',
      count: summary?.high ?? 0,
      icon: Flame,
      color: 'text-rose-600 dark:text-rose-400',
      border: 'border-l-rose-500',
      activeBorder: 'border-rose-500 ring-2 ring-rose-500/20 shadow-md',
      badge: 'CVSS 7.0 - 8.9',
    },
    {
      id: 'medium',
      label: 'Medium Severity',
      count: summary?.medium ?? 0,
      icon: AlertTriangle,
      color: 'text-yellow-600 dark:text-yellow-400',
      border: 'border-l-yellow-500',
      activeBorder: 'border-yellow-500 ring-2 ring-yellow-500/20 shadow-md',
      badge: 'CVSS 4.0 - 6.9',
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
            className={`text-left bg-white dark:bg-[#0f172a] border ${
              isSelected
                ? c.activeBorder
                : 'border-slate-200 dark:border-cyber-border hover:border-slate-300 dark:hover:border-slate-600 shadow-xs'
            } border-l-4 ${c.border} rounded-xl p-4 transition-all hover:bg-slate-50 dark:hover:bg-slate-900/80 cursor-pointer`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                {c.label}
              </span>
              <Icon className={`w-4 h-4 ${c.color}`} />
            </div>

            <div className="flex items-baseline gap-2 mb-1.5">
              <span className={`text-3xl font-extrabold tracking-tight ${c.color}`}>
                {c.count}
              </span>
            </div>

            <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 truncate font-medium">
              {c.badge}
            </div>
          </button>
        );
      })}
    </div>
  );
}
