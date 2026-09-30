import React from 'react';
import { Shield, BookOpen, Activity, Lock } from 'lucide-react';

export default function Header({ onOpenResearchGaps, isScanning }) {
  return (
    <header className="border-b border-cyber-border bg-[#0f172a]/80 backdrop-blur sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Logo and Title */}
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-white font-bold text-xl">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-extrabold text-white tracking-tight">SECUREASSESS</h1>
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                SIH 2026 PS 26163
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Autonomous LLM-Orchestrated Security Assessment Engine — NTRO
            </p>
          </div>
        </div>

        {/* Right Controls & Badges */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-1 rounded-full">
            <Lock className="w-3.5 h-3.5" />
            <span>Pre-Packet Allowlist Gated</span>
          </div>

          <div className="flex items-center gap-1.5 text-xs text-indigo-400 bg-indigo-500/10 border border-indigo-500/30 px-2.5 py-1 rounded-full">
            <Activity className="w-3.5 h-3.5" />
            <span>Safe Playbook (≤5 probes)</span>
          </div>

          <button
            onClick={onOpenResearchGaps}
            className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 hover:text-cyan-400 bg-slate-800/80 hover:bg-slate-800 border border-slate-700 hover:border-cyan-500/40 px-3 py-1.5 rounded-lg transition-all"
            title="View Research Gap Coverage Matrix (Literature-grounded architecture)"
          >
            <BookOpen className="w-4 h-4 text-cyan-400" />
            <span>Research Gap Matrix</span>
          </button>
        </div>
      </div>
    </header>
  );
}
