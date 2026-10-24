import React from 'react';
import { Shield, BookOpen, Activity, Lock, Sun, Moon, FileSearch } from 'lucide-react';

export default function Header({
  onOpenResearchGaps,
  isScanning,
  theme,
  onToggleTheme,
  onLoadPreviousReport,
  hasFindings,
}) {
  return (
    <header className="border-b border-slate-200 dark:border-cyber-border bg-white/90 dark:bg-[#0f172a]/90 backdrop-blur sticky top-0 z-30 transition-colors duration-200 shadow-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Logo and Title */}
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-sky-500 to-blue-600 flex items-center justify-center shadow-lg shadow-blue-500/20 text-white font-bold text-xl">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-extrabold text-slate-900 dark:text-white tracking-tight">
                SECUREASSESS
              </h1>
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-sky-100 text-sky-800 border border-sky-300 dark:bg-cyan-500/10 dark:text-cyan-400 dark:border-cyan-500/30">
                Enterprise v2.4
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Autonomous LLM-Orchestrated Security Assessment Engine
            </p>
          </div>
        </div>

        {/* Right Controls & Badges */}
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="flex items-center gap-1.5 text-xs text-emerald-700 bg-emerald-50 border border-emerald-300 dark:text-emerald-400 dark:bg-emerald-500/10 dark:border-emerald-500/30 px-2.5 py-1 rounded-full font-medium">
            <Lock className="w-3.5 h-3.5" />
            <span>Pre-Packet Allowlist Gated</span>
          </div>

          <div className="flex items-center gap-1.5 text-xs text-purple-700 bg-purple-50 border border-purple-300 dark:text-indigo-400 dark:bg-indigo-500/10 dark:border-indigo-500/30 px-2.5 py-1 rounded-full font-medium">
            <Activity className="w-3.5 h-3.5" />
            <span>Safe Playbook (≤5 probes)</span>
          </div>

          <button
            onClick={onOpenResearchGaps}
            className="flex items-center gap-1.5 text-xs font-semibold text-blue-700 hover:text-blue-800 bg-blue-50 hover:bg-blue-100 border border-blue-200 dark:text-slate-300 dark:hover:text-cyan-400 dark:bg-slate-800/80 dark:border-slate-700 px-3 py-1.5 rounded-lg transition-all shadow-sm"
            title="View Research Gap Coverage Matrix (Literature-grounded architecture)"
          >
            <BookOpen className="w-4 h-4 text-blue-600 dark:text-cyan-400" />
            <span>Research Gap Matrix</span>
          </button>

          {/* Theme Toggle Button */}
          <button
            onClick={onToggleTheme}
            className="p-2 rounded-lg border text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 border-slate-300 dark:text-slate-300 dark:hover:text-amber-400 dark:bg-slate-800/80 dark:border-slate-700 transition-all shadow-sm flex items-center gap-1.5 text-xs font-semibold"
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          >
            {theme === 'dark' ? (
              <>
                <Sun className="w-4 h-4 text-amber-400" />
                <span className="hidden sm:inline">Light</span>
              </>
            ) : (
              <>
                <Moon className="w-4 h-4 text-slate-600" />
                <span className="hidden sm:inline">Dark</span>
              </>
            )}
          </button>
        </div>
      </div>
    </header>
  );
}
