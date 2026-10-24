import React, { useState } from 'react';
import { Play, Globe, Code, AlertTriangle } from 'lucide-react';

export default function TargetConfig({ onStartScan, isScanning, currentTarget, currentMode, error }) {
  const [target, setTarget] = useState(currentTarget || 'http://localhost:3000');
  const [mode, setMode] = useState(currentMode || 'dast');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!target.trim() || isScanning) return;
    onStartScan(target.trim(), mode);
  };

  const setDemoTarget = () => {
    setTarget('http://localhost:3000');
    setMode('dast');
  };

  const setDemoSast = () => {
    setTarget('https://github.com/koala73/worldmonitor');
    setMode('sast');
  };

  return (
    <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-cyber-border rounded-xl p-5 shadow-sm dark:shadow-xl transition-colors duration-200">
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {/* Top Controls row */}
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
          {/* Target Input */}
          <div className="flex-1 relative">
            <label className="block text-xs font-bold text-slate-700 dark:text-slate-400 uppercase tracking-wider mb-1.5">
              Assessment Target
            </label>
            <div className="relative">
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
                placeholder="e.g. http://localhost:3000 or https://github.com/org/repo"
                className="w-full bg-slate-50 dark:bg-[#0b1120] border border-slate-300 dark:border-slate-700 focus:border-blue-500 dark:focus:border-cyan-500 focus:ring-2 focus:ring-blue-500/20 dark:focus:ring-cyan-500/20 rounded-lg pl-4 pr-64 py-2.5 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 font-mono transition-all disabled:opacity-50"
              />
              <div className="absolute right-2 top-2 flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={setDemoTarget}
                  disabled={isScanning}
                  className="text-xs bg-slate-100 hover:bg-slate-200 text-blue-700 border border-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-cyan-400 dark:border-slate-700 px-2.5 py-1 rounded transition-colors disabled:opacity-40 font-medium shadow-sm"
                  title="Load World Monitor Local DAST Target"
                >
                  World Monitor (Local)
                </button>
                <button
                  type="button"
                  onClick={setDemoSast}
                  disabled={isScanning}
                  className="text-xs bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-purple-400 dark:border-slate-700 px-2.5 py-1 rounded transition-colors disabled:opacity-40 font-medium shadow-sm"
                  title="Load World Monitor GitHub SAST Target"
                >
                  GitHub Repo (SAST)
                </button>
              </div>
            </div>
          </div>

          {/* Mode Selector */}
          <div className="w-full lg:w-72">
            <label className="block text-xs font-bold text-slate-700 dark:text-slate-400 uppercase tracking-wider mb-1.5">
              Assessment Pipeline Mode
            </label>
            <div className="grid grid-cols-2 gap-1.5 bg-slate-100 dark:bg-[#0b1120] p-1 rounded-lg border border-slate-300 dark:border-slate-700">
              <button
                type="button"
                onClick={() => setMode('dast')}
                disabled={isScanning}
                className={`flex items-center justify-center gap-1.5 py-1.5 rounded-md text-xs font-bold transition-all ${
                  mode === 'dast'
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-500/30'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                } disabled:opacity-50`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>DAST (Web App)</span>
              </button>
              <button
                type="button"
                onClick={() => setMode('sast')}
                disabled={isScanning}
                className={`flex items-center justify-center gap-1.5 py-1.5 rounded-md text-xs font-bold transition-all ${
                  mode === 'sast'
                    ? 'bg-purple-600 text-white shadow-md shadow-purple-500/30'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                } disabled:opacity-50`}
              >
                <Code className="w-3.5 h-3.5" />
                <span>SAST (Code)</span>
              </button>
            </div>
          </div>

          {/* Launch Button */}
          <div className="flex flex-col justify-end">
            <button
              type="submit"
              disabled={isScanning || !target.trim()}
              className={`flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg text-sm font-bold text-white shadow-md transition-all ${
                isScanning
                  ? 'bg-slate-400 dark:bg-slate-700 text-slate-100 cursor-not-allowed'
                  : 'bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 shadow-blue-500/25 active:scale-[0.98]'
              }`}
            >
              {isScanning ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Pipeline Active...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-white" />
                  <span>Launch Assessment</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Error notification banner if any */}
        {error && (
          <div className="flex items-center gap-2 p-3 rounded-lg bg-red-50 border border-red-200 dark:bg-red-950/40 dark:border-red-500/40 text-red-700 dark:text-red-300 text-xs">
            <AlertTriangle className="w-4 h-4 text-red-500 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </form>
    </div>
  );
}
