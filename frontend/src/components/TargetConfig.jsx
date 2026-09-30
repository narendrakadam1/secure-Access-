import React, { useState } from 'react';
import { Play, Globe, Code, AlertTriangle, Sparkles, CheckCircle2 } from 'lucide-react';

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
    <div className="bg-[#0f172a] border border-cyber-border rounded-xl p-5 shadow-xl">
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {/* Top Controls row */}
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
          {/* Target Input */}
          <div className="flex-1 relative">
            <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">
              Assessment Target
            </label>
            <div className="relative">
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
                placeholder="e.g. http://localhost:3000 or https://github.com/org/repo"
                className="w-full bg-[#0b1120] border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-lg px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 font-mono transition-all disabled:opacity-50"
              />
              <div className="absolute right-2 top-2 flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={setDemoTarget}
                  disabled={isScanning}
                  className="text-xs bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 px-2 py-1 rounded transition-colors disabled:opacity-40"
                  title="Load World Monitor Local DAST Target"
                >
                  World Monitor (Local)
                </button>
                <button
                  type="button"
                  onClick={setDemoSast}
                  disabled={isScanning}
                  className="text-xs bg-slate-800 hover:bg-slate-700 text-purple-400 border border-slate-700 px-2 py-1 rounded transition-colors disabled:opacity-40"
                  title="Load World Monitor GitHub SAST Target"
                >
                  GitHub Repo (SAST)
                </button>
              </div>
            </div>
          </div>

          {/* Mode Selector */}
          <div className="w-full lg:w-72">
            <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">
              Assessment Pipeline Mode
            </label>
            <div className="grid grid-cols-2 gap-2 bg-[#0b1120] p-1 rounded-lg border border-slate-700">
              <button
                type="button"
                onClick={() => setMode('dast')}
                disabled={isScanning}
                className={`flex items-center justify-center gap-1.5 py-1.5 rounded-md text-xs font-bold transition-all ${
                  mode === 'dast'
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-500/30'
                    : 'text-slate-400 hover:text-slate-200'
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
                    : 'text-slate-400 hover:text-slate-200'
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
              className={`flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg text-sm font-bold text-white shadow-lg transition-all ${
                isScanning
                  ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                  : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 shadow-cyan-500/25 active:scale-[0.98]'
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
          <div className="flex items-center gap-2 p-3 rounded-lg bg-red-950/40 border border-red-500/40 text-red-300 text-xs">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </form>
    </div>
  );
}
