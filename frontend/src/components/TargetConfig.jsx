import React, { useState, useEffect } from 'react';
import { Play, Globe, Code, AlertTriangle, Cpu, Sparkles, RefreshCw, XCircle, Zap } from 'lucide-react';
import { getModels, selectModel } from '../api';

export default function TargetConfig({ onStartScan, onCancelScan, isScanning, currentTarget, currentMode, error }) {
  const [target, setTarget] = useState(currentTarget || 'http://localhost:3000');
  const [mode, setMode] = useState(currentMode || 'dast');

  // AI Model Selection & Engine State
  const [modelCatalog, setModelCatalog] = useState(null);
  const [selectedModel, setSelectedModel] = useState('qwen3.5:4b');
  const [isLoadingModels, setIsLoadingModels] = useState(false);

  // Fetch installed models on mount
  const fetchModels = async () => {
    setIsLoadingModels(true);
    try {
      const data = await getModels();
      setModelCatalog(data);
      if (data.active_model) {
        setSelectedModel(data.active_model);
      }
    } catch (err) {
      console.warn('Failed to fetch installed models:', err);
    } finally {
      setIsLoadingModels(false);
    }
  };

  useEffect(() => {
    fetchModels();
  }, []);

  const handleModelChange = async (e) => {
    const newModel = e.target.value;
    setSelectedModel(newModel);
    try {
      await selectModel(newModel);
    } catch (err) {
      console.error('Failed to update active model on backend:', err);
    }
  };

  const normalizeTarget = (raw) => {
    let t = (raw || '').trim();
    if (!t) return 'http://localhost:3000';
    const digitsOnly = t.replace(/[^\d]/g, '');
    if (/^\d+$/.test(t) || /^:\d+$/.test(t)) {
      return `http://localhost:${t.replace(':', '')}`;
    }
    if (t.toLowerCase().startsWith('port') && digitsOnly) {
      return `http://localhost:${digitsOnly}`;
    }
    if (!t.startsWith('http://') && !t.startsWith('https://') && !t.toLowerCase().includes('github.com')) {
      return `http://${t}`;
    }
    return t;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!target.trim() || isScanning) return;
    const cleanTarget = normalizeTarget(target);
    setTarget(cleanTarget);
    onStartScan(cleanTarget, mode, selectedModel);
  };

  const handleQuickDemo = (e) => {
    e.preventDefault();
    if (isScanning) return;
    const cleanTarget = normalizeTarget(target);
    setTarget(cleanTarget);
    setSelectedModel('instant');
    onStartScan(cleanTarget, mode, 'instant');
  };

  const setDemoTarget = () => {
    setTarget('http://localhost:3000');
    setMode('dast');
  };

  const setDemoSast = () => {
    setTarget('https://github.com/koala73/worldmonitor');
    setMode('sast');
  };

  // Find capabilities for currently selected model
  const activeInstalledModel = modelCatalog?.installed_models?.find(
    (m) => m.name === selectedModel
  );

  return (
    <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-cyber-border rounded-xl p-5 shadow-sm dark:shadow-xl transition-colors duration-200 space-y-4">
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {/* Top Controls row */}
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
          {/* Target Input */}
          <div className="flex-1">
            <div className="flex items-center justify-between mb-1.5 gap-2">
              <label className="text-xs font-bold text-slate-700 dark:text-slate-400 uppercase tracking-wider">
                Assessment Target
              </label>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={setDemoTarget}
                  disabled={isScanning}
                  className="text-[11px] bg-slate-100 hover:bg-slate-200 text-blue-700 border border-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-cyan-400 dark:border-slate-700 px-2 py-0.5 rounded transition-colors disabled:opacity-40 font-medium shadow-xs"
                  title="Load World Monitor Local DAST Target"
                >
                  World Monitor (Local)
                </button>
                <button
                  type="button"
                  onClick={setDemoSast}
                  disabled={isScanning}
                  className="text-[11px] bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-purple-400 dark:border-slate-700 px-2 py-0.5 rounded transition-colors disabled:opacity-40 font-medium shadow-xs"
                  title="Load World Monitor GitHub SAST Target"
                >
                  GitHub Repo (SAST)
                </button>
              </div>
            </div>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={isScanning}
              placeholder="e.g. 3000, http://localhost:3000 or https://github.com/org/repo"
              className="w-full bg-slate-50 dark:bg-[#0b1120] border border-slate-300 dark:border-slate-700 focus:border-blue-500 dark:focus:border-cyan-500 focus:ring-2 focus:ring-blue-500/20 dark:focus:ring-cyan-500/20 rounded-lg px-3.5 py-2.5 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 font-mono transition-all disabled:opacity-50"
            />
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

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-end gap-2 justify-end">
            {isScanning ? (
              <button
                type="button"
                onClick={onCancelScan}
                className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg text-sm font-bold text-white bg-red-600 hover:bg-red-700 shadow-md shadow-red-500/30 active:scale-[0.98] transition-all cursor-pointer"
                title="Cancel active assessment immediately"
              >
                <XCircle className="w-4 h-4" />
                <span>Cancel Assessment</span>
              </button>
            ) : (
              <>
                <button
                  type="button"
                  onClick={handleQuickDemo}
                  className="h-10 w-10 rounded-lg text-amber-700 hover:text-amber-800 bg-amber-100/90 hover:bg-amber-200 border border-amber-300 dark:bg-amber-950/40 dark:hover:bg-amber-900/60 dark:text-amber-400 dark:border-amber-700/60 shadow-xs active:scale-[0.96] transition-all cursor-pointer flex items-center justify-center shrink-0"
                  title="Autonomous Rule Engine (< 3s)"
                >
                  <Zap className="w-4 h-4 fill-amber-500 text-amber-500 dark:fill-amber-400 dark:text-amber-400" />
                </button>
                <button
                  type="submit"
                  disabled={!target.trim()}
                  className="flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg text-sm font-bold text-white bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 shadow-blue-500/25 active:scale-[0.98] transition-all disabled:opacity-50 cursor-pointer"
                >
                  <Play className="w-4 h-4 fill-white" />
                  <span>Launch Assessment</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* AI Model Intelligence Bar */}
        <div className="pt-3 border-t border-slate-100 dark:border-slate-800/80 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="flex items-center gap-1.5 font-bold text-slate-700 dark:text-slate-300">
              <Cpu className="w-4 h-4 text-blue-500 dark:text-cyan-400" />
              <span>AI Intelligence Engine:</span>
            </div>

            {/* Model Selector Dropdown */}
            <div className="relative">
              <select
                value={selectedModel}
                onChange={handleModelChange}
                disabled={isScanning}
                className="bg-slate-100 dark:bg-[#0b1120] border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 rounded-lg px-3 py-1.5 text-xs font-semibold focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 dark:focus:border-cyan-500 outline-none transition-all disabled:opacity-50 cursor-pointer"
              >
                {/* Autonomous Rule Engine Option */}
                <optgroup label="Autonomous Engine">
                  <option value="instant">Autonomous Rule Engine (Deterministic / Instant)</option>
                </optgroup>
                {/* Installed Local Ollama Models */}
                {modelCatalog?.installed_models && modelCatalog.installed_models.length > 0 ? (
                  <optgroup label="Local Models (Ollama)">
                    {modelCatalog.installed_models.map((m) => (
                      <option key={m.name} value={m.name}>
                        {m.name} {m.parameter_size ? `(${m.parameter_size})` : ''} - {m.size_gb}GB
                        {m.capabilities?.includes('thinking') ? ' ★ Thinking' : ''}
                      </option>
                    ))}
                  </optgroup>
                ) : (
                  <optgroup label="Local Models (Ollama)">
                    <option value="qwen3.5:4b">qwen3.5:4b (4.7B 3.4GB) ★ Thinking & Tools</option>
                    <option value="gemma2:9b">gemma2:9b (9.2B 5.4GB)</option>
                  </optgroup>
                )}

                {/* Cloud Models */}
                {/* Cloud Models */}
                <optgroup label="Cloud Models (NVIDIA NIM Online)">
                  {modelCatalog?.cloud_models?.map((cm) => (
                    <option key={cm.name} value={cm.name}>
                      {cm.display_name} {modelCatalog?.cloud_ready ? '🟢' : '🔑 Key Needed'}
                    </option>
                  )) || (
                    <>
                      <option value="cloud:minimaxai/minimax-m3.1-flash">NVIDIA NIM: minimax-m3.1-flash (Ultra-Fast ⚡) 🟢</option>
                      <option value="cloud:nvidia/nemotron-3.5-lightning-30b-a3b">NVIDIA NIM: nemotron-3.5-lightning-30b (Reasoning 🧠) 🟢</option>
                    </>
                  )}
                </optgroup>
              </select>
            </div>

            {/* Refresh installed models button */}
            <button
              type="button"
              onClick={fetchModels}
              disabled={isLoadingModels || isScanning}
              className="p-1 text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 rounded transition-colors disabled:opacity-40"
              title="Refresh installed Ollama models"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingModels ? 'animate-spin' : ''}`} />
            </button>

            {/* Model Capabilities Pill */}
            {activeInstalledModel?.capabilities?.includes('thinking') && (
              <span className="inline-flex items-center gap-1 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800/50 px-2 py-0.5 rounded-md font-medium text-[11px]">
                <Sparkles className="w-3 h-3 text-amber-500" />
                Thinking & Tools Ready
              </span>
            )}

            {/* Context Window Pill */}
            <span className="inline-flex items-center gap-1 bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800/50 px-2 py-0.5 rounded-md font-medium text-[11px]">
              Ctx: 8192 tokens
            </span>
          </div>

          {/* Right Status Pill */}
          <div className="flex items-center gap-2">
            {modelCatalog?.ollama_online !== false ? (
              <span className="inline-flex items-center gap-1.5 text-emerald-700 dark:text-emerald-400 font-medium">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span>Ollama Engine: Connected</span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-slate-500 font-medium">
                <span className="w-2 h-2 rounded-full bg-slate-400" />
                <span>Ollama: Standby</span>
              </span>
            )}
            {modelCatalog?.cloud_ready && (
              <span className="inline-flex items-center gap-1.5 text-blue-700 dark:text-cyan-400 font-medium ml-2">
                <span className="w-2 h-2 rounded-full bg-blue-500" />
                <span>NVIDIA Cloud: Active</span>
              </span>
            )}
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
