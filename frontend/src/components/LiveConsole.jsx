import React, { useRef, useEffect } from 'react';
import { Terminal, Copy, Check, Trash2 } from 'lucide-react';

export default function LiveConsole({ logs, isScanning }) {
  const scrollRef = useRef(null);
  const [copied, setCopied] = React.useState(false);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const handleCopy = () => {
    if (!logs || logs.length === 0) return;
    const text = logs.map((l) => `[${l.timestamp}] [${l.source_agent || 'System'}] ${l.message}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#0f172a] border border-cyber-border rounded-xl overflow-hidden shadow-xl">
      {/* Console Header */}
      <div className="bg-[#0b1120] border-b border-cyber-border px-4 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
            Live Multi-Agent Orchestration Log
          </span>
          {isScanning && (
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-500">
            {logs?.length || 0} events
          </span>
          <button
            onClick={handleCopy}
            className="text-xs text-slate-400 hover:text-slate-200 bg-slate-800/80 hover:bg-slate-700 px-2 py-1 rounded transition-colors flex items-center gap-1"
            title="Copy logs"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Terminal View */}
      <div
        ref={scrollRef}
        className="h-44 overflow-y-auto p-3.5 bg-[#050811] font-mono text-xs text-slate-300 space-y-1"
      >
        {(!logs || logs.length === 0) ? (
          <div className="text-slate-600 italic">
            Waiting for scan initiation. System idle.
          </div>
        ) : (
          logs.map((log, idx) => {
            const agent = log.source_agent || 'System';
            let agentColor = 'text-cyan-400';
            if (agent.includes('Validation')) agentColor = 'text-emerald-400';
            if (agent.includes('Report')) agentColor = 'text-purple-400';
            if (agent.includes('Scan')) agentColor = 'text-blue-400';
            if (agent.includes('Analysis')) agentColor = 'text-amber-400';

            return (
              <div key={log.id || idx} className="leading-relaxed hover:bg-slate-900/40 px-1 rounded flex gap-2">
                <span className="text-slate-600 select-none">
                  {log.timestamp ? log.timestamp.split('T')[1]?.substring(0, 8) : '00:00:00'}
                </span>
                <span className={`font-bold ${agentColor} select-none`}>
                  [{agent}]
                </span>
                <span className="text-slate-200 break-all">
                  {log.message}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
