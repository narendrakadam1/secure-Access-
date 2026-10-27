import React, { useRef, useEffect } from 'react';
import { Terminal, Copy, Check } from 'lucide-react';

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
    const text = logs
      .map((l) => {
        const rawTime = l.ts || l.timestamp || '';
        let localTime = rawTime;
        if (rawTime) {
          try {
            const hasTz = rawTime.endsWith('Z') || rawTime.includes('+') || (rawTime.indexOf('-', 10) !== -1);
            const iso = (rawTime.includes('T') && !hasTz) ? `${rawTime}Z` : rawTime;
            const d = new Date(iso);
            if (!isNaN(d.getTime())) {
              localTime = d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
            }
          } catch {}
        }
        const agent = l.agent_name || l.source_agent || 'System';
        const msg = l.line || l.message || '';
        return `[${localTime}] [${agent}] ${msg}`;
      })
      .join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-cyber-border rounded-xl overflow-hidden shadow-sm dark:shadow-xl transition-colors duration-200">
      {/* Console Header */}
      <div className="bg-slate-50 dark:bg-[#0b1120] border-b border-slate-200 dark:border-cyber-border px-4 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-blue-600 dark:text-cyan-400" />
          <span className="text-xs font-bold text-slate-800 dark:text-slate-300 uppercase tracking-wider">
            Live Multi-Agent Orchestration Log
          </span>
          {isScanning && (
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-500 dark:bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-600 dark:bg-cyan-500"></span>
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-500">
            {logs?.length || 0} events
          </span>
          <button
            onClick={handleCopy}
            className="text-xs text-slate-600 hover:text-slate-900 bg-white hover:bg-slate-100 border border-slate-200 dark:text-slate-400 dark:hover:text-slate-200 dark:bg-slate-800/80 dark:hover:bg-slate-700 dark:border-slate-700 px-2.5 py-1 rounded transition-colors flex items-center gap-1 shadow-xs"
            title="Copy logs"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Terminal View */}
      <div
        ref={scrollRef}
        className="h-56 overflow-y-auto p-3.5 bg-slate-50/60 dark:bg-[#050811] font-mono text-xs text-slate-800 dark:text-slate-300 space-y-1 select-text border-t border-slate-100 dark:border-transparent"
      >
        {(!logs || logs.length === 0) ? (
          <div className="text-slate-400 dark:text-slate-600 italic py-2">
            Waiting for scan initiation. System idle. Click "Launch Assessment" to begin.
          </div>
        ) : (
          logs.map((log, idx) => {
            const agent = log.agent_name || log.source_agent || 'System';
            const rawTime = log.ts || log.timestamp || '';
            const msg = log.line || log.message || '';

            // Format timestamp into laptop local time (matches user's laptop clock)
            let formattedTime = '00:00:00';
            if (rawTime) {
              try {
                const hasTz = rawTime.endsWith('Z') || rawTime.includes('+') || (rawTime.indexOf('-', 10) !== -1);
                const isoStr = (rawTime.includes('T') && !hasTz) ? `${rawTime}Z` : rawTime;
                const dateObj = new Date(isoStr);
                if (!isNaN(dateObj.getTime())) {
                  formattedTime = dateObj.toLocaleTimeString([], {
                    hour12: false,
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  });
                } else if (rawTime.includes('T')) {
                  formattedTime = rawTime.split('T')[1]?.substring(0, 8);
                } else {
                  formattedTime = rawTime.substring(0, 8);
                }
              } catch {
                formattedTime = rawTime.substring(0, 8);
              }
            }

            // Agent badge color scheme
            let agentColor = 'text-blue-600 dark:text-cyan-400';
            if (agent.includes('Validation')) agentColor = 'text-emerald-600 dark:text-emerald-400';
            else if (agent.includes('Report')) agentColor = 'text-purple-600 dark:text-purple-400';
            else if (agent.includes('Scan')) agentColor = 'text-sky-600 dark:text-blue-400';
            else if (agent.includes('Analysis')) agentColor = 'text-amber-600 dark:text-amber-400';
            else if (agent.includes('Orchestrator')) agentColor = 'text-indigo-600 dark:text-sky-300';
            else if (agent.includes('Recon')) agentColor = 'text-teal-600 dark:text-teal-400';
            else agentColor = 'text-slate-500 dark:text-slate-400';

            // Message highlight formatting
            const isPhaseHeader = msg.startsWith('===');
            const isWarning = msg.includes('[!]') || msg.includes('FAIL') || msg.includes('ERROR');
            const isSuccess = msg.includes('[+]') || msg.includes('CONFIRMED') || msg.includes('PASS');

            let msgColor = 'text-slate-800 dark:text-slate-200';
            if (isPhaseHeader) {
              msgColor = 'text-blue-900 bg-blue-100/80 border border-blue-200 dark:text-cyan-300 dark:bg-cyan-950/30 dark:border-cyan-800/40 font-bold py-0.5 px-1.5 rounded block';
            } else if (isWarning) {
              msgColor = 'text-rose-700 dark:text-rose-300 font-semibold';
            } else if (isSuccess) {
              msgColor = 'text-emerald-700 dark:text-emerald-300 font-semibold';
            }

            return (
              <div
                key={log.seq || log.id || idx}
                className="leading-relaxed hover:bg-slate-200/50 dark:hover:bg-slate-900/60 px-1.5 py-0.5 rounded flex items-start gap-2"
              >
                <span className="text-slate-400 dark:text-slate-600 select-none font-mono flex-shrink-0 text-[11px]">
                  {formattedTime}
                </span>
                <span className={`font-bold ${agentColor} select-none flex-shrink-0 text-[11px]`}>
                  [{agent}]
                </span>
                <span className={`${msgColor} break-all flex-1`}>
                  {msg}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
