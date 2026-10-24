import React, { useState } from 'react';
import {
  ShieldCheck,
  HelpCircle,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Wrench,
  FileCode,
} from 'lucide-react';

const SEVERITY_STYLES = {
  Critical: {
    border: 'border-l-red-500',
    badge: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-500/20 dark:text-red-300 dark:border-red-500/40',
  },
  High: {
    border: 'border-l-rose-500',
    badge: 'bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-500/20 dark:text-rose-300 dark:border-rose-500/40',
  },
  Medium: {
    border: 'border-l-yellow-500',
    badge: 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-yellow-500/20 dark:text-yellow-300 dark:border-yellow-500/40',
  },
  Low: {
    border: 'border-l-blue-500 dark:border-l-slate-500',
    badge: 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-slate-500/20 dark:text-slate-300 dark:border-slate-500/40',
  },
};

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(true);
  const [copiedCode, setCopiedCode] = useState(false);

  const sevStyle = SEVERITY_STYLES[finding.severity] || SEVERITY_STYLES.Medium;
  const isConfirmed = (finding.status || '').toLowerCase() === 'confirmed';

  const copyCode = (code) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div
      className={`bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-cyber-border border-l-4 ${sevStyle.border} rounded-xl overflow-hidden shadow-sm dark:shadow-lg transition-colors duration-200`}
    >
      {/* Header */}
      <div className="p-4 sm:p-5 bg-slate-50/70 dark:bg-slate-900/60 border-b border-slate-200 dark:border-cyber-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs font-mono font-bold text-slate-700 bg-white border border-slate-300 dark:text-slate-400 dark:bg-[#0b1120] dark:border-slate-700 px-2 py-0.5 rounded shadow-2xs">
            {finding.id}
          </span>
          <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">
            {finding.title}
          </h3>

          {/* Severity Badge */}
          <span className={`text-[11px] font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${sevStyle.badge}`}>
            {finding.severity}
          </span>

          {/* Verification Status Badge */}
          {isConfirmed ? (
            <span className="flex items-center gap-1 text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300 dark:bg-emerald-500/20 dark:text-emerald-300 dark:border-emerald-500/40">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>CONFIRMED</span>
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-300 dark:bg-amber-500/20 dark:text-amber-300 dark:border-amber-500/40">
              <HelpCircle className="w-3.5 h-3.5" />
              <span>UNVERIFIED</span>
            </span>
          )}

          {/* Confidence Badge */}
          <span className="text-[11px] font-semibold text-purple-800 bg-purple-100 border border-purple-300 dark:text-purple-300 dark:bg-purple-500/10 dark:border-purple-500/30 px-2.5 py-0.5 rounded-full">
            Confidence: {finding.confidence_pct}%
          </span>
        </div>

        <div className="flex items-center gap-3 self-end sm:self-center">
          <span className="text-xs font-bold text-slate-700 bg-white border border-slate-300 dark:text-slate-300 dark:bg-slate-800/80 dark:border-slate-700 px-2.5 py-1 rounded-md shadow-2xs">
            CVSS: <span className="text-blue-600 dark:text-cyan-400 font-mono font-extrabold">{finding.cvss_score}</span>
          </span>
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1 text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white rounded hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors cursor-pointer"
            title={expanded ? 'Collapse' : 'Expand'}
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Expanded Details Body */}
      {expanded && (
        <div className="p-4 sm:p-5 space-y-4">
          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 bg-slate-50 dark:bg-[#0b1120] p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 text-xs">
            <div>
              <span className="text-slate-500 dark:text-slate-500 font-semibold block uppercase text-[10px]">Affected Component</span>
              <span className="font-mono text-blue-600 dark:text-cyan-300 break-all font-medium">{finding.affected_component || 'N/A'}</span>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-500 font-semibold block uppercase text-[10px]">OWASP Category</span>
              <span className="text-slate-800 dark:text-slate-200 font-medium">{finding.owasp_category || 'N/A'}</span>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-500 font-semibold block uppercase text-[10px]">SIH Scope Class</span>
              <span className="text-slate-800 dark:text-indigo-300 font-medium">{finding.sih_scope_category || 'N/A'}</span>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-500 font-semibold block uppercase text-[10px]">Source Scanner</span>
              <span className="text-slate-700 dark:text-slate-300 font-mono font-medium">{finding.source_tool || 'N/A'}</span>
            </div>
          </div>

          {/* Description & Business Impact */}
          <div className="space-y-2.5">
            <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
              {finding.description}
            </p>
            {finding.business_impact && (
              <div className="p-3 rounded-lg bg-rose-50/70 border border-rose-200 dark:bg-red-950/20 dark:border-red-500/20 text-xs text-slate-800 dark:text-slate-300">
                <span className="font-bold text-rose-700 dark:text-red-300 uppercase tracking-wide mr-1.5">Business Impact:</span>
                <span>{finding.business_impact}</span>
              </div>
            )}
          </div>

          {/* Steps to Reproduce */}
          {finding.steps_to_reproduce && finding.steps_to_reproduce.length > 0 && (
            <div className="text-xs">
              <span className="font-bold text-slate-700 dark:text-slate-400 uppercase tracking-wider block mb-1.5">
                Steps to Reproduce
              </span>
              <ol className="list-decimal list-inside space-y-1 bg-slate-50 dark:bg-[#0b1120] p-3 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 font-mono">
                {finding.steps_to_reproduce.map((step, idx) => (
                  <li key={idx} className="leading-relaxed">
                    {step}
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* Remediation Guidance */}
          {finding.remediation && (
            <div className="bg-emerald-50/60 border border-emerald-300 dark:bg-[#1e293b]/60 dark:border-slate-700 rounded-xl p-4 space-y-2.5 transition-colors">
              <div className="flex items-center gap-1.5 text-emerald-800 dark:text-cyan-400 font-bold text-xs uppercase tracking-wide">
                <Wrench className="w-4 h-4 text-emerald-600 dark:text-cyan-400" />
                <span>Remediation Guidance</span>
              </div>
              <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                <strong className="text-slate-900 dark:text-white font-semibold">Overview: </strong> {finding.remediation.description}
              </p>
              <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                <strong className="text-slate-900 dark:text-white font-semibold">Actionable Fix: </strong> {finding.remediation.fix}
              </p>

              {finding.remediation.example_code && (
                <div className="relative mt-2">
                  <div className="flex items-center justify-between text-[11px] text-emerald-900 dark:text-slate-400 bg-emerald-100/70 dark:bg-[#090d16] px-3 py-1.5 rounded-t border-t border-x border-emerald-200 dark:border-slate-800 font-mono font-medium">
                    <span className="flex items-center gap-1">
                      <FileCode className="w-3.5 h-3.5 text-emerald-700 dark:text-cyan-400" /> Code / Configuration Fix
                    </span>
                    <button
                      onClick={() => copyCode(finding.remediation.example_code)}
                      className="text-emerald-700 hover:text-emerald-900 dark:text-slate-400 dark:hover:text-white flex items-center gap-1 font-semibold cursor-pointer"
                    >
                      {copiedCode ? <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedCode ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="bg-emerald-50 dark:bg-[#050811] p-3 rounded-b border border-emerald-200 dark:border-slate-800 font-mono text-xs text-emerald-950 dark:text-cyan-300 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                    {finding.remediation.example_code}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* Confirmed PoC Evidence */}
          {finding.poc_evidence && (
            <div className="bg-sky-50/50 border border-sky-300 dark:bg-emerald-950/20 dark:border-emerald-500/30 rounded-xl p-4 transition-colors">
              <div className="flex items-center gap-1.5 text-teal-800 dark:text-emerald-400 font-bold text-xs uppercase tracking-wide mb-2">
                <ShieldCheck className="w-4 h-4 text-teal-600 dark:text-emerald-400" />
                <span>Verified PoC Evidence:</span>
              </div>
              <pre className="font-mono text-xs text-slate-800 dark:text-emerald-200 bg-white/90 dark:bg-[#061410] p-3 rounded-lg border border-sky-200 dark:border-emerald-500/20 whitespace-pre-wrap break-all leading-relaxed shadow-2xs">
                {finding.poc_evidence}
              </pre>
            </div>
          )}

          {/* Raw Scanner Evidence */}
          {finding.evidence && finding.evidence.length > 0 && (
            <div className="bg-slate-100/80 border border-slate-200 dark:bg-slate-900/60 dark:border-slate-800 rounded-xl p-4 transition-colors">
              <span className="text-slate-600 dark:text-slate-400 font-bold text-xs uppercase tracking-wider block mb-1.5">
                Raw Scanner Evidence:
              </span>
              <pre className="font-mono text-xs text-slate-700 dark:text-slate-400 bg-white/80 dark:bg-[#0b1120] p-3 rounded-lg border border-slate-200 dark:border-slate-800 whitespace-pre-wrap break-all leading-relaxed">
                {finding.evidence.join('\n')}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
