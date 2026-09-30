import React, { useState } from 'react';
import {
  ShieldCheck,
  HelpCircle,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Wrench,
  FileCode,
  ExternalLink,
} from 'lucide-react';

const SEVERITY_STYLES = {
  Critical: {
    border: 'border-l-red-500',
    badge: 'bg-red-500/20 text-red-300 border-red-500/40',
    dot: 'bg-red-500',
  },
  High: {
    border: 'border-l-rose-500',
    badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
    dot: 'bg-rose-500',
  },
  Medium: {
    border: 'border-l-yellow-500',
    badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
    dot: 'bg-yellow-500',
  },
  Low: {
    border: 'border-l-slate-500',
    badge: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
    dot: 'bg-slate-500',
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
      className={`bg-[#0f172a] border border-cyber-border border-l-4 ${sevStyle.border} rounded-xl overflow-hidden shadow-lg transition-all`}
    >
      {/* Header */}
      <div className="p-4 sm:p-5 bg-slate-900/60 border-b border-cyber-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs font-mono font-bold text-slate-400 bg-[#0b1120] border border-slate-700 px-2 py-0.5 rounded">
            {finding.id}
          </span>
          <h3 className="text-base font-bold text-white tracking-tight">
            {finding.title}
          </h3>

          {/* Severity Badge */}
          <span className={`text-[11px] font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${sevStyle.badge}`}>
            {finding.severity}
          </span>

          {/* Verification Status Badge */}
          {isConfirmed ? (
            <span className="flex items-center gap-1 text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>CONFIRMED</span>
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40">
              <HelpCircle className="w-3.5 h-3.5" />
              <span>UNVERIFIED</span>
            </span>
          )}

          {/* Confidence Badge */}
          <span className="text-[11px] font-semibold text-purple-300 bg-purple-500/10 border border-purple-500/30 px-2 py-0.5 rounded-full">
            {finding.confidence_pct}% Confidence
          </span>
        </div>

        <div className="flex items-center gap-3 self-end sm:self-center">
          <span className="text-xs font-bold text-slate-300 bg-slate-800/80 px-2.5 py-1 rounded-md border border-slate-700">
            CVSS: <span className="text-cyan-400 font-mono font-extrabold">{finding.cvss_score}</span>
          </span>
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition-colors"
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
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 bg-[#0b1120] p-3 rounded-lg border border-slate-800 text-xs">
            <div>
              <span className="text-slate-500 font-semibold block uppercase text-[10px]">Affected Component</span>
              <span className="font-mono text-cyan-300 break-all">{finding.affected_component || 'N/A'}</span>
            </div>
            <div>
              <span className="text-slate-500 font-semibold block uppercase text-[10px]">OWASP Category</span>
              <span className="text-slate-200">{finding.owasp_category || 'N/A'}</span>
            </div>
            <div>
              <span className="text-slate-500 font-semibold block uppercase text-[10px]">SIH Scope Class</span>
              <span className="text-indigo-300 font-semibold">{finding.sih_scope_category || 'N/A'}</span>
            </div>
            <div>
              <span className="text-slate-500 font-semibold block uppercase text-[10px]">Source Scanner</span>
              <span className="text-slate-300 font-mono">{finding.source_tool || 'N/A'}</span>
            </div>
          </div>

          {/* Description & Business Impact */}
          <div>
            <p className="text-sm text-slate-300 leading-relaxed mb-2.5">
              {finding.description}
            </p>
            {finding.business_impact && (
              <div className="p-3 rounded-lg bg-red-950/20 border border-red-500/20 text-xs">
                <span className="font-bold text-red-300 uppercase tracking-wide mr-1.5">Business Impact:</span>
                <span className="text-slate-300">{finding.business_impact}</span>
              </div>
            )}
          </div>

          {/* Steps to Reproduce */}
          {finding.steps_to_reproduce && finding.steps_to_reproduce.length > 0 && (
            <div className="text-xs">
              <span className="font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
                Steps to Reproduce
              </span>
              <ol className="list-decimal list-inside space-y-1 bg-[#0b1120] p-3 rounded-lg border border-slate-800 text-slate-300">
                {finding.steps_to_reproduce.map((step, idx) => (
                  <li key={idx} className="font-mono text-slate-300 leading-relaxed">
                    {step}
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* Remediation Guidance */}
          {finding.remediation && (
            <div className="bg-[#1e293b]/60 border border-slate-700 rounded-lg p-3.5 space-y-2">
              <div className="flex items-center gap-1.5 text-cyan-400 font-bold text-xs uppercase tracking-wide">
                <Wrench className="w-3.5 h-3.5" />
                <span>Actionable Remediation Guidance</span>
              </div>
              <p className="text-xs text-slate-300">
                <strong className="text-white">Mitigation: </strong> {finding.remediation.description}
              </p>
              <p className="text-xs text-slate-300">
                <strong className="text-white">Implementation Fix: </strong> {finding.remediation.fix}
              </p>

              {finding.remediation.example_code && (
                <div className="relative mt-2">
                  <div className="flex items-center justify-between text-[11px] text-slate-400 bg-[#090d16] px-3 py-1.5 rounded-t border-t border-x border-slate-800 font-mono">
                    <span className="flex items-center gap-1">
                      <FileCode className="w-3.5 h-3.5 text-cyan-400" /> Code / Configuration Fix
                    </span>
                    <button
                      onClick={() => copyCode(finding.remediation.example_code)}
                      className="text-slate-400 hover:text-white flex items-center gap-1"
                    >
                      {copiedCode ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedCode ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="bg-[#050811] p-3 rounded-b border border-slate-800 font-mono text-xs text-cyan-300 overflow-x-auto whitespace-pre-wrap break-all">
                    {finding.remediation.example_code}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* Confirmed PoC Evidence */}
          {finding.poc_evidence && (
            <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-lg p-3">
              <div className="flex items-center gap-1.5 text-emerald-400 font-bold text-xs uppercase tracking-wide mb-1.5">
                <ShieldCheck className="w-4 h-4" />
                <span>Verified Non-Destructive PoC Evidence</span>
              </div>
              <pre className="font-mono text-xs text-emerald-200 bg-[#061410] p-2.5 rounded border border-emerald-500/20 whitespace-pre-wrap break-all">
                {finding.poc_evidence}
              </pre>
            </div>
          )}

          {/* Raw Scanner Evidence */}
          {finding.evidence && finding.evidence.length > 0 && !finding.poc_evidence && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3">
              <span className="text-slate-400 font-bold text-xs uppercase tracking-wider block mb-1">
                Raw Scanner Evidence
              </span>
              <pre className="font-mono text-xs text-slate-400 bg-[#0b1120] p-2.5 rounded border border-slate-800 whitespace-pre-wrap break-all">
                {finding.evidence.join('\n')}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
