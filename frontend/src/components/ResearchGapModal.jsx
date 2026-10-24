import React from 'react';
import { X, BookOpen, CheckCircle, Shield } from 'lucide-react';

const RESEARCH_GAPS = [
  {
    citation: '#1 & #17 AutoPT (2024)',
    gap: 'Context Window Exhaustion & State Loss in Autonomous Agent Loops',
    solution: 'Per-job SQLite state machine isolating agent memory slices. Agents read only their required phase inputs, eliminating unbounded conversational token degradation.',
  },
  {
    citation: '#8 Peng et al. (2023)',
    gap: 'LLM Hallucination of False-Positive Exploits',
    solution: 'Hard evidence gating. Findings start as Unverified. Only findings with concrete, reproducible HTTP response proofs or validated AST traces are promoted to Confirmed.',
  },
  {
    citation: '#11 Deng et al. (PentestGPT 2023)',
    gap: 'Planning Loops & Dead-End Traps in Autonomous Pentesting',
    solution: 'Deterministic sequential 5-agent state machine (Recon → Scan → Analysis → Validation → Report). Prevents dynamic planners from getting trapped in infinite sub-goal loops.',
  },
  {
    citation: '#16 & #20 PTFusion (2024)',
    gap: 'Heterogeneous Output Schema Mismatches Across DAST/SAST Scanners',
    solution: '15-field Unified Finding Schema with deterministic tool-specific regex/AST parsers feeding a single unified LLM deduplication and normalization pass.',
  },
  {
    citation: '#13 & #19 Alazmi et al. (2023)',
    gap: 'Single-Scanner Vulnerability Detection Blind Spots',
    solution: 'Multi-tool dual-modality fusion: OWASP ZAP + Nikto for dynamic application traffic and Semgrep + Gitleaks for static source code analysis.',
  },
  {
    citation: '#4 EvoMaster (2021)',
    gap: 'Lack of Authorization / RBAC Policy Modeling',
    solution: 'Explicit classification of authorization/RBAC and authentication & session scope categories mapped directly to OWASP Top 10 and enterprise evaluation criteria.',
  },
  {
    citation: '#3 Kalopisis et al. (2024)',
    gap: 'Client-Side DOM Execution & Browser Event Blind Spot',
    solution: 'Client-side DOM XSS and sink taint-tracking covered via specialized Semgrep JS/TS rules; headless Playwright browser agent cataloged under Future Work roadmap.',
  },
];

export default function ResearchGapModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 dark:bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-cyber-border rounded-2xl max-w-4xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden transition-colors">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-200 dark:border-cyber-border flex items-center justify-between bg-slate-50 dark:bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-50 border border-blue-200 text-blue-600 dark:bg-cyan-500/10 dark:border-cyan-500/30 dark:text-cyan-400">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white tracking-tight">
                Research Gap Coverage Matrix
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Academic & Industry Grounding for Autonomous Security Assessment Platforms
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-white hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-3.5">
          {RESEARCH_GAPS.map((gap, idx) => (
            <div
              key={idx}
              className="bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800 rounded-xl p-4 hover:border-slate-300 dark:hover:border-slate-700 transition-colors"
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-mono font-bold text-blue-700 bg-blue-100 border border-blue-200 dark:text-cyan-400 dark:bg-cyan-500/10 dark:border-cyan-500/20 px-2 py-0.5 rounded">
                  {gap.citation}
                </span>
                <span className="flex items-center gap-1 text-[11px] font-bold text-emerald-600 dark:text-emerald-400">
                  <CheckCircle className="w-3.5 h-3.5" /> Resolved in Architecture
                </span>
              </div>
              <h4 className="text-sm font-bold text-slate-900 dark:text-slate-200 mb-1">
                {gap.gap}
              </h4>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                <strong className="text-slate-900 dark:text-slate-300 font-semibold">SECUREASSESS Solution: </strong>
                {gap.solution}
              </p>
            </div>
          ))}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-200 dark:border-cyber-border bg-slate-50 dark:bg-slate-900/60 flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-blue-600 dark:text-cyan-400" />
            <span>Autonomous Security Assessment & Compliance Framework</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-bold text-xs transition-colors shadow-xs"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
