import React from 'react';
import { Download, FileText, ExternalLink, Search, Filter } from 'lucide-react';
import { getReportHtmlUrl, getReportPdfUrl } from '../api';

export default function ExportToolbar({
  jobId,
  searchQuery,
  onSearchChange,
  statusFilter,
  onStatusFilterChange,
  severityFilter,
  onSeverityFilterChange,
  totalFindings,
  displayedFindings,
}) {
  const htmlUrl = jobId ? getReportHtmlUrl(jobId) : '/report.html';
  const pdfUrl = jobId ? getReportPdfUrl(jobId) : '/report.pdf';
  const jsonUrl = jobId ? `/scan/${encodeURIComponent(jobId)}/report.json` : '/report.json';

  return (
    <div className="bg-[#0f172a] border border-cyber-border rounded-xl p-4 shadow-xl flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
      {/* Search and Filters */}
      <div className="flex-1 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search findings (title, component, OWASP, ID)..."
            className="w-full bg-[#0b1120] border border-slate-700 focus:border-cyan-500 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 transition-all"
          />
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1 bg-[#0b1120] p-1 rounded-lg border border-slate-700">
          {['all', 'confirmed', 'unverified'].map((st) => (
            <button
              key={st}
              onClick={() => onStatusFilterChange(st)}
              className={`px-2.5 py-1 rounded text-xs font-semibold capitalize transition-all ${
                statusFilter === st
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Severity Filter */}
        <select
          value={severityFilter}
          onChange={(e) => onSeverityFilterChange(e.target.value)}
          className="bg-[#0b1120] border border-slate-700 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:border-cyan-500 outline-none"
        >
          <option value="all">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        <span className="text-xs text-slate-500 font-mono whitespace-nowrap self-center">
          Showing {displayedFindings} of {totalFindings}
        </span>
      </div>

      {/* Deliverable Download Action Buttons */}
      <div className="flex items-center gap-2 flex-wrap">
        <a
          href={jsonUrl}
          download={`report_${jobId || 'latest'}.json`}
          className="flex items-center gap-1.5 text-xs font-bold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 px-3 py-1.5 rounded-lg transition-all shadow-sm"
        >
          <Download className="w-3.5 h-3.5 text-cyan-400" />
          <span>JSON</span>
        </a>

        <a
          href={pdfUrl}
          download={`secureassess_${jobId || 'latest'}.pdf`}
          className="flex items-center gap-1.5 text-xs font-bold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 px-3 py-1.5 rounded-lg transition-all shadow-sm"
        >
          <FileText className="w-3.5 h-3.5 text-rose-400" />
          <span>PDF Report</span>
        </a>

        <a
          href={htmlUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 text-xs font-bold text-cyan-300 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-500/40 hover:border-cyan-400 px-3 py-1.5 rounded-lg transition-all shadow-sm"
        >
          <ExternalLink className="w-3.5 h-3.5" />
          <span>Open Full HTML</span>
        </a>
      </div>
    </div>
  );
}
