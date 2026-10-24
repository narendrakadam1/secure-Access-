import React from 'react';
import { Download, FileText, ExternalLink, Search } from 'lucide-react';
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
    <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-cyber-border rounded-xl p-4 shadow-sm dark:shadow-xl flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4 transition-colors duration-200">
      {/* Search and Filters */}
      <div className="flex-1 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search findings (title, component, OWASP, ID)..."
            className="w-full bg-slate-50 dark:bg-[#0b1120] border border-slate-300 dark:border-slate-700 focus:border-blue-500 dark:focus:border-cyan-500 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 transition-all shadow-xs"
          />
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1 bg-slate-100 dark:bg-[#0b1120] p-1 rounded-lg border border-slate-200 dark:border-slate-700">
          {['all', 'confirmed', 'unverified'].map((st) => (
            <button
              key={st}
              onClick={() => onStatusFilterChange(st)}
              className={`px-3 py-1 rounded-md text-xs font-semibold capitalize transition-all ${
                statusFilter === st
                  ? 'bg-blue-600 dark:bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
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
          className="bg-slate-50 dark:bg-[#0b1120] border border-slate-300 dark:border-slate-700 text-xs text-slate-800 dark:text-slate-300 rounded-lg px-2.5 py-1.5 focus:border-blue-500 dark:focus:border-cyan-500 outline-none shadow-xs font-medium"
        >
          <option value="all">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        <span className="text-xs text-slate-500 font-mono whitespace-nowrap self-center font-medium">
          Showing {displayedFindings} of {totalFindings}
        </span>
      </div>

      {/* Deliverable Download Action Buttons */}
      <div className="flex items-center gap-2 flex-wrap">
        <a
          href={jsonUrl}
          download={`report_${jobId || 'latest'}.json`}
          className="flex items-center gap-1.5 text-xs font-bold text-sky-800 bg-sky-50 hover:bg-sky-100 border border-sky-300 dark:text-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 dark:border-slate-700 px-3 py-1.5 rounded-lg transition-all shadow-xs"
        >
          <Download className="w-3.5 h-3.5 text-sky-600 dark:text-cyan-400" />
          <span>JSON</span>
        </a>

        <a
          href={pdfUrl}
          download={`secureassess_${jobId || 'latest'}.pdf`}
          className="flex items-center gap-1.5 text-xs font-bold text-rose-800 bg-rose-50 hover:bg-rose-100 border border-rose-300 dark:text-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 dark:border-slate-700 px-3 py-1.5 rounded-lg transition-all shadow-xs"
        >
          <FileText className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />
          <span>PDF Report</span>
        </a>

        <a
          href={htmlUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 text-xs font-bold text-emerald-800 bg-emerald-50 hover:bg-emerald-100 border border-emerald-300 dark:text-cyan-300 dark:bg-cyan-950/60 dark:hover:bg-cyan-900/60 dark:border-cyan-500/40 px-3 py-1.5 rounded-lg transition-all shadow-xs"
        >
          <ExternalLink className="w-3.5 h-3.5 text-emerald-600 dark:text-cyan-300" />
          <span>Open Full HTML</span>
        </a>
      </div>
    </div>
  );
}
