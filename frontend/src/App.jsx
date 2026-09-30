import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import TargetConfig from './components/TargetConfig';
import PhaseStepper from './components/PhaseStepper';
import MetricCards from './components/MetricCards';
import LiveConsole from './components/LiveConsole';
import FindingCard from './components/FindingCard';
import ExportToolbar from './components/ExportToolbar';
import ResearchGapModal from './components/ResearchGapModal';
import { startScan, getScanStatus, getReportJson } from './api';

export default function App() {
  const [jobId, setJobId] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [currentPhase, setCurrentPhase] = useState('idle');
  const [currentTarget, setCurrentTarget] = useState('http://localhost:3000');
  const [currentMode, setCurrentMode] = useState('dast');
  const [logs, setLogs] = useState([]);
  const [summary, setSummary] = useState({
    total: 0,
    confirmed: 0,
    unverified: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  });
  const [findings, setFindings] = useState([]);
  const [error, setError] = useState(null);
  const [isResearchGapOpen, setIsResearchGapOpen] = useState(false);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');

  const pollTimerRef = useRef(null);
  const latestSeqRef = useRef(0);

  // On mount: attempt to load latest pre-existing report
  useEffect(() => {
    async function loadInitial() {
      try {
        const res = await fetch('/report.json');
        if (res.ok) {
          const data = await res.json();
          if (data.findings && data.findings.length > 0) {
            setFindings(data.findings);
            setSummary(data.metrics_summary || data.summary || summary);
            setCurrentPhase('completed');
            if (data.assessment_metadata) {
              setJobId(data.assessment_metadata.job_id);
              setCurrentTarget(data.assessment_metadata.target || 'http://localhost:3000');
              setCurrentMode((data.assessment_metadata.mode || 'dast').toLowerCase());
            }
          }
        }
      } catch (err) {
        // Normal if no scan has been run yet
      }
    }
    loadInitial();
  }, []);

  // Poll status while scanning
  useEffect(() => {
    if (!isScanning || !jobId) return;

    pollTimerRef.current = setInterval(async () => {
      try {
        const status = await getScanStatus(jobId, latestSeqRef.current);
        setCurrentPhase(status.phase);
        if (status.summary) {
          setSummary(status.summary);
        }

        if (status.log_tail && status.log_tail.length > 0) {
          setLogs((prev) => {
            const newLogs = [...prev, ...status.log_tail];
            latestSeqRef.current = Math.max(...newLogs.map((l) => l.seq || 0));
            return newLogs;
          });
        }

        if (status.phase === 'completed') {
          setIsScanning(false);
          clearInterval(pollTimerRef.current);
          // Fetch final enriched report
          const report = await getReportJson(jobId);
          setFindings(report.findings || []);
          if (report.metrics_summary) {
            setSummary(report.metrics_summary);
          }
        } else if (status.phase === 'failed') {
          setIsScanning(false);
          setError(status.error_message || 'Assessment pipeline failed.');
          clearInterval(pollTimerRef.current);
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 1500);

    return () => clearInterval(pollTimerRef.current);
  }, [isScanning, jobId]);

  const handleStartScan = async (target, mode) => {
    setError(null);
    setLogs([]);
    setFindings([]);
    latestSeqRef.current = 0;
    setCurrentTarget(target);
    setCurrentMode(mode);

    try {
      setIsScanning(true);
      setCurrentPhase('recon');
      const res = await startScan(target, mode);
      setJobId(res.job_id);
      setLogs([
        {
          seq: 1,
          timestamp: new Date().toISOString(),
          source_agent: 'Orchestrator',
          message: `Scan pipeline initiated for target: ${target} [Job ID: ${res.job_id}]`,
        },
      ]);
    } catch (err) {
      setIsScanning(false);
      setCurrentPhase('failed');
      setError(err.message || 'Failed to initiate scan pipeline.');
    }
  };

  // Filtered findings
  const filteredFindings = findings.filter((f) => {
    // Status filter
    if (statusFilter === 'confirmed' && (f.status || '').toLowerCase() !== 'confirmed') return false;
    if (statusFilter === 'unverified' && (f.status || '').toLowerCase() !== 'unverified') return false;

    // Severity filter
    if (severityFilter !== 'all' && (f.severity || '').toLowerCase() !== severityFilter.toLowerCase()) return false;

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = (f.id || '').toLowerCase().includes(q);
      const matchTitle = (f.title || '').toLowerCase().includes(q);
      const matchComp = (f.affected_component || '').toLowerCase().includes(q);
      const matchOwasp = (f.owasp_category || '').toLowerCase().includes(q);
      const matchScope = (f.sih_scope_category || '').toLowerCase().includes(q);
      return matchId || matchTitle || matchComp || matchOwasp || matchScope;
    }

    return true;
  });

  return (
    <div className="min-h-screen bg-[#0b1120] text-slate-100 flex flex-col">
      {/* Top Header */}
      <Header
        onOpenResearchGaps={() => setIsResearchGapOpen(true)}
        isScanning={isScanning}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Target Launch & Configuration Card */}
        <TargetConfig
          onStartScan={handleStartScan}
          isScanning={isScanning}
          currentTarget={currentTarget}
          currentMode={currentMode}
          error={error}
        />

        {/* 5-Agent Pipeline Stepper */}
        <PhaseStepper
          currentPhase={currentPhase}
          isFailed={currentPhase === 'failed'}
        />

        {/* Live Multi-Agent Log Console */}
        <LiveConsole
          logs={logs}
          isScanning={isScanning}
        />

        {/* 6 SUDARSHAN Summary Metric Counter Cards */}
        <MetricCards
          summary={summary}
          activeFilter={statusFilter !== 'all' ? statusFilter : severityFilter !== 'all' ? severityFilter.toLowerCase() : 'all'}
          onSelectFilter={(filterKey) => {
            if (filterKey === 'all') {
              setStatusFilter('all');
              setSeverityFilter('all');
            } else if (filterKey === 'confirmed' || filterKey === 'unverified') {
              setStatusFilter(filterKey);
              setSeverityFilter('all');
            } else {
              setStatusFilter('all');
              setSeverityFilter(filterKey.charAt(0).toUpperCase() + filterKey.slice(1));
            }
          }}
        />

        {/* Export & Filter Toolbar */}
        <ExportToolbar
          jobId={jobId}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          statusFilter={statusFilter}
          onStatusFilterChange={setStatusFilter}
          severityFilter={severityFilter}
          onSeverityFilterChange={setSeverityFilter}
          totalFindings={findings.length}
          displayedFindings={filteredFindings.length}
        />

        {/* Findings List */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <span>Detailed Vulnerability Findings</span>
              <span className="text-xs bg-slate-800 text-cyan-400 px-2 py-0.5 rounded-full border border-slate-700">
                {filteredFindings.length}
              </span>
            </h2>
          </div>

          {filteredFindings.length === 0 ? (
            <div className="bg-[#0f172a] border border-cyber-border rounded-xl p-12 text-center">
              <p className="text-slate-400 text-sm mb-1">
                {findings.length === 0
                  ? 'No vulnerability findings recorded yet. Launch a scan above to initiate assessment.'
                  : 'No findings match your active filter criteria.'}
              </p>
              {findings.length > 0 && (
                <button
                  onClick={() => {
                    setStatusFilter('all');
                    setSeverityFilter('all');
                    setSearchQuery('');
                  }}
                  className="mt-3 text-xs text-cyan-400 hover:underline"
                >
                  Clear all filters
                </button>
              )}
            </div>
          ) : (
            filteredFindings.map((finding) => (
              <FindingCard
                key={finding.id}
                finding={finding}
              />
            ))
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-cyber-border bg-[#0f172a]/60 py-4 mt-12 text-center text-xs text-slate-500">
        <p>
          SECUREASSESS — Smart India Hackathon 2026 | NTRO Problem Statement 26163 | Target: {currentTarget}
        </p>
      </footer>

      {/* Literature Research Gap Coverage Modal */}
      <ResearchGapModal
        isOpen={isResearchGapOpen}
        onClose={() => setIsResearchGapOpen(false)}
      />
    </div>
  );
}
