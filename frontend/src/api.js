/**
 * SECUREASSESS - Frontend API Client
 * Interfaces with FastAPI orchestrator endpoints
 */

const API_BASE = import.meta.env.VITE_API_URL || '';

export async function checkHealth() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
}

export async function getModels() {
  const res = await fetch(`${API_BASE}/models`);
  if (!res.ok) throw new Error(`Failed to fetch models: ${res.statusText}`);
  return res.json();
}

export async function selectModel(model, cloudApiKey = null) {
  const res = await fetch(`${API_BASE}/models/select`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, cloud_api_key: cloudApiKey }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to select model (${res.status})`);
  }
  return res.json();
}

export async function startScan(target, mode = 'dast', model = null) {
  const payload = { target, mode };
  if (model) payload.model = model;
  const res = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    const message = errorData.detail || `Scan initiation failed (${res.status})`;
    throw new Error(message);
  }
  return res.json();
}

export async function cancelScan(jobId) {
  const res = await fetch(`${API_BASE}/scan/${encodeURIComponent(jobId)}/cancel`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to cancel scan (${res.status})`);
  }
  return res.json();
}

export async function getScanStatus(jobId, sinceSeq = 0) {
  const res = await fetch(`${API_BASE}/scan/${encodeURIComponent(jobId)}/status?since_seq=${sinceSeq}`);
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch status (${res.status})`);
  }
  return res.json();
}

export async function getReportJson(jobId) {
  const res = await fetch(`${API_BASE}/scan/${encodeURIComponent(jobId)}/report.json`);
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch report JSON (${res.status})`);
  }
  return res.json();
}

export function getReportHtmlUrl(jobId) {
  return `${API_BASE}/scan/${encodeURIComponent(jobId)}/report.html`;
}

export function getReportPdfUrl(jobId) {
  return `${API_BASE}/scan/${encodeURIComponent(jobId)}/report.pdf`;
}
