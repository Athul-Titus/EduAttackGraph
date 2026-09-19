import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('eduattack_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ─── Types ──────────────────────────────────────────────────────────────────

export interface Target {
  id: string;
  hostname: string;
  ip_address?: string;
  description?: string;
  authorized: boolean;
  authorization_note?: string;
  created_at: string;
}

export interface Scan {
  id: string;
  target_id: string;
  status: 'pending' | 'running' | 'fingerprinting' | 'analyzing' | 'completed' | 'failed' | 'cancelled';
  notes?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  embedding_model?: string;
  similarity_threshold?: number;
  top_k?: number;
  llm_provider?: string;
  llm_model?: string;
  prompt_version?: string;
  error_message?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  analysis_id: string;
  title: string;
  category?: string;
  severity?: string;
  description?: string;
  affected_components?: string[];
  remediation?: string[];
  status: string;
  evidence_type: string;
  created_at: string;
  updated_at?: string;
}

export interface ScanResult {
  scan_id: string;
  status: string;
  target?: string;
  started_at?: string;
  completed_at?: string;
  fingerprint?: {
    web_framework?: string;
    server_software?: string;
    technologies?: string[];
    text_representation?: string;
    evidence_type: string;
  };
  retrieval?: {
    max_similarity?: number;
    threshold?: number;
    threshold_passed: boolean;
    top_k?: number;
    results?: RetrievalResult[];
    evidence_type: string;
  };
  analysis?: {
    llm_provider?: string;
    llm_model?: string;
    potential_vulnerability?: string;
    category?: string;
    severity?: string;
    analysis_text?: string;
    remediation_steps?: string[];
    uncertainty_statement?: string;
    evidence_type: string;
    validation_required: boolean;
  };
  findings?: Array<{
    id: string;
    title: string;
    category?: string;
    severity?: string;
    status: string;
    evidence_type: string;
  }>;
  error?: string;
}

export interface RetrievalResult {
  chunk_id: string;
  source: string;
  title?: string;
  technology?: string;
  similarity_score: number;
  evidence_type: string;
}

export interface HealthStatus {
  status: string;
  version: string;
  app_env: string;
  embedding_model: string;
  similarity_threshold: number;
  top_k: number;
  llm_provider: string;
  knowledge_base_ready: boolean;
  faiss_index_ready: boolean;
  demo_mode: boolean;
  faiss_num_vectors: number;
}

export interface DemoResult {
  _demo_mode: boolean;
  _warning: string;
  pipeline_stages: {
    stage_1_fingerprinting: Record<string, unknown>;
    stage_2_rag: Record<string, unknown>;
    stage_2_llm: Record<string, unknown>;
  };
  finding: Record<string, unknown>;
}

// ─── API Calls ───────────────────────────────────────────────────────────────

export const apiClient = {
  // Health
  getHealth: () => api.get<HealthStatus>('/api/health').then(r => r.data),
  getConfig: () => api.get('/api/config').then(r => r.data),

  // Auth
  login: (data: { email: string; password: string }) =>
    api.post<{ access_token: string; token_type: string; user: { id: string; email: string; role: string } }>('/api/v1/auth/login', data).then(r => r.data),
  getMe: () =>
    api.get<{ id: string; email: string; role: string }>('/api/v1/auth/me').then(r => r.data),

  // Targets
  listTargets: () => api.get<Target[]>('/api/v1/targets/').then(r => r.data),
  createTarget: (data: { hostname: string; description?: string; authorization_note?: string }) =>
    api.post<Target>('/api/v1/targets/', data).then(r => r.data),
  deleteTarget: (id: string) => api.delete(`/api/v1/targets/${id}`),
  toggleTargetAuth: (id: string) => api.patch<Target>(`/api/v1/targets/${id}/toggle-auth`).then(r => r.data),

  // Scans
  listScans: (targetId?: string) => {
    const params = targetId ? { target_id: targetId } : {};
    return api.get<{ scans: Scan[]; total: number }>('/api/v1/scans/', { params }).then(r => r.data);
  },
  createScan: (data: { target_id: string; notes?: string }) =>
    api.post<Scan>('/api/v1/scans/', data).then(r => r.data),
  getScan: (id: string) => api.get<Scan>(`/api/v1/scans/${id}`).then(r => r.data),
  getScanResult: (id: string) => api.get<ScanResult>(`/api/v1/scans/${id}/result`).then(r => r.data),

  // Findings
  listFindings: (scanId?: string, status?: string) => {
    const params: Record<string, string> = {};
    if (scanId) params.scan_id = scanId;
    if (status) params.status = status;
    return api.get<Finding[]>('/api/v1/findings/', { params }).then(r => r.data);
  },
  submitForReview: (findingId: string) =>
    api.post(`/api/v1/findings/${findingId}/submit-for-review`).then(r => r.data),
  validateFinding: (findingId: string, action: 'accept' | 'reject' | 'needs-more-evidence', payload: { reviewer: string; comment?: string }) =>
    api.post(`/api/v1/findings/${findingId}/validate/${action}`, payload).then(r => r.data),

  // Reports
  generateReport: (scanId: string, format: 'json' | 'markdown' = 'json') =>
    api.post(`/api/v1/reports/${scanId}/generate`, null, { params: { format } }).then(r => r.data),

  // Demo
  getDemoInfo: () => api.get('/api/v1/demo/').then(r => r.data),
  runDemo: () => api.post<DemoResult>('/api/v1/demo/run').then(r => r.data),
  getDemoFingerprint: () => api.get('/api/v1/demo/fingerprint').then(r => r.data),
  getDemoKB: () => api.get('/api/v1/demo/knowledge-base').then(r => r.data),
  getVulnCategories: () => api.get('/api/v1/demo/vulnerability-categories').then(r => r.data),
};
