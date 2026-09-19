import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import { Scan as ScanIcon, Play, RefreshCw, AlertTriangle, ChevronRight } from 'lucide-react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';

export default function NewScan() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const defaultTarget = params.get('target') || '';

  const [targetId, setTargetId] = useState(defaultTarget);
  const [notes, setNotes] = useState('');
  const [error, setError] = useState('');

  const { data: targets = [] } = useQuery({ queryKey: ['targets'], queryFn: apiClient.listTargets });
  const { data: scansData, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => apiClient.listScans(),
    refetchInterval: 5000,
  });
  const scans = scansData?.scans ?? [];

  const createMutation = useMutation({
    mutationFn: apiClient.createScan,
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      navigate(`/scans/${scan.id}`);
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Failed to start scan';
      setError(msg);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetId) { setError('Select a target'); return; }
    setError('');
    createMutation.mutate({ target_id: targetId, notes: notes.trim() || undefined });
  };

  return (
    <div className="page animate-fade-in">
      <div className="page-header">
        <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ScanIcon size={24} color="var(--accent-blue)" /> Scans
        </h1>
        <p className="page-subtitle">Stage 1 (Fingerprinting) + Stage 2 (LLM Analysis) pipeline</p>
      </div>

      <div className="grid-2" style={{ gap: 24, alignItems: 'start' }}>
        {/* New scan form */}
        <div className="card">
          <div className="section-header">
            <Play size={16} color="var(--accent-green)" />
            <span className="section-title">New Scan</span>
          </div>
          <div className="alert alert-warning" style={{ marginBottom: 16 }}>
            <AlertTriangle size={14} />
            <div>
              <strong>Authorization required.</strong> Only targets you are explicitly authorized to scan.
              The LLM output will be <strong>INFERRED</strong> — not a confirmed vulnerability.
            </div>
          </div>
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, display: 'block', marginBottom: 6 }}>
                Authorized Target *
              </label>
              {targets.length === 0 ? (
                <div className="alert alert-info">
                  <span>No targets registered. <Link to="/targets" style={{ color: 'var(--accent-blue)' }}>Register one first →</Link></span>
                </div>
              ) : (
                <select
                  className="input"
                  value={targetId}
                  onChange={e => setTargetId(e.target.value)}
                  style={{ cursor: 'pointer' }}
                >
                  <option value="">Select a target…</option>
                  {targets.map(t => (
                    <option key={t.id} value={t.id}>{t.hostname} {t.description ? `— ${t.description}` : ''}</option>
                  ))}
                </select>
              )}
            </div>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, display: 'block', marginBottom: 6 }}>
                Notes (optional)
              </label>
              <input
                className="input"
                value={notes}
                onChange={e => setNotes(e.target.value)}
                placeholder="e.g. Testing after upgrade"
              />
            </div>
            {error && <div className="alert alert-danger"><AlertTriangle size={14} /> {error}</div>}
            <button
              type="submit"
              className="btn btn-primary"
              disabled={createMutation.isPending || targets.length === 0}
            >
              <Play size={14} />
              {createMutation.isPending ? 'Launching…' : 'Start Scan'}
            </button>
          </form>

          <div className="divider" />

          {/* Pipeline overview */}
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 12, textTransform: 'uppercase', letterSpacing: 0.8 }}>
              Pipeline (Algorithm 1 + 2)
            </div>
            <PipelineStep num="1" title="Fingerprinting" desc="Port scan → Service identification → Web fingerprinting" color="var(--accent-cyan)" evidence="OBSERVED" />
            <PipelineStep num="2" title="RAG Retrieval" desc="BGE-m3 embedding → FAISS search → Cosine similarity ≥ 0.6" color="var(--accent-purple)" evidence="RETRIEVED" />
            <PipelineStep num="3" title="LLM Analysis" desc="DeepSeek prompt: Φ(T₂) ⊕ Ψ(T) ⊕ Γ → INFERRED output" color="var(--accent-yellow)" evidence="INFERRED" />
            <PipelineStep num="4" title="Human Validation" desc="Analyst reviews → VALIDATED / REJECTED" color="var(--accent-green)" evidence="VALIDATED" last />
          </div>
        </div>

        {/* Recent scans list */}
        <div className="card">
          <div className="section-header">
            <RefreshCw size={16} color="var(--accent-blue)" />
            <span className="section-title">Recent Scans</span>
          </div>
          {isLoading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[1,2,3,4].map(i => <div key={i} className="skeleton" style={{ height: 64 }} />)}
            </div>
          ) : scans.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)', fontSize: 13 }}>
              No scans yet. Start your first scan.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {scans.map(scan => {
                const target = targets.find(t => t.id === scan.target_id);
                return (
                  <Link key={scan.id} to={`/scans/${scan.id}`} style={{ textDecoration: 'none' }}>
                    <div style={{
                      background: 'var(--bg-input)', borderRadius: 10,
                      padding: '12px 14px', border: '1px solid var(--border)',
                      display: 'flex', alignItems: 'center', gap: 12,
                      transition: 'border-color 0.15s',
                    }}
                    onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--border-accent)')}
                    onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
                    >
                      <div className={`status-dot status-dot-${scan.status}`} style={{ flexShrink: 0 }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace' }}>
                          {target?.hostname || scan.target_id.slice(0, 12)}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {new Date(scan.created_at).toLocaleString()} · {scan.llm_provider || 'mock'}
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 11, color: statusColor(scan.status), fontWeight: 600, textTransform: 'uppercase' }}>
                          {scan.status}
                        </span>
                        <ChevronRight size={14} color="var(--text-muted)" />
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function PipelineStep({ num, title, desc, color, evidence, last = false }: {
  num: string; title: string; desc: string; color: string; evidence: string; last?: boolean
}) {
  return (
    <div style={{ display: 'flex', gap: 12, marginBottom: last ? 0 : 14 }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <div style={{
          width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
          background: `${color}20`, border: `1px solid ${color}60`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 11, fontWeight: 700, color,
        }}>{num}</div>
        {!last && <div style={{ width: 1, flex: 1, background: 'var(--border)', marginTop: 4 }} />}
      </div>
      <div style={{ paddingBottom: last ? 0 : 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{title}</span>
          <span className={`badge badge-${evidence.toLowerCase()}`}>{evidence}</span>
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{desc}</div>
      </div>
    </div>
  );
}

function statusColor(status: string) {
  const m: Record<string, string> = {
    pending: 'var(--text-muted)', running: 'var(--accent-blue)',
    fingerprinting: 'var(--accent-cyan)', analyzing: 'var(--accent-purple)',
    completed: 'var(--accent-green)', failed: 'var(--accent-red)', cancelled: 'var(--text-muted)',
  };
  return m[status] || 'var(--text-muted)';
}
