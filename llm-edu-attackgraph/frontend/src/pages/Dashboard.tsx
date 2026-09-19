import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import { Shield, Activity, Cpu, Database, AlertTriangle, CheckCircle2, Clock, RefreshCw } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Dashboard() {
  const { data: health, isLoading: hLoading, refetch: refetchHealth } = useQuery({
    queryKey: ['health'],
    queryFn: apiClient.getHealth,
    refetchInterval: 15000,
  });
  const { data: scansData, isLoading: sLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => apiClient.listScans(),
    refetchInterval: 10000,
  });
  const { data: findings, isLoading: fLoading } = useQuery({
    queryKey: ['findings'],
    queryFn: () => apiClient.listFindings(),
  });
  const { data: targets } = useQuery({ queryKey: ['targets'], queryFn: apiClient.listTargets });
  const { data: vulnCats } = useQuery({ queryKey: ['vulnCats'], queryFn: apiClient.getVulnCategories });

  const scans = scansData?.scans ?? [];
  const activeScans = scans.filter(s => ['running', 'fingerprinting', 'analyzing'].includes(s.status));
  const completedScans = scans.filter(s => s.status === 'completed');
  const potentialFindings = (findings ?? []).filter(f => f.status === 'potential');
  const pendingReview = (findings ?? []).filter(f => f.status === 'pending_review');
  const validated = (findings ?? []).filter(f => f.status === 'validated');

  return (
    <div className="page animate-fade-in">
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Shield size={26} color="var(--accent-blue)" />
            LLM-EduAttackGraph
          </h1>
          <p className="page-subtitle">Security Vulnerability Analysis for Educational Websites</p>
          <div style={{ marginTop: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              📄 Liu et al., IEEE Internet of Things Journal, 2026
            </span>
          </div>
        </div>
        <button className="btn btn-secondary" onClick={() => refetchHealth()} style={{ marginTop: 8 }}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* System health status */}
      <div className="disclaimer-bar" style={{ marginBottom: 20 }}>
        <AlertTriangle size={14} />
        <span>
          This is a <strong>research tool</strong>. All LLM outputs are <strong>INFERRED</strong> — not confirmed vulnerabilities.
          Human validation is required before acting on any finding.
        </span>
      </div>

      {/* Health banner */}
      {health && (
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)',
          padding: '14px 20px',
          marginBottom: 20,
          display: 'flex',
          alignItems: 'center',
          gap: 20,
          flexWrap: 'wrap',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-green)' }} />
            <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>System Online</span>
          </div>
          <StatusChip label="LLM" value={health.llm_provider} ok={true} />
          <StatusChip label="Embedding" value={health.embedding_model.split('/').pop() || health.embedding_model} ok={true} />
          <StatusChip label="FAISS Index" value={health.faiss_index_ready ? `${health.faiss_num_vectors} vectors` : 'NOT BUILT'} ok={health.faiss_index_ready} />
          <StatusChip label="Threshold" value={`${health.similarity_threshold} (paper)`} ok={true} />
          {health.demo_mode && <span className="badge badge-demo">DEMO MODE</span>}
        </div>
      )}

      {/* Stats grid */}
      <div className="grid-4" style={{ marginBottom: 24 }}>
        <StatCard icon={<Activity size={20} color="var(--accent-blue)" />} label="Total Scans" value={scans.length} sub={`${activeScans.length} active`} color="var(--accent-blue)" loading={sLoading} />
        <StatCard icon={<CheckCircle2 size={20} color="var(--accent-green)" />} label="Completed" value={completedScans.length} sub="scans finished" color="var(--accent-green)" loading={sLoading} />
        <StatCard icon={<AlertTriangle size={20} color="var(--accent-yellow)" />} label="Findings" value={(findings ?? []).length} sub={`${potentialFindings.length} potential`} color="var(--accent-yellow)" loading={fLoading} />
        <StatCard icon={<Database size={20} color="var(--accent-cyan)" />} label="Targets" value={targets?.length ?? 0} sub="authorized" color="var(--accent-cyan)" />
      </div>

      {/* Two column layout */}
      <div className="grid-2" style={{ gap: 20, marginBottom: 24 }}>
        {/* Recent Scans */}
        <div className="card">
          <div className="section-header">
            <Activity size={16} color="var(--accent-blue)" />
            <span className="section-title">Recent Scans</span>
            <Link to="/scans" style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--accent-blue)' }}>New scan →</Link>
          </div>
          {sLoading ? <SkeletonList n={3} /> : scans.length === 0 ? (
            <Empty message="No scans yet" cta="Start your first scan" to="/scans" />
          ) : (
            <div>
              {scans.slice(0, 6).map(scan => (
                <Link to={`/scans/${scan.id}`} key={scan.id} style={{ textDecoration: 'none' }}>
                  <div style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '10px 0', borderBottom: '1px solid var(--border)',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div className={`status-dot status-dot-${scan.status}`} />
                      <div>
                        <div style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>
                          {scan.id.slice(0, 8)}…
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {new Date(scan.created_at).toLocaleString()}
                        </div>
                      </div>
                    </div>
                    <ScanStatusBadge status={scan.status} />
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Findings queue */}
        <div className="card">
          <div className="section-header">
            <AlertTriangle size={16} color="var(--accent-yellow)" />
            <span className="section-title">Findings Queue</span>
            <Link to="/findings" style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--accent-blue)' }}>View all →</Link>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 }}>
            <QueueItem label="Potential (INFERRED)" count={potentialFindings.length} color="var(--accent-yellow)" />
            <QueueItem label="Pending Review" count={pendingReview.length} color="var(--accent-blue)" />
            <QueueItem label="Validated" count={validated.length} color="var(--accent-green)" />
            <QueueItem label="Rejected" count={(findings ?? []).filter(f => f.status === 'rejected').length} color="var(--accent-red)" />
          </div>
          {fLoading ? <SkeletonList n={2} /> : (findings ?? []).length === 0 && (
            <Empty message="No findings yet" cta="Run a scan" to="/scans" />
          )}
        </div>
      </div>

      {/* Vulnerability categories from paper */}
      {vulnCats && (
        <div className="card">
          <div className="section-header">
            <Cpu size={16} color="var(--accent-purple)" />
            <span className="section-title">Vulnerability Categories</span>
            <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>
              From research paper — {vulnCats.total_vulnerabilities_in_paper} vulnerabilities analyzed
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
            {vulnCats.categories.map((cat: { code: string; name: string; paper_prevalence: string; count: number }) => (
              <div key={cat.code} style={{
                background: 'var(--bg-input)', borderRadius: 10,
                padding: '12px 14px', border: '1px solid var(--border)',
              }}>
                <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)', marginBottom: 4 }}>
                  {cat.code}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 600, marginBottom: 2 }}>
                  {cat.name}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {cat.paper_prevalence} ({cat.count} cases)
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ icon, label, value, sub, color, loading }: { icon: React.ReactNode; label: string; value: number; sub: string; color: string; loading?: boolean }) {
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ padding: 10, background: `${color}18`, borderRadius: 10 }}>{icon}</div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>{label}</span>
      </div>
      {loading ? (
        <div className="skeleton" style={{ height: 36, width: '60%' }} />
      ) : (
        <>
          <div style={{ fontSize: 32, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1 }}>{value}</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{sub}</div>
        </>
      )}
    </div>
  );
}

function StatusChip({ label, value, ok }: { label: string; value: string; ok: boolean }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>{label}:</span>
      <span style={{ fontSize: 11, color: ok ? 'var(--accent-cyan)' : 'var(--accent-red)', fontFamily: 'JetBrains Mono, monospace' }}>
        {value}
      </span>
    </div>
  );
}

function QueueItem({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0' }}>
      <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{label}</span>
      <span style={{
        fontSize: 13, fontWeight: 700, color,
        background: `${color}18`, padding: '2px 10px', borderRadius: 100,
        border: `1px solid ${color}30`,
      }}>{count}</span>
    </div>
  );
}

function ScanStatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    pending: 'var(--text-muted)', running: 'var(--accent-blue)',
    fingerprinting: 'var(--accent-cyan)', analyzing: 'var(--accent-purple)',
    completed: 'var(--accent-green)', failed: 'var(--accent-red)', cancelled: 'var(--text-muted)',
  };
  const c = colors[status] || 'var(--text-muted)';
  return (
    <span style={{ fontSize: 11, color: c, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>
      {status}
    </span>
  );
}

function SkeletonList({ n }: { n: number }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {Array.from({ length: n }).map((_, i) => (
        <div key={i} className="skeleton" style={{ height: 44 }} />
      ))}
    </div>
  );
}

function Empty({ message, cta, to }: { message: string; cta: string; to: string }) {
  return (
    <div style={{ textAlign: 'center', padding: '24px 0' }}>
      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 10 }}>{message}</p>
      <Link to={to} className="btn btn-primary" style={{ display: 'inline-flex', textDecoration: 'none' }}>
        {cta}
      </Link>
    </div>
  );
}
