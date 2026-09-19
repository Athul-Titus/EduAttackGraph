import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import { FlaskConical, AlertTriangle, Zap, Eye, Cpu, Shield, ChevronDown, ChevronRight } from 'lucide-react';

export default function DemoPage() {
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [runError, setRunError] = useState('');

  const { data: categories } = useQuery({ queryKey: ['vulnCats'], queryFn: apiClient.getVulnCategories });
  const { data: demoFP } = useQuery({ queryKey: ['demoFP'], queryFn: apiClient.getDemoFingerprint });
  const { data: demoKB } = useQuery({ queryKey: ['demoKB'], queryFn: apiClient.getDemoKB });

  const runMutation = useMutation({
    mutationFn: apiClient.runDemo,
    onSuccess: (data) => { setResult(data as Record<string, unknown>); setRunError(''); },
    onError: () => setRunError('Demo pipeline failed. Is the backend running?'),
  });

  return (
    <div className="page animate-fade-in">
      <div className="page-header">
        <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <FlaskConical size={24} color="var(--accent-purple)" /> Demo Mode
        </h1>
        <p className="page-subtitle">Explore the pipeline using pre-built synthetic data — no real scanning required</p>
      </div>

      {/* Warning banner */}
      <div className="alert alert-warning" style={{ marginBottom: 20, fontSize: 14 }}>
        <AlertTriangle size={16} />
        <div>
          <strong>Demo Mode</strong> — All data is synthetic and pre-built. No real target is scanned.
          Results are labeled <strong>DEMO</strong> and should never be treated as real security findings.
        </div>
      </div>

      {/* Run demo */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="section-header">
          <Zap size={16} color="var(--accent-yellow)" />
          <span className="section-title">Run Demo Pipeline</span>
        </div>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
          Runs the full two-stage pipeline with synthetic RuoYi fingerprint + mock LLM.
          Shows how Algorithm 1 (Fingerprinting) + Algorithm 2 (RAG + LLM) work together.
        </p>
        <button
          className="btn btn-primary"
          onClick={() => runMutation.mutate()}
          disabled={runMutation.isPending}
          style={{ marginBottom: runError ? 12 : 0 }}
        >
          <Zap size={14} />
          {runMutation.isPending ? 'Running Demo…' : 'Run Demo Pipeline'}
        </button>
        {runError && <div className="alert alert-danger" style={{ marginTop: 12 }}><AlertTriangle size={14} /> {runError}</div>}

        {result && (
          <div style={{ marginTop: 20 }}>
            <div className="alert alert-warning" style={{ marginBottom: 16 }}>
              <AlertTriangle size={14} />
              <strong>{(result as { _warning?: string })._warning as string}</strong>
            </div>

            {/* Stage results */}
            {Object.entries((result as { pipeline_stages: Record<string, unknown> }).pipeline_stages).map(([stage, data]) => (
              <DemoStageCard key={stage} stage={stage} data={data as Record<string, unknown>} />
            ))}

            <div className="alert alert-info" style={{ marginTop: 16 }}>
              <Shield size={14} />
              <div>
                <strong>Finding Status: {((result as { finding?: { status?: string } }).finding?.status ?? 'N/A').toUpperCase()}</strong>
                <br /><span style={{ fontSize: 12 }}>{(result as { finding?: { disclaimer?: string } }).finding?.disclaimer as string}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Two column: demo fingerprint + knowledge base */}
      <div className="grid-2" style={{ gap: 20, marginBottom: 20 }}>
        <div className="card">
          <div className="section-header">
            <Eye size={15} color="var(--evidence-observed)" />
            <span className="section-title">Demo Fingerprint</span>
            <span className="badge badge-observed">SYNTHETIC OBSERVED</span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
            Based on RuoYi (若依) platform — mentioned in the research paper
          </div>
          {demoFP && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <InfoRow label="Target" value={(demoFP as { target?: string }).target || 'localhost:8080'} mono />
              <InfoRow label="Framework" value={(demoFP as { web_framework?: string }).web_framework} mono />
              <InfoRow label="Server" value={(demoFP as { server_software?: string }).server_software} />
              <InfoRow label="Technologies" value={((demoFP as { technologies?: string[] }).technologies || []).join(', ')} />
              <InfoRow label="Server Version" value={(demoFP as { server_version?: string }).server_version} mono />
            </div>
          )}
        </div>

        <div className="card">
          <div className="section-header">
            <Cpu size={15} color="var(--evidence-retrieved)" />
            <span className="section-title">Demo Knowledge Base</span>
            <span className="badge badge-retrieved">SYNTHETIC RETRIEVED</span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
            Representative Awesome-POC documents (synthetic summaries)
          </div>
          {demoKB && ((demoKB as { documents?: unknown[] }).documents || []).map((doc: unknown, i: number) => {
            const d = doc as { title?: string; category?: string; technology?: string; similarity_score_demo?: number };
            return (
              <div key={i} style={{ background: 'var(--bg-input)', borderRadius: 10, padding: '10px 12px', border: '1px solid var(--border)', marginBottom: 10 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>{d.title}</div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <span className="badge badge-retrieved">{d.category}</span>
                  {d.technology && <span style={{ fontSize: 11, color: 'var(--accent-cyan)', fontFamily: 'monospace' }}>{d.technology}</span>}
                  {d.similarity_score_demo && (
                    <span style={{ fontSize: 11, color: 'var(--accent-green)', fontFamily: 'monospace' }}>
                      sim: {d.similarity_score_demo}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Vulnerability categories from paper */}
      {categories && (
        <div className="card">
          <div className="section-header">
            <Shield size={16} color="var(--accent-purple)" />
            <span className="section-title">Paper: 6 Vulnerability Categories</span>
            <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>
              {categories.total_vulnerabilities_in_paper} vulns analyzed in {categories.source}
            </span>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Code</th>
                <th>Name</th>
                <th>Paper Count</th>
                <th>Prevalence</th>
              </tr>
            </thead>
            <tbody>
              {categories.categories.map((c: { code: string; name: string; count: number; paper_prevalence: string }) => (
                <tr key={c.code}>
                  <td style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)' }}>{c.code}</td>
                  <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{c.name}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{c.count}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{ width: 80, height: 6, background: 'var(--bg-input)', borderRadius: 3, overflow: 'hidden' }}>
                        <div style={{ width: c.paper_prevalence, height: '100%', background: 'var(--accent-blue)', borderRadius: 3 }} />
                      </div>
                      <span style={{ fontSize: 12, color: 'var(--accent-blue)', fontFamily: 'monospace' }}>{c.paper_prevalence}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DemoStageCard({ stage, data }: { stage: string; data: Record<string, unknown> }) {
  const [open, setOpen] = useState(true);
  const titles: Record<string, string> = {
    stage_1_fingerprinting: 'Stage 1 — Fingerprinting',
    stage_2_rag: 'Stage 2a — RAG Retrieval',
    stage_2_llm: 'Stage 2b — LLM Analysis',
  };
  const badgeClasses: Record<string, string> = {
    stage_1_fingerprinting: 'badge-observed',
    stage_2_rag: 'badge-retrieved',
    stage_2_llm: 'badge-inferred',
  };
  const evidenceTypes: Record<string, string> = {
    stage_1_fingerprinting: 'DEMO OBSERVED',
    stage_2_rag: 'DEMO RETRIEVED',
    stage_2_llm: 'DEMO INFERRED',
  };

  return (
    <div style={{ background: 'var(--bg-input)', borderRadius: 10, border: '1px solid var(--border)', padding: '12px 16px', marginBottom: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }} onClick={() => setOpen(o => !o)}>
        <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{titles[stage] || stage}</span>
        <span className={`badge ${badgeClasses[stage] || 'badge-inferred'}`}>{evidenceTypes[stage]}</span>
        <div style={{ marginLeft: 'auto' }}>
          {open ? <ChevronDown size={13} color="var(--text-muted)" /> : <ChevronRight size={13} color="var(--text-muted)" />}
        </div>
      </div>
      {open && (
        <div className="code-block" style={{ marginTop: 12, maxHeight: 300, overflow: 'auto', fontSize: 11 }}>
          {JSON.stringify(data, null, 2)}
        </div>
      )}
    </div>
  );
}

function InfoRow({ label, value, mono = false }: { label: string; value?: string; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
      <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>{label}</span>
      <span style={{ fontSize: 12, color: 'var(--text-primary)', fontFamily: mono ? 'JetBrains Mono, monospace' : 'inherit', textAlign: 'right', maxWidth: '60%' }}>
        {value || '—'}
      </span>
    </div>
  );
}
