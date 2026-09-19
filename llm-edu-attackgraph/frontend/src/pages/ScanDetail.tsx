import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import {
  Activity, Eye, Cpu, AlertTriangle, CheckCircle2, XCircle, RefreshCw,
  ChevronDown, ChevronRight, FileText, Shield
} from 'lucide-react';

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const qc = useQueryClient();
  const [showPrompt, setShowPrompt] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  const [reportData, setReportData] = useState<Record<string, unknown> | null>(null);

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => apiClient.getScan(scanId!),
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d || ['completed', 'failed', 'cancelled'].includes(d.status)) return false;
      return 3000;
    },
  });

  const { data: result, isLoading: resultLoading } = useQuery({
    queryKey: ['scan-result', scanId],
    queryFn: () => apiClient.getScanResult(scanId!),
    enabled: !!scan && ['completed', 'failed'].includes(scan.status),
    refetchInterval: false,
  });

  const reportMutation = useMutation({
    mutationFn: () => apiClient.generateReport(scanId!, 'json'),
    onSuccess: (data) => setReportData(data as Record<string, unknown>),
  });

  const isRunning = scan && ['pending', 'running', 'fingerprinting', 'analyzing'].includes(scan.status);

  if (scanLoading) return <div className="page"><div className="skeleton" style={{ height: 200, marginTop: 32 }} /></div>;
  if (!scan) return <div className="page" style={{ padding: 48, color: 'var(--text-muted)', textAlign: 'center' }}>Scan not found</div>;

  return (
    <div className="page animate-fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Activity size={24} color="var(--accent-blue)" />
            Scan Detail
          </h1>
          <p className="page-subtitle" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}>
            {scanId}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          {scan.status === 'completed' && (
            <button className="btn btn-secondary" onClick={() => reportMutation.mutate()} disabled={reportMutation.isPending}>
              <FileText size={14} /> {reportMutation.isPending ? 'Generating…' : 'Generate Report'}
            </button>
          )}
          <button className="btn btn-secondary" onClick={() => qc.invalidateQueries({ queryKey: ['scan', scanId] })}>
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      {/* Status card */}
      <ScanStatusCard scan={scan} />

      {isRunning && (
        <div className="alert alert-info" style={{ marginTop: 16 }}>
          <Activity size={14} className="animate-spin" />
          Scan in progress — {scan.status}. Auto-refreshing every 3 seconds…
        </div>
      )}

      {scan.status === 'failed' && scan.error_message && (
        <div className="alert alert-danger" style={{ marginTop: 16 }}>
          <AlertTriangle size={14} /> Error: {scan.error_message}
        </div>
      )}

      {/* Results */}
      {result && !resultLoading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 20 }}>
          {/* Stage 1: Fingerprint */}
          {result.fingerprint && (
            <Section
              icon={<Eye size={15} color="var(--evidence-observed)" />}
              title="Stage 1 — Fingerprint"
              badge="OBSERVED"
              badgeClass="badge-observed"
              desc="Directly obtained from reconnaissance (Algorithm 1)"
            >
              <div className="grid-2" style={{ gap: 12 }}>
                <InfoItem label="Framework" value={result.fingerprint.web_framework} mono />
                <InfoItem label="Server" value={result.fingerprint.server_software} mono />
                <InfoItem label="Technologies" value={(result.fingerprint.technologies || []).join(', ')} />
              </div>
              {result.fingerprint.text_representation && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600 }}>
                    Fingerprint Text (fed to embedding model)
                  </div>
                  <div className="code-block" style={{ maxHeight: 160, overflow: 'auto' }}>
                    {result.fingerprint.text_representation}
                  </div>
                </div>
              )}
            </Section>
          )}

          {/* Stage 2a: RAG Retrieval */}
          {result.retrieval && (
            <Section
              icon={<Cpu size={15} color="var(--evidence-retrieved)" />}
              title="Stage 2a — RAG Retrieval"
              badge="RETRIEVED"
              badgeClass="badge-retrieved"
              desc="Historical vulnerability cases from Awesome-POC knowledge base (Algorithm 2)"
            >
              <div className="grid-3" style={{ gap: 12, marginBottom: 14 }}>
                <MetricChip label="Max Similarity" value={result.retrieval.max_similarity?.toFixed(4) ?? 'N/A'} highlight={result.retrieval.threshold_passed} />
                <MetricChip label="Threshold (paper)" value={`${result.retrieval.threshold}`} />
                <MetricChip label="Threshold Passed" value={result.retrieval.threshold_passed ? 'YES ✓' : 'NO ✗'} highlight={result.retrieval.threshold_passed} />
              </div>
              {!result.retrieval.threshold_passed && (
                <div className="alert alert-info">
                  Max similarity {result.retrieval.max_similarity?.toFixed(4)} did not reach threshold {result.retrieval.threshold}.
                  Per Algorithm 2: "No relevant vulnerabilities were detected."
                </div>
              )}
              {(result.retrieval.results || []).length > 0 && (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Title</th>
                      <th>Technology</th>
                      <th>Source</th>
                      <th>Similarity</th>
                      <th>Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.retrieval.results!.map((r, i) => (
                      <tr key={i}>
                        <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{r.title || '—'}</td>
                        <td><span style={{ color: 'var(--accent-cyan)', fontFamily: 'monospace', fontSize: 12 }}>{r.technology || '—'}</span></td>
                        <td style={{ color: 'var(--text-muted)' }}>{r.source}</td>
                        <td>
                          <div style={{
                            display: 'inline-block', padding: '2px 8px', borderRadius: 100,
                            background: r.similarity_score >= (result.retrieval!.threshold || 0.6)
                              ? 'var(--accent-green-dim)' : 'var(--bg-input)',
                            color: r.similarity_score >= (result.retrieval!.threshold || 0.6)
                              ? 'var(--accent-green)' : 'var(--text-secondary)',
                            fontSize: 12, fontFamily: 'monospace', fontWeight: 600,
                          }}>
                            {r.similarity_score.toFixed(4)}
                          </div>
                        </td>
                        <td><span className="badge badge-retrieved">RETRIEVED</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Section>
          )}

          {/* Stage 2b: LLM Analysis */}
          {result.analysis && (
            <Section
              icon={<Shield size={15} color="var(--evidence-inferred)" />}
              title="Stage 2b — LLM Analysis"
              badge="INFERRED"
              badgeClass="badge-inferred"
              desc={`Generated by ${result.analysis.llm_provider}/${result.analysis.llm_model} — NOT a confirmed vulnerability`}
            >
              <div className="disclaimer-bar" style={{ marginBottom: 14 }}>
                <AlertTriangle size={13} />
                This is INFERRED by an LLM. Human validation required before treating as a confirmed vulnerability.
              </div>
              <div className="grid-2" style={{ gap: 12, marginBottom: 14 }}>
                <InfoItem label="Potential Vulnerability" value={result.analysis.potential_vulnerability} />
                <InfoItem label="Category" value={result.analysis.category} mono />
                <InfoItem label="Severity" value={result.analysis.severity?.toUpperCase()} />
                <InfoItem label="Validation Required" value="Always" />
              </div>
              {result.analysis.analysis_text && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600 }}>Analysis</div>
                  <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                    {result.analysis.analysis_text}
                  </div>
                </div>
              )}
              {(result.analysis.remediation_steps || []).length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600 }}>Remediation Steps</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {result.analysis.remediation_steps!.map((step, i) => (
                      <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                        <div style={{
                          width: 20, height: 20, borderRadius: '50%', background: 'var(--accent-green-dim)',
                          border: '1px solid rgba(16,185,129,0.3)', display: 'flex', alignItems: 'center',
                          justifyContent: 'center', fontSize: 10, fontWeight: 700, color: 'var(--accent-green)', flexShrink: 0,
                        }}>{i + 1}</div>
                        <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {result.analysis.uncertainty_statement && (
                <div className="alert alert-warning">
                  <AlertTriangle size={14} />
                  <span><strong>Uncertainty:</strong> {result.analysis.uncertainty_statement}</span>
                </div>
              )}
            </Section>
          )}

          {/* Findings */}
          {(result.findings || []).length > 0 && (
            <Section
              icon={<AlertTriangle size={15} color="var(--accent-yellow)" />}
              title="Findings"
              badge="REQUIRES VALIDATION"
              badgeClass="badge-inferred"
              desc="Human review required for all findings"
            >
              {result.findings!.map(f => (
                <FindingCard key={f.id} finding={f} scanId={scanId!} />
              ))}
            </Section>
          )}

          {/* Report */}
          {reportData && (
            <Section
              icon={<FileText size={15} color="var(--accent-blue)" />}
              title="Generated Report"
              badge="JSON"
              badgeClass="badge-observed"
              desc="Structured security report with full evidence chain"
            >
              <div className="code-block" style={{ maxHeight: 400, overflow: 'auto', fontSize: 11 }}>
                {JSON.stringify(reportData, null, 2)}
              </div>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

function ScanStatusCard({ scan }: { scan: import('../api/client').Scan | undefined }) {
  if (!scan) return null;
  const colors: Record<string, string> = {
    pending: 'var(--text-muted)', running: 'var(--accent-blue)',
    fingerprinting: 'var(--accent-cyan)', analyzing: 'var(--accent-purple)',
    completed: 'var(--accent-green)', failed: 'var(--accent-red)', cancelled: 'var(--text-muted)',
  };
  const c = colors[scan.status] || 'var(--text-muted)';
  return (
    <div className="card" style={{ borderLeft: `3px solid ${c}` }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24 }}>
        <InfoItem label="Status" value={<span style={{ color: c, fontWeight: 700, textTransform: 'uppercase' }}>{scan.status}</span>} />
        <InfoItem label="LLM Provider" value={scan.llm_provider || 'mock'} mono />
        <InfoItem label="Embedding" value={scan.embedding_model?.split('/').pop() || 'N/A'} mono />
        <InfoItem label="Similarity Threshold" value={scan.similarity_threshold?.toString() || 'N/A'} />
        <InfoItem label="Started" value={scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : 'Not started'} />
        <InfoItem label="Completed" value={scan.completed_at ? new Date(scan.completed_at).toLocaleTimeString() : '—'} />
      </div>
    </div>
  );
}

function Section({ icon, title, badge, badgeClass, desc, children }: {
  icon: React.ReactNode; title: string; badge: string; badgeClass: string; desc?: string; children: React.ReactNode
}) {
  const [open, setOpen] = useState(true);
  return (
    <div className="card">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: open ? 16 : 0, cursor: 'pointer' }} onClick={() => setOpen(o => !o)}>
        {icon}
        <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--text-primary)' }}>{title}</span>
        <span className={`badge ${badgeClass}`}>{badge}</span>
        {desc && <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 4 }}>{desc}</span>}
        <div style={{ marginLeft: 'auto' }}>
          {open ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}
        </div>
      </div>
      {open && children}
    </div>
  );
}

function InfoItem({ label, value, mono = false }: { label: string; value?: string | React.ReactNode; mono?: boolean }) {
  return (
    <div style={{ minWidth: 120 }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.6, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 13, color: 'var(--text-primary)', fontFamily: mono ? 'JetBrains Mono, monospace' : 'inherit' }}>
        {value || <span style={{ color: 'var(--text-muted)' }}>—</span>}
      </div>
    </div>
  );
}

function MetricChip({ label, value, highlight = false }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div style={{
      background: highlight ? 'var(--accent-green-dim)' : 'var(--bg-input)',
      border: `1px solid ${highlight ? 'rgba(16,185,129,0.3)' : 'var(--border)'}`,
      borderRadius: 10, padding: '10px 14px',
    }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 16, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: highlight ? 'var(--accent-green)' : 'var(--text-primary)' }}>
        {value}
      </div>
    </div>
  );
}

function FindingCard({ finding, scanId }: { finding: { id: string; title: string; category?: string; severity?: string; status: string; evidence_type: string }; scanId: string }) {
  const qc = useQueryClient();
  const [reviewer, setReviewer] = useState('');
  const [comment, setComment] = useState('');
  const [showForm, setShowForm] = useState(false);

  const submitMutation = useMutation({
    mutationFn: () => apiClient.submitForReview(finding.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-result', scanId] }),
  });

  const validateMutation = useMutation({
    mutationFn: (action: 'accept' | 'reject') => apiClient.validateFinding(finding.id, action, { reviewer, comment }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scan-result', scanId] }); setShowForm(false); },
  });

  const severityColor: Record<string, string> = {
    critical: 'var(--severity-critical)', high: 'var(--severity-high)',
    medium: 'var(--severity-medium)', low: 'var(--severity-low)',
    informational: 'var(--severity-info)',
  };
  const sc = severityColor[finding.severity || ''] || 'var(--text-muted)';

  return (
    <div style={{
      background: 'var(--bg-input)', borderRadius: 10,
      border: '1px solid var(--border)', padding: '14px 16px', marginBottom: 10,
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>{finding.title}</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {finding.severity && (
              <span style={{ fontSize: 11, fontWeight: 700, color: sc, background: `${sc}18`, padding: '2px 8px', borderRadius: 100, border: `1px solid ${sc}40` }}>
                {finding.severity.toUpperCase()}
              </span>
            )}
            {finding.category && <span className="badge badge-inferred">{finding.category}</span>}
            <span className={`badge badge-${finding.status === 'validated' ? 'validated-status' : finding.status === 'rejected' ? 'rejected' : finding.status === 'pending_review' ? 'pending_review' : 'potential'}`}>
              {finding.status.replace('_', ' ').toUpperCase()}
            </span>
            <span className="badge badge-inferred">INFERRED</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
          {finding.status === 'potential' && (
            <button className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: 12 }}
              onClick={() => submitMutation.mutate()} disabled={submitMutation.isPending}>
              Submit for Review
            </button>
          )}
          {finding.status === 'pending_review' && (
            <button className="btn btn-primary" style={{ padding: '6px 12px', fontSize: 12 }}
              onClick={() => setShowForm(true)}>
              Validate
            </button>
          )}
        </div>
      </div>

      {showForm && (
        <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 10 }}>
            Human Validation — <span className="badge badge-inferred">INFERRED finding requires review</span>
          </div>
          <div style={{ display: 'flex', gap: 10, flexDirection: 'column' }}>
            <input className="input" value={reviewer} onChange={e => setReviewer(e.target.value)} placeholder="Analyst name *" />
            <input className="input" value={comment} onChange={e => setComment(e.target.value)} placeholder="Comment / evidence (optional)" />
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn btn-success" onClick={() => validateMutation.mutate('accept')} disabled={!reviewer || validateMutation.isPending}>
                <CheckCircle2 size={13} /> Accept as Valid
              </button>
              <button className="btn btn-danger" onClick={() => validateMutation.mutate('reject')} disabled={!reviewer || validateMutation.isPending}>
                <XCircle size={13} /> Reject (False Positive)
              </button>
              <button className="btn btn-secondary" onClick={() => setShowForm(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
