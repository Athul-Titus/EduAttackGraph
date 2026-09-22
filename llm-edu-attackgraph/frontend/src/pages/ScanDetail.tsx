import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import {
  Activity, Eye, Cpu, AlertTriangle, CheckCircle2, XCircle, RefreshCw,
  ChevronDown, ChevronRight, FileText, Shield, Download, ArrowLeft, BookOpen, Clock
} from 'lucide-react';
import { getVulnExplanation, URGENCY_CONFIG } from '../utils/vulnExplainer';

// ─── Live Pipeline Progress Timeline ──────────────────────────────────────────

const PIPELINE_STEPS = [
  { id: 'pending',        label: 'Queued',          icon: Clock,        desc: 'Scan is waiting to start' },
  { id: 'fingerprinting', label: 'Fingerprinting',  icon: Eye,          desc: 'Algorithm 1 — Port scan, service detection, web fingerprinting' },
  { id: 'analyzing',     label: 'LLM Analysis',     icon: Cpu,          desc: 'Algorithm 2 — RAG retrieval + LLM vulnerability inference' },
  { id: 'completed',     label: 'Complete',          icon: CheckCircle2, desc: 'Pipeline finished — findings available for review' },
];

function PipelineTimeline({ status }: { status: string }) {
  const activeIdx = status === 'failed' ? -1
    : status === 'cancelled' ? -1
    : PIPELINE_STEPS.findIndex(s => s.id === status);
  const completedIdx = status === 'completed' ? 3 : activeIdx;

  return (
    <div style={{ padding: '20px 24px', background: 'var(--bg-input)', borderRadius: 12, border: '1px solid var(--border)', marginTop: 16 }}>
      <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 20 }}>
        Pipeline Progress (Algorithm 1 + 2)
      </div>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 0, position: 'relative' }}>
        {PIPELINE_STEPS.map((step, idx) => {
          const isDone = status === 'completed' || (completedIdx >= 0 && idx < completedIdx);
          const isActive = idx === completedIdx && status !== 'completed';
          const isPending = idx > completedIdx;
          const Icon = step.icon;

          const color = isDone || (idx === 3 && status === 'completed')
            ? 'var(--accent-green)'
            : isActive ? 'var(--accent-blue)'
            : 'var(--text-muted)';

          return (
            <div key={step.id} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', position: 'relative' }}>
              {/* Connector line */}
              {idx > 0 && (
                <div style={{
                  position: 'absolute', left: 0, top: 16, width: '50%', height: 2,
                  background: isDone ? 'var(--accent-green)' : 'var(--border)',
                  transition: 'background 0.5s',
                }} />
              )}
              {idx < PIPELINE_STEPS.length - 1 && (
                <div style={{
                  position: 'absolute', right: 0, top: 16, width: '50%', height: 2,
                  background: (isDone || (idx === 3 && status === 'completed')) ? 'var(--accent-green)' : 'var(--border)',
                  transition: 'background 0.5s',
                }} />
              )}

              {/* Icon circle */}
              <div style={{
                width: 34, height: 34, borderRadius: '50%', zIndex: 1,
                background: isDone ? 'var(--accent-green-dim)' : isActive ? 'rgba(59,130,246,0.15)' : 'var(--bg-card)',
                border: `2px solid ${color}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                transition: 'all 0.4s',
                boxShadow: isActive ? `0 0 12px ${color}60` : 'none',
              }}>
                {isActive
                  ? <div style={{ width: 12, height: 12, borderRadius: '50%', background: color, animation: 'pulse 1.2s ease-in-out infinite' }} />
                  : <Icon size={15} color={color} />
                }
              </div>

              {/* Label */}
              <div style={{ marginTop: 10, textAlign: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: isPending ? 'var(--text-muted)' : color }}>
                  {step.label}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3, lineHeight: 1.4, maxWidth: 100 }}>
                  {step.desc}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {status === 'failed' && (
        <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 8, color: 'var(--accent-red)', fontSize: 13 }}>
          <XCircle size={14} /> Pipeline failed — see error below
        </div>
      )}
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────────

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const qc = useQueryClient();
  const [showPrompt, setShowPrompt] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  const [reportData, setReportData] = useState<Record<string, unknown> | null>(null);
  const [reportFormat, setReportFormat] = useState<'json' | 'markdown'>('json');

  const { data: targets = [] } = useQuery({ queryKey: ['targets'], queryFn: apiClient.listTargets });

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
    mutationFn: () => apiClient.generateReport(scanId!, reportFormat),
    onSuccess: (data) => setReportData(data as Record<string, unknown>),
  });

  const downloadReport = (format: 'json' | 'markdown') => {
    if (!reportData) return;
    const content = format === 'json' ? JSON.stringify(reportData, null, 2) : String(reportData);
    const mime = format === 'json' ? 'application/json' : 'text/markdown';
    const ext = format === 'json' ? 'json' : 'md';
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_report_${scanId!.slice(0, 8)}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const isRunning = scan && ['pending', 'running', 'fingerprinting', 'analyzing'].includes(scan.status);

  // Resolve target hostname for breadcrumb
  const targetHost = targets.find(t => t.id === scan?.target_id)?.hostname || scan?.target_id?.slice(0, 12) || '…';

  if (scanLoading) return <div className="page"><div className="skeleton" style={{ height: 200, marginTop: 32 }} /></div>;
  if (!scan) return <div className="page" style={{ padding: 48, color: 'var(--text-muted)', textAlign: 'center' }}>Scan not found</div>;

  return (
    <div className="page animate-fade-in">

      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, fontSize: 13, color: 'var(--text-muted)' }}>
        <Link to="/scans" style={{ color: 'var(--accent-blue)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4 }}>
          <ArrowLeft size={14} /> Scans
        </Link>
        <span>/</span>
        <span style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-secondary)' }}>{targetHost}</span>
        <span>/</span>
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--text-muted)' }}>{scanId!.slice(0, 8)}…</span>
      </div>

      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Activity size={24} color="var(--accent-blue)" />
            {targetHost}
          </h1>
          <p className="page-subtitle">
            {scan.started_at
              ? `Started ${new Date(scan.started_at).toLocaleString()}`
              : `Created ${new Date(scan.created_at).toLocaleString()}`
            }
            {scan.completed_at && ` · Completed ${new Date(scan.completed_at).toLocaleString()}`}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          {scan.status === 'completed' && (
            <>
              <button className="btn btn-secondary" onClick={() => { setReportFormat('json'); reportMutation.mutate(); }} disabled={reportMutation.isPending}>
                <FileText size={14} /> {reportMutation.isPending ? 'Generating…' : 'Generate Report'}
              </button>
              {reportData && (
                <button className="btn btn-secondary" onClick={() => downloadReport(reportFormat)} title="Download generated report">
                  <Download size={14} /> Download
                </button>
              )}
            </>
          )}
          <button className="btn btn-secondary" onClick={() => qc.invalidateQueries({ queryKey: ['scan', scanId] })}>
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      {/* Status card */}
      <ScanStatusCard scan={scan} />

      {/* Live pipeline progress */}
      <PipelineTimeline status={scan.status} />

      {isRunning && (
        <div className="alert alert-info" style={{ marginTop: 16, animation: 'pulse 2s ease-in-out infinite' }}>
          <Activity size={14} />
          <span>
            Scan in progress — <strong>{scan.status.toUpperCase()}</strong>. Auto-refreshing every 3 seconds…
            This may take 30–120 seconds depending on the target.
          </span>
        </div>
      )}

      {scan.status === 'failed' && scan.error_message && (
        <div className="alert alert-danger" style={{ marginTop: 16 }}>
          <AlertTriangle size={14} /> <strong>Error:</strong> {scan.error_message}
        </div>
      )}

      {/* Results */}
      {result && !resultLoading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 20 }}>

          {/* Stage 1: Fingerprint */}
          {result.fingerprint && (
            <Section
              icon={<Eye size={15} color="var(--evidence-observed)" />}
              title="Stage 1 — Website Fingerprint"
              badge="OBSERVED"
              badgeClass="badge-observed"
              desc="Directly obtained from reconnaissance (Algorithm 1)"
            >
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14, lineHeight: 1.6 }}>
                📌 <strong>What is this?</strong> During Stage 1 we connected to the target website and read its "fingerprint" —
                like reading the label on a product. This tells us which software, server, and technologies are running,
                so we can look up known vulnerabilities for those exact products.
              </div>
              <div className="grid-2" style={{ gap: 12 }}>
                <InfoItem label="Framework Detected" value={result.fingerprint.web_framework} mono />
                <InfoItem label="Server Software" value={result.fingerprint.server_software} mono />
                <InfoItem label="Technologies" value={(result.fingerprint.technologies || []).join(', ')} />
              </div>
              {result.fingerprint.text_representation && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600 }}>
                    Fingerprint Text (this is what gets converted into a vector for similarity search)
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
              title="Stage 2a — Knowledge Base Search (RAG)"
              badge="RETRIEVED"
              badgeClass="badge-retrieved"
              desc="Historical vulnerability cases from knowledge base (Algorithm 2)"
            >
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14, lineHeight: 1.6 }}>
                📌 <strong>What is this?</strong> We converted the fingerprint into a mathematical representation (a "vector")
                using the <strong>BGE embedding model</strong>, then searched our knowledge base of{' '}
                <strong>961 educational website vulnerabilities</strong> for the most similar past cases.
                A similarity score ≥ <strong>{result.retrieval.threshold}</strong> (from the research paper) means
                the match is strong enough to send to the LLM for analysis.
              </div>
              <div className="grid-3" style={{ gap: 12, marginBottom: 14 }}>
                <MetricChip
                  label="Best Match Score"
                  value={result.retrieval.max_similarity?.toFixed(4) ?? 'N/A'}
                  highlight={result.retrieval.threshold_passed}
                  note="Cosine similarity (0–1)"
                />
                <MetricChip
                  label="Threshold (Paper)"
                  value={`≥ ${result.retrieval.threshold}`}
                  note="From Liu et al., 2026"
                />
                <MetricChip
                  label="Threshold Passed?"
                  value={result.retrieval.threshold_passed ? 'YES ✓' : 'NO ✗'}
                  highlight={result.retrieval.threshold_passed}
                  note={result.retrieval.threshold_passed ? 'LLM will analyze' : 'No LLM analysis triggered'}
                />
              </div>
              {!result.retrieval.threshold_passed && (
                <div className="alert alert-info">
                  Best match score {result.retrieval.max_similarity?.toFixed(4)} did not reach threshold {result.retrieval.threshold}.
                  Per Algorithm 2: <em>"No relevant vulnerabilities were detected for this fingerprint."</em>
                </div>
              )}
              {(result.retrieval.results || []).length > 0 && (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Matched Vulnerability Case</th>
                      <th>Technology</th>
                      <th>Source</th>
                      <th>Similarity Score</th>
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
              title="Stage 2b — LLM Vulnerability Analysis"
              badge="INFERRED"
              badgeClass="badge-inferred"
              desc={`Generated by ${result.analysis.llm_provider}/${result.analysis.llm_model} — NOT a confirmed vulnerability`}
            >
              <div className="disclaimer-bar" style={{ marginBottom: 14 }}>
                <AlertTriangle size={13} />
                <span>
                  📌 <strong>What is this?</strong> The LLM (AI language model) received the fingerprint + matched vulnerability cases
                  and was asked: <em>"Given what we observed, what security risks might exist?"</em> The answer is <strong>INFERRED</strong> —
                  it's the AI's best guess, not a confirmed security test result. A human must verify every finding.
                </span>
              </div>
              <div className="grid-2" style={{ gap: 12, marginBottom: 14 }}>
                <InfoItem label="Potential Vulnerability Type" value={result.analysis.potential_vulnerability} />
                <InfoItem label="Research Category" value={result.analysis.category} mono />
                <InfoItem label="Estimated Severity" value={result.analysis.severity?.toUpperCase()} />
                <InfoItem label="Human Validation Required" value="Always — before taking any action" />
              </div>
              {result.analysis.analysis_text && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600 }}>
                    AI Analysis Narrative (INFERRED)
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                    {result.analysis.analysis_text}
                  </div>
                </div>
              )}
              {(result.analysis.remediation_steps || []).length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600 }}>
                    Suggested Remediation Steps (Verify with a security professional)
                  </div>
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
                  <span><strong>AI Uncertainty Note:</strong> {result.analysis.uncertainty_statement}</span>
                </div>
              )}
            </Section>
          )}

          {/* Findings */}
          {(result.findings || []).length > 0 && (
            <Section
              icon={<AlertTriangle size={15} color="var(--accent-yellow)" />}
              title="Findings Generated"
              badge="REQUIRES VALIDATION"
              badgeClass="badge-inferred"
              desc="Human review required — see Findings page for full detail and plain-English explanations"
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
              badge={reportFormat.toUpperCase()}
              badgeClass="badge-observed"
              desc="Structured security report — download for your records"
            >
              <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
                <button className="btn btn-secondary" onClick={() => downloadReport('json')} style={{ fontSize: 12 }}>
                  <Download size={13} /> Download JSON
                </button>
                <button className="btn btn-secondary" onClick={() => downloadReport('markdown')} style={{ fontSize: 12 }}>
                  <Download size={13} /> Download Markdown
                </button>
              </div>
              <div className="code-block" style={{ maxHeight: 400, overflow: 'auto', fontSize: 11 }}>
                {JSON.stringify(reportData, null, 2)}
              </div>
            </Section>
          )}
        </div>
      )}

      {/* Prompt debug */}
      {showPrompt && (
        <div style={{ marginTop: 16, background: 'var(--bg-input)', borderRadius: 10, padding: 16, border: '1px solid var(--border)' }}>
          <pre style={{ fontSize: 11, color: 'var(--text-muted)' }}>Prompt debug view — not yet implemented</pre>
        </div>
      )}
    </div>
  );
}

// ─── ScanStatusCard ────────────────────────────────────────────────────────────

function ScanStatusCard({ scan }: { scan: import('../api/client').Scan | undefined }) {
  if (!scan) return null;
  const colors: Record<string, string> = {
    pending: 'var(--text-muted)', running: 'var(--accent-blue)',
    fingerprinting: 'var(--accent-cyan)', analyzing: 'var(--accent-purple)',
    completed: 'var(--accent-green)', failed: 'var(--accent-red)', cancelled: 'var(--text-muted)',
  };
  const c = colors[scan.status] || 'var(--text-muted)';

  // Duration
  let duration = '';
  if (scan.started_at && scan.completed_at) {
    const ms = new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime();
    duration = ms < 60000 ? `${Math.round(ms / 1000)}s` : `${Math.round(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
  }

  return (
    <div className="card" style={{ borderLeft: `3px solid ${c}` }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24 }}>
        <InfoItem label="Status" value={<span style={{ color: c, fontWeight: 700, textTransform: 'uppercase' }}>{scan.status}</span>} />
        <InfoItem label="LLM Provider" value={scan.llm_provider || 'mock'} mono />
        <InfoItem label="Embedding Model" value={scan.embedding_model?.split('/').pop() || 'N/A'} mono />
        <InfoItem label="Similarity Threshold" value={scan.similarity_threshold?.toString() || 'N/A'} />
        <InfoItem label="Started" value={scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : 'Not started'} />
        <InfoItem label="Completed" value={scan.completed_at ? new Date(scan.completed_at).toLocaleTimeString() : '—'} />
        {duration && <InfoItem label="Duration" value={duration} />}
      </div>
      {scan.notes && (
        <div style={{ marginTop: 10, fontSize: 13, color: 'var(--text-secondary)' }}>
          📝 <em>{scan.notes}</em>
        </div>
      )}
    </div>
  );
}

// ─── Section ────────────────────────────────────────────────────────────────────

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

// ─── InfoItem ───────────────────────────────────────────────────────────────────

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

// ─── MetricChip ─────────────────────────────────────────────────────────────────

function MetricChip({ label, value, highlight = false, note }: { label: string; value: string; highlight?: boolean; note?: string }) {
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
      {note && <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>{note}</div>}
    </div>
  );
}

// ─── FindingCard ─────────────────────────────────────────────────────────────────

function FindingCard({ finding, scanId }: { finding: { id: string; title: string; category?: string; severity?: string; status: string; evidence_type: string }; scanId: string }) {
  const qc = useQueryClient();
  const [reviewer, setReviewer] = useState('');
  const [comment, setComment] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [showExplainer, setShowExplainer] = useState(false);
  const explanation = getVulnExplanation(finding.category, finding.title);

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
  const urgencyConf = explanation ? URGENCY_CONFIG[explanation.urgency] : null;

  return (
    <div style={{
      background: 'var(--bg-input)', borderRadius: 10,
      border: `1px solid var(--border)`, borderLeft: `3px solid ${sc}`,
      marginBottom: 10, overflow: 'hidden',
    }}>
      <div style={{ padding: '14px 16px' }}>
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
      </div>

      {/* Plain English explainer toggle */}
      {explanation && (
        <button
          onClick={() => setShowExplainer(v => !v)}
          style={{
            width: '100%', background: showExplainer ? 'rgba(99,102,241,0.1)' : 'rgba(99,102,241,0.04)',
            border: 'none', borderTop: '1px solid var(--border)',
            padding: '8px 16px', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 8,
            color: 'var(--accent-purple)', fontSize: 12, fontWeight: 600,
            fontFamily: 'inherit', textAlign: 'left',
          }}
        >
          <BookOpen size={13} />
          {explanation.emoji} What does this mean? (Plain English)
          <span style={{ marginLeft: 'auto' }}>
            {showExplainer ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </span>
        </button>
      )}

      {showExplainer && explanation && (
        <div style={{ padding: '16px', borderTop: '1px solid var(--border)', background: urgencyConf ? urgencyConf.bg : 'transparent' }}>
          <p style={{ margin: '0 0 10px', fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            <strong>{explanation.emoji} {explanation.plainName}</strong> — {explanation.simpleExplanation}
          </p>
          <p style={{ margin: '0 0 10px', fontSize: 13, color: 'var(--text-muted)', fontStyle: 'italic', lineHeight: 1.6 }}>
            {explanation.analogy}
          </p>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 10 }}>
            <strong>⚠️ Risk:</strong> {explanation.realWorldRisk}
          </div>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent-green)', marginBottom: 6 }}>✅ What to do:</div>
            {explanation.whatToDoNext.slice(0, 3).map((step, i) => (
              <div key={i} style={{ fontSize: 12, color: 'var(--text-secondary)', paddingLeft: 12, marginBottom: 4 }}>
                {i + 1}. {step}
              </div>
            ))}
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
              → See the <Link to="/findings" style={{ color: 'var(--accent-blue)' }}>Findings page</Link> for the full guide including all action steps.
            </div>
          </div>
        </div>
      )}

      {showForm && (
        <div style={{ padding: '14px 16px', borderTop: '1px solid var(--border)', background: 'var(--bg-card)' }}>
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
