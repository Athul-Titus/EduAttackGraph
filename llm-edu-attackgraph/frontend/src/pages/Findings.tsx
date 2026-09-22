import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient, Finding } from '../api/client';
import { Bug, AlertTriangle, CheckCircle2, XCircle, Clock, Download, BookOpen, ChevronDown, ChevronRight, FileText } from 'lucide-react';
import { getVulnExplanation, URGENCY_CONFIG } from '../utils/vulnExplainer';

const STATUS_FILTERS = ['all', 'potential', 'pending_review', 'validated', 'rejected', 'needs_more_evidence'];
const STATUS_LABELS: Record<string, string> = {
  all: 'ALL',
  potential: 'POTENTIAL',
  pending_review: 'PENDING REVIEW',
  validated: 'VALIDATED',
  rejected: 'REJECTED',
  needs_more_evidence: 'NEEDS MORE EVIDENCE',
};

// ─── CSV Export ────────────────────────────────────────────────────────────────

function exportCSV(findings: Finding[]) {
  const headers = ['Title', 'Category', 'Severity', 'Status', 'Evidence Type', 'Scan ID', 'Created At', 'Description'];
  const rows = findings.map(f => [
    `"${(f.title || '').replace(/"/g, '""')}"`,
    f.category || '',
    f.severity || '',
    f.status,
    f.evidence_type,
    f.scan_id.slice(0, 12),
    new Date(f.created_at).toLocaleString(),
    `"${(f.description || '').replace(/"/g, '""').slice(0, 300)}"`,
  ]);
  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `eduattackgraph_findings_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── PDF-ready HTML Export ─────────────────────────────────────────────────────

function exportPDF(findings: Finding[]) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>LLM-EduAttackGraph — Security Findings Report</title>
  <style>
    body { font-family: Arial, sans-serif; color: #1e293b; margin: 40px; line-height: 1.6; }
    h1 { color: #1e3a5f; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }
    h2 { color: #1e3a5f; margin-top: 30px; }
    .meta { background: #f1f5f9; padding: 12px 16px; border-radius: 8px; font-size: 13px; margin-bottom: 24px; }
    .disclaimer { background: #fef9c3; border-left: 4px solid #f59e0b; padding: 12px 16px; margin: 20px 0; font-size: 13px; border-radius: 4px; }
    .finding { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 16px 0; page-break-inside: avoid; }
    .finding.critical { border-left: 4px solid #ef4444; }
    .finding.high { border-left: 4px solid #f59e0b; }
    .finding.medium { border-left: 4px solid #3b82f6; }
    .finding.low { border-left: 4px solid #6b7280; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 100px; font-size: 11px; font-weight: 700; margin: 2px; }
    .badge-critical { background: #fee2e2; color: #b91c1c; }
    .badge-high { background: #fef3c7; color: #b45309; }
    .badge-medium { background: #dbeafe; color: #1d4ed8; }
    .badge-low { background: #f1f5f9; color: #475569; }
    .badge-inferred { background: #ede9fe; color: #7c3aed; }
    .badge-potential { background: #fef9c3; color: #92400e; }
    .badge-validated { background: #d1fae5; color: #065f46; }
    .badge-rejected { background: #fee2e2; color: #991b1b; }
    .section-title { font-size: 11px; color: #94a3b8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin: 12px 0 4px; }
    .desc { font-size: 13px; color: #334155; margin-top: 8px; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; font-size: 13px; }
    th { background: #f8fafc; border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }
    td { border: 1px solid #e2e8f0; padding: 8px 12px; }
    footer { margin-top: 40px; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 12px; }
  </style>
</head>
<body>
  <h1>🛡️ LLM-EduAttackGraph — Security Findings Report</h1>
  <div class="meta">
    <strong>Generated:</strong> ${new Date().toLocaleString()} &nbsp;|&nbsp;
    <strong>Total Findings:</strong> ${findings.length} &nbsp;|&nbsp;
    <strong>System:</strong> LLM-EduAttackGraph v0.1.0 (Liu et al., IEEE IoT Journal, 2026)
  </div>
  <div class="disclaimer">
    ⚠️ <strong>IMPORTANT:</strong> All findings are <strong>INFERRED</strong> by an LLM model. They are NOT confirmed vulnerabilities.
    Every finding MUST be reviewed and validated by a qualified human security analyst before taking action.
    This report is a research output — not a formal penetration test result.
  </div>

  <h2>Summary Table</h2>
  <table>
    <tr>
      <th>#</th><th>Title</th><th>Category</th><th>Severity</th><th>Status</th><th>Date</th>
    </tr>
    ${findings.map((f, i) => `
    <tr>
      <td>${i + 1}</td>
      <td>${f.title}</td>
      <td>${f.category || '—'}</td>
      <td><span class="badge badge-${f.severity || 'low'}">${(f.severity || 'N/A').toUpperCase()}</span></td>
      <td><span class="badge badge-${f.status}">${f.status.replace(/_/g, ' ').toUpperCase()}</span></td>
      <td>${new Date(f.created_at).toLocaleDateString()}</td>
    </tr>`).join('')}
  </table>

  <h2>Detailed Findings</h2>
  ${findings.map((f, i) => {
    const expl = getVulnExplanation(f.category, f.title);
    return `
  <div class="finding ${f.severity || 'low'}">
    <h3>${i + 1}. ${f.title}</h3>
    <div>
      <span class="badge badge-${f.severity || 'low'}">${(f.severity || 'N/A').toUpperCase()}</span>
      <span class="badge badge-inferred">${f.category || 'N/A'}</span>
      <span class="badge badge-inferred">INFERRED</span>
      <span class="badge badge-${f.status}">${f.status.replace(/_/g, ' ').toUpperCase()}</span>
    </div>
    ${f.description ? `<div class="desc">${f.description}</div>` : ''}
    ${expl ? `
    <div class="section-title">Plain Language Explanation</div>
    <div class="desc"><strong>${expl.emoji} ${expl.plainName}</strong><br>${expl.simpleExplanation}</div>
    <div class="section-title">Real-World Risk</div>
    <div class="desc">${expl.realWorldRisk}</div>
    <div class="section-title">What To Do</div>
    <ol>${expl.whatToDoNext.map(s => `<li>${s}</li>`).join('')}</ol>
    ` : ''}
    <div class="section-title">Scan Reference</div>
    <div class="desc">Scan ID: ${f.scan_id} &nbsp;|&nbsp; Created: ${new Date(f.created_at).toLocaleString()}</div>
  </div>`;
  }).join('')}

  <footer>
    LLM-EduAttackGraph — Research implementation of Liu et al., "LLM-Assisted Security Vulnerability Analysis for Educational Websites", IEEE Internet of Things Journal, 2026.
    All outputs require human validation. This is not a replacement for professional penetration testing.
  </footer>
</body>
</html>`;
  const blob = new Blob([html], { type: 'text/html;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `eduattackgraph_findings_${new Date().toISOString().slice(0, 10)}.html`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Component ─────────────────────────────────────────────────────────────────

export default function Findings() {
  const [statusFilter, setStatusFilter] = useState('all');
  const [reviewer, setReviewer] = useState('');
  const [reviewingId, setReviewingId] = useState<string | null>(null);
  const [comment, setComment] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const qc = useQueryClient();

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ['findings', statusFilter],
    queryFn: () => apiClient.listFindings(undefined, statusFilter === 'all' ? undefined : statusFilter),
    refetchInterval: 8000,
  });

  const submitMutation = useMutation({
    mutationFn: (id: string) => apiClient.submitForReview(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  });

  const validateMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'accept' | 'reject' }) =>
      apiClient.validateFinding(id, action, { reviewer, comment }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] });
      setReviewingId(null); setReviewer(''); setComment('');
    },
  });

  const counts = {
    all: findings.length,
    potential: findings.filter(f => f.status === 'potential').length,
    pending_review: findings.filter(f => f.status === 'pending_review').length,
    validated: findings.filter(f => f.status === 'validated').length,
    rejected: findings.filter(f => f.status === 'rejected').length,
  };

  const filteredFindings = findings.filter(f => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.title?.toLowerCase().includes(q) ||
      f.category?.toLowerCase().includes(q) ||
      f.severity?.toLowerCase().includes(q) ||
      f.description?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="page animate-fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Bug size={24} color="var(--accent-yellow)" /> Findings
          </h1>
          <p className="page-subtitle">Human-in-the-loop validation queue · Plain-English analysis included</p>
        </div>
        {findings.length > 0 && (
          <div style={{ display: 'flex', gap: 10, flexShrink: 0 }}>
            <button
              className="btn btn-secondary"
              onClick={() => exportCSV(findings)}
              title="Download as CSV spreadsheet"
            >
              <Download size={14} /> Export CSV
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => exportPDF(findings)}
              title="Download as printable HTML report (open in browser → Print → Save as PDF)"
            >
              <FileText size={14} /> Export Report (PDF)
            </button>
          </div>
        )}
      </div>

      <div className="disclaimer-bar" style={{ marginBottom: 20 }}>
        <AlertTriangle size={14} />
        <span>
          All findings start as <strong>POTENTIAL (INFERRED)</strong> from LLM analysis.
          A finding is only <strong>VALIDATED</strong> after human analyst review.
          Never treat INFERRED findings as confirmed vulnerabilities.
        </span>
      </div>

      {/* Search + Filter row */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          className="input"
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="🔍 Search findings by title, category, severity…"
          style={{ flex: '1 1 220px', minWidth: 180 }}
        />
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {STATUS_FILTERS.map(s => {
            const active = statusFilter === s;
            const count = s === 'all' ? findings.length : counts[s as keyof typeof counts] ?? 0;
            return (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                style={{
                  padding: '6px 14px', borderRadius: 100, fontSize: 12, fontWeight: 600, cursor: 'pointer',
                  border: '1px solid', fontFamily: 'inherit',
                  background: active ? 'var(--accent-blue-dim)' : 'var(--bg-input)',
                  borderColor: active ? 'rgba(59,130,246,0.5)' : 'var(--border)',
                  color: active ? 'var(--accent-blue)' : 'var(--text-secondary)',
                  display: 'flex', alignItems: 'center', gap: 6,
                }}
              >
                {STATUS_LABELS[s] || s.toUpperCase()}
                <span style={{
                  background: active ? 'rgba(59,130,246,0.3)' : 'rgba(148,163,184,0.2)',
                  borderRadius: 100, padding: '0 6px', fontSize: 11,
                }}>{count}</span>
              </button>
            );
          })}
        </div>
      </div>

      {isLoading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 80 }} />)}
        </div>
      ) : filteredFindings.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
          <Bug size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
          <p style={{ fontSize: 15 }}>No findings {statusFilter !== 'all' ? `with status "${STATUS_LABELS[statusFilter]}"` : 'yet'}</p>
          <p style={{ fontSize: 13, marginTop: 6 }}>Run a scan to generate findings</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {filteredFindings.map(f => (
            <FindingRow
              key={f.id}
              finding={f}
              isReviewing={reviewingId === f.id}
              reviewer={reviewer}
              comment={comment}
              setReviewer={setReviewer}
              setComment={setComment}
              onSubmitReview={() => submitMutation.mutate(f.id)}
              onStartReview={() => { setReviewingId(f.id); setReviewer(''); setComment(''); }}
              onAccept={() => validateMutation.mutate({ id: f.id, action: 'accept' })}
              onReject={() => validateMutation.mutate({ id: f.id, action: 'reject' })}
              onCancel={() => setReviewingId(null)}
              loading={submitMutation.isPending || validateMutation.isPending}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── FindingRow ────────────────────────────────────────────────────────────────

function FindingRow({
  finding, isReviewing, reviewer, comment, setReviewer, setComment,
  onSubmitReview, onStartReview, onAccept, onReject, onCancel, loading
}: {
  finding: Finding;
  isReviewing: boolean;
  reviewer: string;
  comment: string;
  setReviewer: (v: string) => void;
  setComment: (v: string) => void;
  onSubmitReview: () => void;
  onStartReview: () => void;
  onAccept: () => void;
  onReject: () => void;
  onCancel: () => void;
  loading: boolean;
}) {
  const [showExplainer, setShowExplainer] = useState(false);
  const [showFullDesc, setShowFullDesc] = useState(false);
  const explanation = getVulnExplanation(finding.category, finding.title);

  const severityColors: Record<string, string> = {
    critical: 'var(--severity-critical)', high: 'var(--severity-high)',
    medium: 'var(--severity-medium)', low: 'var(--severity-low)',
    informational: 'var(--severity-info)',
  };
  const sc = severityColors[finding.severity || ''] || 'var(--text-muted)';
  const statusIcons: Record<string, React.ReactNode> = {
    potential: <Clock size={14} color="var(--accent-yellow)" />,
    pending_review: <AlertTriangle size={14} color="var(--accent-blue)" />,
    validated: <CheckCircle2 size={14} color="var(--accent-green)" />,
    rejected: <XCircle size={14} color="var(--accent-red)" />,
  };

  const urgencyConf = explanation ? URGENCY_CONFIG[explanation.urgency] : null;

  return (
    <div className="card" style={{ borderLeft: `3px solid ${sc}`, padding: 0, overflow: 'hidden' }}>
      {/* Main header */}
      <div style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
              {statusIcons[finding.status]}
              <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>{finding.title}</span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {finding.severity && (
                <span style={{ fontSize: 11, fontWeight: 700, color: sc, background: `${sc}18`, padding: '2px 8px', borderRadius: 100, border: `1px solid ${sc}30` }}>
                  {finding.severity.toUpperCase()}
                </span>
              )}
              {finding.category && <span className="badge badge-inferred">{finding.category}</span>}
              <span className="badge badge-inferred">INFERRED</span>
              <span className={`badge ${finding.status === 'validated' ? 'badge-validated-status' : finding.status === 'rejected' ? 'badge-rejected' : finding.status === 'pending_review' ? 'badge-pending_review' : 'badge-potential'}`}>
                {finding.status.replace(/_/g, ' ').toUpperCase()}
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
              Scan: {finding.scan_id.slice(0, 12)}… · {new Date(finding.created_at).toLocaleString()}
            </div>
            {finding.description && (
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 10, lineHeight: 1.6 }}>
                {showFullDesc ? finding.description : finding.description.slice(0, 220)}
                {finding.description.length > 220 && (
                  <button onClick={() => setShowFullDesc(v => !v)} style={{ background: 'none', border: 'none', color: 'var(--accent-blue)', cursor: 'pointer', fontSize: 12, marginLeft: 4, padding: 0 }}>
                    {showFullDesc ? ' Show less' : '… Read more'}
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flexShrink: 0, alignItems: 'flex-end' }}>
            {finding.status === 'potential' && (
              <button className="btn btn-secondary" onClick={onSubmitReview} disabled={loading} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
                Submit for Review
              </button>
            )}
            {finding.status === 'pending_review' && !isReviewing && (
              <button className="btn btn-primary" onClick={onStartReview} style={{ fontSize: 12 }}>
                <CheckCircle2 size={13} /> Validate
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Plain English Explainer toggle */}
      {explanation && (
        <>
          <button
            onClick={() => setShowExplainer(v => !v)}
            style={{
              width: '100%', background: showExplainer ? 'rgba(99,102,241,0.08)' : 'rgba(99,102,241,0.04)',
              border: 'none', borderTop: '1px solid var(--border)',
              padding: '10px 20px', cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: 8,
              color: 'var(--accent-purple)', fontSize: 13, fontWeight: 600,
              fontFamily: 'inherit', textAlign: 'left',
              transition: 'background 0.15s',
            }}
          >
            <BookOpen size={14} />
            {explanation.emoji} What does this mean? (Plain English Guide)
            <span style={{ marginLeft: 'auto' }}>
              {showExplainer ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </span>
          </button>

          {showExplainer && (
            <div style={{
              padding: '20px 24px',
              background: urgencyConf ? urgencyConf.bg : 'rgba(99,102,241,0.04)',
              borderTop: `1px solid ${urgencyConf ? urgencyConf.border : 'var(--border)'}`,
            }}>
              {/* Urgency badge */}
              {urgencyConf && (
                <div style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  background: urgencyConf.bg, border: `1px solid ${urgencyConf.border}`,
                  borderRadius: 6, padding: '4px 12px', marginBottom: 16, fontSize: 12, fontWeight: 700,
                  color: urgencyConf.color,
                }}>
                  <AlertTriangle size={12} /> {urgencyConf.label}
                </div>
              )}

              <div style={{ display: 'grid', gap: 16, gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
                {/* What is this */}
                <ExplainerCard emoji="💡" title="What is this vulnerability?">
                  <p style={{ margin: 0, lineHeight: 1.7, fontSize: 13, color: 'var(--text-secondary)' }}>
                    {explanation.simpleExplanation}
                  </p>
                </ExplainerCard>

                {/* Analogy */}
                <ExplainerCard emoji="🧠" title="Simple Analogy">
                  <p style={{ margin: 0, lineHeight: 1.7, fontSize: 13, color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                    {explanation.analogy}
                  </p>
                </ExplainerCard>

                {/* What we scanned */}
                <ExplainerCard emoji="🔭" title="What did we scan?">
                  <p style={{ margin: 0, lineHeight: 1.7, fontSize: 13, color: 'var(--text-secondary)' }}>
                    {explanation.whatWeScanned}
                  </p>
                </ExplainerCard>

                {/* What was found */}
                <ExplainerCard emoji="🔍" title="What was found?">
                  <p style={{ margin: 0, lineHeight: 1.7, fontSize: 13, color: 'var(--text-secondary)' }}>
                    {explanation.whatWasFound}
                  </p>
                </ExplainerCard>

                {/* Real world risk */}
                <ExplainerCard emoji="⚠️" title="Real-World Risk" highlight={urgencyConf?.color}>
                  <p style={{ margin: 0, lineHeight: 1.7, fontSize: 13, color: 'var(--text-secondary)' }}>
                    {explanation.realWorldRisk}
                  </p>
                </ExplainerCard>

                {/* Who is affected */}
                <ExplainerCard emoji="👥" title="Who is affected?">
                  <p style={{ margin: 0, lineHeight: 1.7, fontSize: 13, color: 'var(--text-secondary)' }}>
                    {explanation.whoIsAffected}
                  </p>
                </ExplainerCard>
              </div>

              {/* What to do */}
              <div style={{
                marginTop: 16, background: 'var(--bg-card)',
                border: '1px solid var(--border)', borderRadius: 10, padding: '16px 20px',
              }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-green)', marginBottom: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
                  <CheckCircle2 size={15} /> What should you do next?
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {explanation.whatToDoNext.map((step, i) => (
                    <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                      <div style={{
                        width: 22, height: 22, borderRadius: '50%',
                        background: 'var(--accent-green-dim)',
                        border: '1px solid rgba(16,185,129,0.3)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: 11, fontWeight: 700, color: 'var(--accent-green)', flexShrink: 0, marginTop: 1,
                      }}>{i + 1}</div>
                      <span style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{step}</span>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 14, padding: '10px 14px', background: 'rgba(245, 158, 11, 0.08)', borderRadius: 8, border: '1px solid rgba(245, 158, 11, 0.2)', fontSize: 12, color: 'var(--text-muted)' }}>
                  ⚠️ <strong>Remember:</strong> This finding is <strong>INFERRED</strong> by an AI — not a confirmed vulnerability.
                  Have a qualified security professional verify before taking action.
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* Validation form */}
      {isReviewing && (
        <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border)', background: 'var(--bg-input)' }}>
          <div className="disclaimer-bar" style={{ marginBottom: 12 }}>
            <AlertTriangle size={13} />
            You are validating an <strong>INFERRED</strong> LLM finding. Review the evidence carefully before accepting.
          </div>
          <div style={{ display: 'flex', gap: 10, marginBottom: 10 }}>
            <input className="input" value={reviewer} onChange={e => setReviewer(e.target.value)} placeholder="Analyst name *" style={{ flex: 1 }} />
            <input className="input" value={comment} onChange={e => setComment(e.target.value)} placeholder="Comment (optional)" style={{ flex: 2 }} />
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <button className="btn btn-success" onClick={onAccept} disabled={!reviewer || loading}>
              <CheckCircle2 size={13} /> Validate as Real
            </button>
            <button className="btn btn-danger" onClick={onReject} disabled={!reviewer || loading}>
              <XCircle size={13} /> Reject (False Positive)
            </button>
            <button className="btn btn-secondary" onClick={onCancel}>Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ────────────────────────────────────────────────────────────

function ExplainerCard({ emoji, title, children, highlight }: {
  emoji: string; title: string; children: React.ReactNode; highlight?: string;
}) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${highlight ? `${highlight}30` : 'var(--border)'}`,
      borderRadius: 10, padding: '14px 16px',
    }}>
      <div style={{
        fontSize: 12, fontWeight: 700, color: highlight || 'var(--text-secondary)',
        marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6,
      }}>
        {emoji} {title}
      </div>
      {children}
    </div>
  );
}
