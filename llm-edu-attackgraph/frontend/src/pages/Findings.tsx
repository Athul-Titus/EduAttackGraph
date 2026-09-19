import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient, Finding } from '../api/client';
import { Bug, AlertTriangle, CheckCircle2, XCircle, Clock, Filter } from 'lucide-react';

const STATUS_FILTERS = ['all', 'potential', 'pending_review', 'validated', 'rejected', 'needs_more_evidence'];

export default function Findings() {
  const [statusFilter, setStatusFilter] = useState('all');
  const [reviewer, setReviewer] = useState('');
  const [reviewingId, setReviewingId] = useState<string | null>(null);
  const [comment, setComment] = useState('');
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

  return (
    <div className="page animate-fade-in">
      <div className="page-header">
        <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Bug size={24} color="var(--accent-yellow)" /> Findings
        </h1>
        <p className="page-subtitle">Human-in-the-loop validation queue</p>
      </div>

      <div className="disclaimer-bar" style={{ marginBottom: 20 }}>
        <AlertTriangle size={14} />
        <span>
          All findings start as <strong>POTENTIAL (INFERRED)</strong> from LLM analysis.
          A finding is only <strong>VALIDATED</strong> after human analyst review.
          Never treat INFERRED findings as confirmed vulnerabilities.
        </span>
      </div>

      {/* Filter tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
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
              {s.replace('_', ' ').toUpperCase()}
              <span style={{
                background: active ? 'rgba(59,130,246,0.3)' : 'rgba(148,163,184,0.2)',
                borderRadius: 100, padding: '0 6px', fontSize: 11,
              }}>{count}</span>
            </button>
          );
        })}
      </div>

      {isLoading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 80 }} />)}
        </div>
      ) : findings.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
          <Bug size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
          <p style={{ fontSize: 15 }}>No findings {statusFilter !== 'all' ? `with status "${statusFilter}"` : 'yet'}</p>
          <p style={{ fontSize: 13, marginTop: 6 }}>Run a scan to generate findings</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {findings.map(f => (
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

  return (
    <div className="card" style={{
      borderLeft: `3px solid ${sc}`,
      animation: 'fadeIn 0.3s ease',
    }}>
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
              {finding.description.slice(0, 200)}{finding.description.length > 200 ? '…' : ''}
            </div>
          )}
        </div>
        <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
          {finding.status === 'potential' && (
            <button className="btn btn-secondary" onClick={onSubmitReview} disabled={loading} style={{ fontSize: 12 }}>
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

      {isReviewing && (
        <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
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
