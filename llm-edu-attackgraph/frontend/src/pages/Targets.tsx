import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import { Target as TargetIcon, Plus, Trash2, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function Targets() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [hostname, setHostname] = useState('');
  const [description, setDescription] = useState('');
  const [authNote, setAuthNote] = useState('');
  const [error, setError] = useState('');

  const { data: targets = [], isLoading } = useQuery({ queryKey: ['targets'], queryFn: apiClient.listTargets });

  const createMutation = useMutation({
    mutationFn: apiClient.createTarget,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['targets'] });
      setHostname(''); setDescription(''); setAuthNote(''); setError('');
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Failed to register target';
      setError(msg);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: apiClient.deleteTarget,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['targets'] }),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!hostname.trim()) { setError('Hostname is required'); return; }
    setError('');
    createMutation.mutate({ hostname: hostname.trim(), description, authorization_note: authNote });
  };

  return (
    <div className="page animate-fade-in">
      <div className="page-header">
        <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <TargetIcon size={24} color="var(--accent-blue)" /> Authorized Targets
        </h1>
        <p className="page-subtitle">Only registered, authorized targets can be scanned.</p>
      </div>

      <div className="disclaimer-bar" style={{ marginBottom: 24 }}>
        <AlertTriangle size={14} />
        <span>
          You must be explicitly authorized to scan any target. Only add targets you own or have written permission to test.
          The system will reject any target not on this allowlist.
        </span>
      </div>

      <div className="grid-2" style={{ gap: 24, alignItems: 'start' }}>
        {/* Add target form */}
        <div className="card">
          <div className="section-header">
            <Plus size={16} color="var(--accent-green)" />
            <span className="section-title">Register Target</span>
          </div>
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, display: 'block', marginBottom: 6 }}>
                Hostname / IP *
              </label>
              <input
                className="input"
                value={hostname}
                onChange={e => setHostname(e.target.value)}
                placeholder="localhost or 127.0.0.1"
              />
            </div>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, display: 'block', marginBottom: 6 }}>
                Description
              </label>
              <input
                className="input"
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="e.g. Local test environment"
              />
            </div>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, display: 'block', marginBottom: 6 }}>
                Authorization Note *
              </label>
              <input
                className="input"
                value={authNote}
                onChange={e => setAuthNote(e.target.value)}
                placeholder="e.g. My own server, written permission from owner"
              />
            </div>
            {error && (
              <div className="alert alert-danger">
                <AlertTriangle size={14} /> {error}
              </div>
            )}
            <button
              type="submit"
              className="btn btn-primary"
              disabled={createMutation.isPending}
            >
              <Plus size={14} />
              {createMutation.isPending ? 'Registering…' : 'Register Target'}
            </button>
            {createMutation.isSuccess && (
              <div className="alert alert-success">
                <CheckCircle2 size={14} /> Target registered successfully!
              </div>
            )}
          </form>
        </div>

        {/* Target list */}
        <div className="card">
          <div className="section-header">
            <TargetIcon size={16} color="var(--accent-blue)" />
            <span className="section-title">Registered Targets ({targets.length})</span>
          </div>
          {isLoading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 56 }} />)}
            </div>
          ) : targets.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)', fontSize: 13 }}>
              No targets registered yet.<br />Add your first authorized target.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {targets.map(t => (
                <div key={t.id} style={{
                  background: 'var(--bg-input)', borderRadius: 10,
                  padding: '12px 14px', border: '1px solid var(--border)',
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                      <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace' }}>
                        {t.hostname}
                      </span>
                      {t.authorized && <span className="badge badge-validated">authorized</span>}
                    </div>
                    {t.description && (
                      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{t.description}</div>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '6px 12px', fontSize: 12 }}
                      onClick={() => navigate(`/scans?target=${t.id}`)}
                    >
                      Scan
                    </button>
                    <button
                      className="btn btn-danger"
                      style={{ padding: '6px 10px' }}
                      onClick={() => deleteMutation.mutate(t.id)}
                      disabled={deleteMutation.isPending}
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
