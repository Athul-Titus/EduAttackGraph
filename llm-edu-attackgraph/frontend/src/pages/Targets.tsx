import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { Target as TargetIcon, Plus, Trash2, AlertTriangle, CheckCircle2, ShieldCheck, ShieldAlert, LogIn, Lock } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function Targets() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { user, isAdmin, openLoginModal } = useAuth();

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

  const toggleAuthMutation = useMutation({
    mutationFn: apiClient.toggleTargetAuth,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['targets'] }),
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Failed to toggle authorization';
      setError(msg);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!hostname.trim()) { setError('Hostname or IP is required'); return; }
    setError('');
    createMutation.mutate({
      hostname: hostname.trim(),
      description,
      authorization_note: authNote || (isAdmin ? `Authorized by Admin (${user?.email})` : undefined),
    });
  };

  return (
    <div className="page animate-fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <TargetIcon size={24} color="var(--accent-blue)" /> Authorized Targets
          </h1>
          <p className="page-subtitle">Registered target hosts and IP addresses for LLM-EduAttackGraph vulnerability analysis.</p>
        </div>

        {isAdmin ? (
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            padding: '8px 14px',
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            borderRadius: 10,
            fontSize: 13,
            color: '#10b981',
            fontWeight: 600,
          }}>
            <ShieldCheck size={18} />
            <span>Admin Target Control: Full Authorization Active</span>
          </div>
        ) : (
          <button
            onClick={openLoginModal}
            className="btn btn-secondary"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              fontSize: 13,
              border: '1px solid rgba(59, 130, 246, 0.4)',
              color: 'var(--accent-blue)',
            }}
          >
            <LogIn size={15} />
            Admin Login to Add Custom Targets
          </button>
        )}
      </div>

      {/* Notice Banner */}
      {isAdmin ? (
        <div style={{
          marginBottom: 24,
          padding: '12px 16px',
          borderRadius: 8,
          background: 'rgba(59, 130, 246, 0.08)',
          border: '1px solid rgba(59, 130, 246, 0.25)',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          fontSize: 13,
          color: 'var(--text-secondary)',
        }}>
          <ShieldCheck size={18} color="var(--accent-blue)" style={{ flexShrink: 0 }} />
          <div>
            <strong style={{ color: 'var(--text-primary)' }}>Administrator Privileges Active: </strong>
            Logged in as <code style={{ color: 'var(--accent-cyan)' }}>{user?.email}</code>. You can register, authorize, or revoke any custom educational portal or IP address directly from this dashboard.
          </div>
        </div>
      ) : (
        <div className="disclaimer-bar" style={{ marginBottom: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <AlertTriangle size={16} style={{ flexShrink: 0 }} />
            <span>
              Standard Mode: Target allowlist restriction is active. To register custom domains or IPs, log in with your administrator account.
            </span>
          </div>
          <button
            onClick={openLoginModal}
            className="btn btn-primary"
            style={{ padding: '4px 12px', fontSize: 12 }}
          >
            Log In Now
          </button>
        </div>
      )}

      <div className="grid-2" style={{ gap: 24, alignItems: 'start' }}>
        {/* Add target form */}
        <div className="card">
          <div className="section-header">
            <Plus size={16} color="var(--accent-green)" />
            <span className="section-title">
              {isAdmin ? 'Register & Authorize Target (Admin)' : 'Register Target (Allowlisted)'}
            </span>
          </div>
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, display: 'block', marginBottom: 6 }}>
                Hostname / IP Address *
              </label>
              <input
                className="input"
                value={hostname}
                onChange={e => setHostname(e.target.value)}
                placeholder={isAdmin ? "e.g. demo.edu-portal.ac.in or 192.168.1.50" : "localhost or 127.0.0.1"}
              />
              <span style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, display: 'block' }}>
                {isAdmin
                  ? "✓ As Administrator, any valid hostname or IPv4 will be saved and authorized."
                  : "ℹ Standard mode only allows addresses on the server's predefined allowlist."}
              </span>
            </div>

            <div>
              <label style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, display: 'block', marginBottom: 6 }}>
                Description
              </label>
              <input
                className="input"
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="e.g. University Student Portal / Staging LMS"
              />
            </div>

            <div>
              <label style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, display: 'block', marginBottom: 6 }}>
                Authorization Note {isAdmin ? '(Optional)' : '*'}
              </label>
              <input
                className="input"
                value={authNote}
                onChange={e => setAuthNote(e.target.value)}
                placeholder={isAdmin ? `Default: Authorized by Admin (${user?.email})` : "e.g. Written permission from institution"}
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
              style={{
                background: isAdmin ? 'linear-gradient(135deg, #059669, #10b981)' : undefined,
                boxShadow: isAdmin ? '0 0 16px rgba(16, 185, 129, 0.3)' : undefined,
              }}
            >
              <Plus size={14} />
              {createMutation.isPending ? 'Registering…' : (isAdmin ? 'Authorize & Add Target' : 'Register Target')}
            </button>

            {createMutation.isSuccess && (
              <div className="alert alert-success">
                <CheckCircle2 size={14} /> Target registered and authorized successfully!
              </div>
            )}
          </form>
        </div>

        {/* Target list */}
        <div className="card">
          <div className="section-header" style={{ justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <TargetIcon size={16} color="var(--accent-blue)" />
              <span className="section-title">Registered Targets ({targets.length})</span>
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {targets.filter(t => t.authorized).length} active / authorized
            </span>
          </div>

          {isLoading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[1, 2, 3].map(i => <div key={i} className="skeleton" style={{ height: 56 }} />)}
            </div>
          ) : targets.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)', fontSize: 13 }}>
              No targets registered yet.<br />Add your first authorized target using the form.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {targets.map(t => (
                <div key={t.id} style={{
                  background: 'var(--bg-input)', borderRadius: 10,
                  padding: '12px 14px', border: '1px solid var(--border)',
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  gap: 12,
                }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace' }}>
                        {t.hostname}
                      </span>
                      {t.authorized ? (
                        <span className="badge badge-validated" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          <ShieldCheck size={11} /> authorized
                        </span>
                      ) : (
                        <span className="badge badge-needs-evidence" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          <ShieldAlert size={11} /> unauthorized
                        </span>
                      )}
                    </div>
                    {t.description && (
                      <div style={{ fontSize: 12, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {t.description}
                      </div>
                    )}
                    {t.authorization_note && (
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', opacity: 0.75, marginTop: 2 }}>
                        Note: {t.authorization_note}
                      </div>
                    )}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                    {t.authorized ? (
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '6px 12px', fontSize: 12 }}
                        onClick={() => navigate(`/scans?target=${t.id}`)}
                        title="Start scan against this target"
                      >
                        Scan
                      </button>
                    ) : (
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '6px 12px', fontSize: 12, opacity: 0.5 }}
                        disabled
                        title="Target must be authorized to scan"
                      >
                        Scan
                      </button>
                    )}

                    {isAdmin && (
                      <button
                        className="btn btn-secondary"
                        style={{
                          padding: '6px 10px',
                          fontSize: 11,
                          color: t.authorized ? '#f59e0b' : '#10b981',
                          borderColor: t.authorized ? 'rgba(245, 158, 11, 0.3)' : 'rgba(16, 185, 129, 0.3)',
                        }}
                        onClick={() => toggleAuthMutation.mutate(t.id)}
                        disabled={toggleAuthMutation.isPending}
                        title={t.authorized ? "Revoke Authorization" : "Grant Authorization"}
                      >
                        {t.authorized ? 'Revoke' : 'Authorize'}
                      </button>
                    )}

                    <button
                      className="btn btn-danger"
                      style={{ padding: '6px 10px' }}
                      onClick={() => deleteMutation.mutate(t.id)}
                      disabled={deleteMutation.isPending}
                      title="Delete Target"
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

