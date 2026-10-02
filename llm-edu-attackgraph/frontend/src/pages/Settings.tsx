import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import { Settings, Cpu, Database, Shield, AlertTriangle, CheckCircle2, Activity } from 'lucide-react';

export default function SettingsPage() {
  const { data: health, isLoading: hLoading } = useQuery({
    queryKey: ['health'],
    queryFn: apiClient.getHealth,
    refetchInterval: 30000,
  });
  const { data: config, isLoading: cLoading } = useQuery({
    queryKey: ['config'],
    queryFn: apiClient.getConfig,
  });

  const isLoading = hLoading || cLoading;

  return (
    <div className="page animate-fade-in">
      <div className="page-header">
        <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Settings size={24} color="var(--accent-purple)" /> System Settings
        </h1>
        <p className="page-subtitle">Live configuration and system status — read-only view</p>
      </div>

      <div className="disclaimer-bar" style={{ marginBottom: 20 }}>
        <AlertTriangle size={14} />
        <span>
          Settings are loaded from <strong>.env</strong> and are read-only from this panel.
          To change configuration, edit the <strong>backend/.env</strong> file and restart the backend.
        </span>
      </div>

      {isLoading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {[1, 2, 3].map(i => <div key={i} className="skeleton" style={{ height: 120 }} />)}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* System Status */}
          <div className="card">
            <div className="section-header">
              <Activity size={16} color="var(--accent-green)" />
              <span className="section-title">System Status</span>
              <span className={`badge ${health?.status === 'healthy' ? 'badge-observed' : 'badge-inferred'}`}>
                {health?.status?.toUpperCase() || 'UNKNOWN'}
              </span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
              <StatusRow
                label="Backend API"
                value={health?.status === 'healthy' ? 'Online' : 'Offline'}
                ok={health?.status === 'healthy'}
              />
              <StatusRow
                label="FAISS Index"
                value={health?.faiss_index_ready ? `Ready (${health.faiss_num_vectors} vectors)` : 'Not Built'}
                ok={health?.faiss_index_ready ?? null}
              />
              <StatusRow
                label="Demo Mode"
                value={health?.demo_mode ? 'Active (synthetic data)' : 'Disabled (production)'}
                ok={health?.demo_mode === true ? false : health?.demo_mode === false ? true : null}
                okColor="var(--accent-green)"
                failColor="var(--accent-yellow)"
              />
              <StatusRow
                label="Environment"
                value={health?.app_env || 'N/A'}
                ok={health?.app_env !== 'production' ? null : true}
              />
            </div>
          </div>

          {/* LLM Provider */}
          <div className="card">
            <div className="section-header">
              <Cpu size={16} color="var(--accent-purple)" />
              <span className="section-title">LLM Provider</span>
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14 }}>
              The Large Language Model used for Stage 2 (Vulnerability Analysis). All outputs are <strong>INFERRED</strong> — not confirmed.
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
              <ConfigRow label="Provider" value={health?.llm_provider || config?.llm_provider || 'N/A'} mono />
              <ConfigRow label="Similarity Threshold" value={`${health?.similarity_threshold ?? config?.similarity_threshold ?? 'N/A'}`}
                note="From research paper — cosine similarity ≥ 0.6 triggers LLM analysis" />
              <ConfigRow label="Top-K Results" value={`${config?.top_k ?? 'N/A'}`}
                note="Maximum knowledge-base documents retrieved per scan" />
              <ConfigRow label="Paper Reference" value="Liu et al., IEEE IoT Journal, 2026" />
            </div>
          </div>

          {/* Embedding Model */}
          <div className="card">
            <div className="section-header">
              <Database size={16} color="var(--accent-cyan)" />
              <span className="section-title">Embedding Model & FAISS Index</span>
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14 }}>
              Sentence embeddings convert fingerprint text into vectors for similarity comparison (FAISS IndexFlatIP with cosine normalization).
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
              <ConfigRow label="Model" value={health?.embedding_model || config?.embedding_model || 'N/A'} mono />
              <ConfigRow label="FAISS Vectors" value={`${health?.faiss_num_vectors ?? 0}`}
                note="Number of vulnerability descriptions indexed" />
              <ConfigRow label="Chunk Size" value={`${config?.chunk_size ?? 'N/A'} tokens`} />
              <ConfigRow label="Chunk Overlap" value={`${config?.chunk_overlap ?? 'N/A'} tokens`} />
            </div>
          </div>

          {/* Authorization */}
          <div className="card">
            <div className="section-header">
              <Shield size={16} color="var(--accent-blue)" />
              <span className="section-title">Authorization & Scanning Policy</span>
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14 }}>
              Only explicitly authorized targets can be scanned. This is an ethical requirement — never scan systems you don't own or have permission to test.
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
              <ConfigRow
                label="Authorization Mode"
                value={config?.authorized_target_mode || 'N/A'}
                mono
              />
              <ConfigRow label="Port Scan Range" value={config?.port_scan_range || 'N/A'} mono />
            </div>
            {config?.allowed_targets && Array.isArray(config.allowed_targets) && config.allowed_targets.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase' }}>
                  Static Allowlist
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {(config.allowed_targets as string[]).map((t: string) => (
                    <span key={t} style={{
                      fontSize: 12, fontFamily: 'JetBrains Mono, monospace',
                      background: 'var(--bg-input)', border: '1px solid var(--border)',
                      borderRadius: 6, padding: '4px 10px', color: 'var(--accent-cyan)',
                    }}>{t}</span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Research paper info */}
          <div className="card" style={{ background: 'linear-gradient(135deg, rgba(99,102,241,0.06) 0%, rgba(6,182,212,0.04) 100%)' }}>
            <div className="section-header">
              <Shield size={16} color="var(--accent-purple)" />
              <span className="section-title">Research Paper Reference</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 16 }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 4 }}>TITLE</div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5 }}>
                  LLM-Assisted Security Vulnerability Analysis for Educational Websites: Risk Identification via LLM-EduAttackGraph
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 4 }}>PUBLISHED</div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)' }}>IEEE Internet of Things Journal, 2026</div>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 4 }}>METHODOLOGY</div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)' }}>
                  Algorithm 1 (Fingerprinting) + Algorithm 2 (RAG + LLM Inference) + Human Validation
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 4 }}>DATASET</div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)' }}>
                  961 educational website vulnerabilities across 6 categories (Awesome-POC)
                </div>
              </div>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}

function StatusRow({ label, value, ok, okColor, failColor }: {
  label: string; value: string; ok: boolean | null;
  okColor?: string; failColor?: string;
}) {
  const successColor = okColor || 'var(--accent-green)';
  const errorColor = failColor || 'var(--accent-red)';
  return (
    <div style={{ background: 'var(--bg-input)', borderRadius: 10, padding: '10px 14px', border: '1px solid var(--border)' }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 6 }}>{label}</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {ok === true && <CheckCircle2 size={14} color={successColor} />}
        {ok === false && <AlertTriangle size={14} color={errorColor} />}
        <span style={{
          fontSize: 13, fontWeight: 600,
          color: ok === true ? successColor : ok === false ? errorColor : 'var(--text-secondary)',
        }}>{value}</span>
      </div>
    </div>
  );
}

function ConfigRow({ label, value, mono = false, note }: {
  label: string; value: string; mono?: boolean; note?: string;
}) {
  return (
    <div style={{ background: 'var(--bg-input)', borderRadius: 10, padding: '10px 14px', border: '1px solid var(--border)' }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 4 }}>{label}</div>
      <div style={{
        fontSize: 14, fontWeight: 600,
        color: 'var(--text-primary)',
        fontFamily: mono ? 'JetBrains Mono, monospace' : 'inherit',
      }}>{value}</div>
      {note && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.4 }}>{note}</div>}
    </div>
  );
}
