import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Shield, KeyRound, Lock, X, AlertCircle, CheckCircle2 } from 'lucide-react';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose }) => {
  const { login } = useAuth();
  const [email, setEmail] = useState('titusathul8@gmail.com');
  const [password, setPassword] = useState('ATHUL321');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await login(email, password);
      setSuccess(true);
      setTimeout(() => {
        setSuccess(false);
        onClose();
      }, 700);
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string } } };
      setError(axiosErr?.response?.data?.detail || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'rgba(0, 0, 0, 0.75)',
        backdropFilter: 'blur(6px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 20,
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 420,
          background: 'var(--bg-secondary, #111827)',
          border: '1px solid var(--border, #374151)',
          borderRadius: 14,
          padding: '28px 24px',
          boxShadow: '0 20px 40px rgba(0,0,0,0.6), 0 0 24px rgba(59,130,246,0.15)',
          position: 'relative',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: 16,
            right: 16,
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted, #9ca3af)',
            cursor: 'pointer',
            padding: 4,
          }}
        >
          <X size={18} />
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
          <div
            style={{
              width: 40,
              height: 40,
              borderRadius: 10,
              background: 'linear-gradient(135deg, #2563eb, #06b6d4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 16px rgba(37,99,235,0.4)',
            }}
          >
            <Shield size={22} color="#ffffff" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: 'var(--text-primary, #f9fafb)' }}>
              Administrator Login
            </h3>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted, #9ca3af)' }}>
              Authorize and manage scanning targets
            </p>
          </div>
        </div>

        {error && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '10px 14px',
              borderRadius: 8,
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: '#f87171',
              fontSize: 13,
              marginBottom: 16,
            }}
          >
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '10px 14px',
              borderRadius: 8,
              background: 'rgba(16, 185, 129, 0.15)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              color: '#34d399',
              fontSize: 13,
              marginBottom: 16,
            }}
          >
            <CheckCircle2 size={16} />
            <span>Authenticated successfully! Redirecting...</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #d1d5db)', marginBottom: 6 }}>
              Administrator Email
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="titusathul8@gmail.com"
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  background: 'var(--bg-primary, #030712)',
                  border: '1px solid var(--border, #374151)',
                  borderRadius: 8,
                  color: 'white',
                  fontSize: 13,
                  outline: 'none',
                  boxSizing: 'border-box',
                }}
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #d1d5db)', marginBottom: 6 }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  background: 'var(--bg-primary, #030712)',
                  border: '1px solid var(--border, #374151)',
                  borderRadius: 8,
                  color: 'white',
                  fontSize: 13,
                  outline: 'none',
                  boxSizing: 'border-box',
                }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || success}
            style={{
              marginTop: 6,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 8,
              padding: '10px 16px',
              borderRadius: 8,
              background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
              border: 'none',
              color: 'white',
              fontSize: 13,
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.7 : 1,
              transition: 'background 0.2s',
            }}
          >
            <Lock size={15} />
            {loading ? 'Authenticating...' : 'Sign In as Administrator'}
          </button>
        </form>

        <div style={{ marginTop: 18, paddingTop: 14, borderTop: '1px solid var(--border, #374151)', display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted, #9ca3af)' }}>
          <KeyRound size={14} color="#60a5fa" />
          <span>Configured admin: <b>titusathul8@gmail.com</b></span>
        </div>
      </div>
    </div>
  );
};
