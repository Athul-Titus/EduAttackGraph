import React from 'react';
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from './context/AuthContext';
import Dashboard from './pages/Dashboard';
import Targets from './pages/Targets';
import NewScan from './pages/NewScan';
import ScanDetail from './pages/ScanDetail';
import Findings from './pages/Findings';
import DemoPage from './pages/Demo';
import { Shield, LayoutDashboard, Target, Scan, Bug, FlaskConical, LogIn, LogOut, ShieldCheck } from 'lucide-react';

const qc = new QueryClient({ defaultOptions: { queries: { refetchOnWindowFocus: false, staleTime: 10000 } } });

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/targets', icon: Target, label: 'Targets' },
  { to: '/scans', icon: Scan, label: 'Scans' },
  { to: '/findings', icon: Bug, label: 'Findings' },
  { to: '/demo', icon: FlaskConical, label: 'Demo Mode' },
];

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <BrowserRouter>
          <div style={{ display: 'flex', minHeight: '100vh' }}>
            {/* Sidebar */}
            <Sidebar />
            {/* Main content */}
            <main style={{ flex: 1, overflow: 'auto' }}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/targets" element={<Targets />} />
                <Route path="/scans" element={<NewScan />} />
                <Route path="/scans/:scanId" element={<ScanDetail />} />
                <Route path="/findings" element={<Findings />} />
                <Route path="/demo" element={<DemoPage />} />
              </Routes>
            </main>
          </div>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

function Sidebar() {
  const { user, isAdmin, logout, openLoginModal } = useAuth();

  return (
    <nav style={{
      width: 230,
      background: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      padding: '0 0 16px',
      position: 'sticky',
      top: 0,
      height: '100vh',
      overflowY: 'auto',
      flexShrink: 0,
    }}>
      {/* Logo */}
      <div style={{ padding: '20px 20px 16px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: 'linear-gradient(135deg, #1d4ed8, #06b6d4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 16px rgba(59,130,246,0.4)',
          }}>
            <Shield size={18} color="white" />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.1 }}>EduAttack</div>
            <div style={{ fontSize: 10, color: 'var(--accent-cyan)', fontWeight: 600, letterSpacing: 1 }}>LLM GRAPH</div>
          </div>
        </div>
      </div>

      {/* Nav links */}
      <div style={{ padding: '12px 10px', flex: 1 }}>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase', padding: '8px 10px 6px' }}>
          Navigation
        </div>
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '8px 12px',
              borderRadius: 8,
              textDecoration: 'none',
              fontSize: 13,
              fontWeight: 500,
              marginBottom: 2,
              color: isActive ? 'var(--accent-blue)' : 'var(--text-secondary)',
              background: isActive ? 'var(--accent-blue-dim)' : 'transparent',
              transition: 'all 0.15s',
              border: isActive ? '1px solid rgba(59,130,246,0.2)' : '1px solid transparent',
            })}
          >
            <Icon size={15} />
            {label}
          </NavLink>
        ))}
      </div>

      {/* Admin Auth Status / Action Widget */}
      <div style={{ padding: '12px 12px 8px', borderTop: '1px solid var(--border)' }}>
        {user ? (
          <div style={{
            background: 'rgba(16, 185, 129, 0.08)',
            border: '1px solid rgba(16, 185, 129, 0.25)',
            borderRadius: 8,
            padding: '10px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <ShieldCheck size={14} color="#10b981" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#10b981', letterSpacing: 0.5 }}>
                  {isAdmin ? 'ADMIN' : 'USER'}
                </span>
              </div>
              <button
                onClick={logout}
                title="Sign out"
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  padding: 2,
                }}
                onMouseEnter={e => e.currentTarget.style.color = '#ef4444'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
              >
                <LogOut size={13} />
              </button>
            </div>
            <div style={{
              fontSize: 11,
              color: 'var(--text-primary)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              fontFamily: 'JetBrains Mono, monospace',
            }}>
              {user.email}
            </div>
          </div>
        ) : (
          <button
            onClick={openLoginModal}
            className="btn btn-primary"
            style={{
              width: '100%',
              padding: '8px 12px',
              fontSize: 12,
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 8,
              background: 'linear-gradient(135deg, #1e40af, #2563eb)',
              boxShadow: '0 0 14px rgba(37, 99, 235, 0.3)',
            }}
          >
            <LogIn size={14} />
            Admin Login
          </button>
        )}
      </div>

      {/* Footer */}
      <div style={{ padding: '8px 16px 4px' }}>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.4 }}>
          LLM-EduAttackGraph v0.1.0<br />
          <span style={{ color: 'rgba(245,158,11,0.7)' }}>⚠ Research Tool</span>
        </div>
      </div>
    </nav>
  );
}

