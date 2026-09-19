import React from 'react';
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Dashboard from './pages/Dashboard';
import Targets from './pages/Targets';
import NewScan from './pages/NewScan';
import ScanDetail from './pages/ScanDetail';
import Findings from './pages/Findings';
import DemoPage from './pages/Demo';
import { Shield, LayoutDashboard, Target, Scan, Bug, FlaskConical, Zap } from 'lucide-react';

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
    </QueryClientProvider>
  );
}

function Sidebar() {
  return (
    <nav style={{
      width: 220,
      background: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      padding: '0 0 24px',
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

      {/* Footer */}
      <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)' }}>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.5 }}>
          LLM-EduAttackGraph v0.1.0<br />
          <span style={{ color: 'rgba(245,158,11,0.7)' }}>⚠ Research Tool</span>
        </div>
      </div>
    </nav>
  );
}
