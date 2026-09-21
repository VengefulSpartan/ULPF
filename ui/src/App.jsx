import React, { useState } from 'react';
import LiveStats from './components/LiveStats';
import ParserOnboarding from './components/ParserOnboarding';
import RCAGraph from './components/RCAGraph';
import LogExplained from './components/LogExplained';
import UlpfLogo from './components/UlpfLogo';
import ThemeToggle from './components/ThemeToggle';
import { ThemeProvider } from './context/ThemeContext';
import { Activity, BookOpen, Cpu, GitMerge, ShieldCheck } from 'lucide-react';

function DashboardContent() {
  const [activeTab, setActiveTab] = useState('stats');

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--bg-base)' }}>
      {/* Top Navbar */}
      <header style={{
        backgroundColor: 'var(--bg-surface)',
        borderBottom: '1px solid var(--border-default)',
        padding: '12px 24px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <UlpfLogo size={32} />
          <div>
            <h1 style={{ margin: 0, fontSize: '1.15rem', color: 'var(--text-primary)' }} className="font-headline">
              ULPF Security Operations Dashboard
            </h1>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }} className="font-body">
              Universal Log Pre-processing Framework (NTRO / SIH)
            </span>
          </div>
        </div>

        {/* Header Badges & Theme Toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div className="badge badge-green">
            <ShieldCheck size={14} /> AIR-GAPPED OFFLINE MODE
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }} className="font-mono">
            v1.1.0 (OCSF Schema)
          </div>
          <ThemeToggle />
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav style={{
        backgroundColor: 'var(--bg-base)',
        borderBottom: '1px solid var(--border-default)',
        padding: '0 24px',
        display: 'flex',
        gap: '8px'
      }}>
        <button
          onClick={() => setActiveTab('stats')}
          className="font-label"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '12px 18px',
            backgroundColor: 'transparent',
            border: 'none',
            borderBottom: activeTab === 'stats' ? '2px solid var(--text-primary)' : '2px solid transparent',
            color: activeTab === 'stats' ? 'var(--text-primary)' : 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'all 120ms ease'
          }}
        >
          <Activity size={14} /> Live Ingestion Stats
        </button>

        <button
          onClick={() => setActiveTab('onboarding')}
          className="font-label"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '12px 18px',
            backgroundColor: 'transparent',
            border: 'none',
            borderBottom: activeTab === 'onboarding' ? '2px solid var(--accent-warning)' : '2px solid transparent',
            color: activeTab === 'onboarding' ? 'var(--accent-warning)' : 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'all 120ms ease'
          }}
        >
          <Cpu size={14} /> Parser Onboarding
        </button>

        <button
          onClick={() => setActiveTab('rca')}
          className="font-label"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '12px 18px',
            backgroundColor: 'transparent',
            border: 'none',
            borderBottom: activeTab === 'rca' ? '2px solid var(--accent-critical)' : '2px solid transparent',
            color: activeTab === 'rca' ? 'var(--accent-critical)' : 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'all 120ms ease'
          }}
        >
          <GitMerge size={14} /> RCA Causal Graph
        </button>

        <button
          onClick={() => setActiveTab('explained')}
          className="font-label"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '12px 18px',
            backgroundColor: 'transparent',
            border: 'none',
            borderBottom: activeTab === 'explained' ? '2px solid var(--accent-success)' : '2px solid transparent',
            color: activeTab === 'explained' ? 'var(--accent-success)' : 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'all 120ms ease'
          }}
        >
          <BookOpen size={14} /> Log Explained
        </button>
      </nav>

      {/* Main Content Body with Tab Panel Switch Transition */}
      <main style={{ flex: 1, padding: '24px' }}>
        <div key={activeTab} className="tab-panel">
          {activeTab === 'stats' && <LiveStats />}
          {activeTab === 'onboarding' && <ParserOnboarding />}
          {activeTab === 'rca' && <RCAGraph />}
          {activeTab === 'explained' && <LogExplained />}
        </div>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <DashboardContent />
    </ThemeProvider>
  );
}
