import React from 'react';

export default function UlpfLogo({ size = 28, className = "" }) {
  return (
    <div
      style={{
        width: `${size}px`,
        height: `${size}px`,
        backgroundColor: 'var(--bg-surface-raised)',
        border: '1px solid var(--border-default)',
        borderRadius: '6px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '3px'
      }}
      className={className}
      title="ULPF — Many log formats unified into one OCSF schema"
    >
      <svg
        width="100%"
        height="100%"
        viewBox="0 0 32 32"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* Top 3 Diverging Lines */}
        <path d="M7 6 L16 18" stroke="var(--text-muted)" strokeWidth="2" strokeLinecap="round" />
        <path d="M16 6 L16 18" stroke="var(--text-muted)" strokeWidth="2" strokeLinecap="round" />
        <path d="M25 6 L16 18" stroke="var(--text-muted)" strokeWidth="2" strokeLinecap="round" />
        
        {/* Converged Solid Accent Line */}
        <path d="M16 18 L16 26" stroke="var(--accent-success)" strokeWidth="3" strokeLinecap="round" />
        
        {/* Convergence Junction Node */}
        <circle cx="16" cy="18" r="2" fill="var(--accent-success)" />
      </svg>
    </div>
  );
}
