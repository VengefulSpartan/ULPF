import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export default function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      onClick={toggleTheme}
      aria-label="Toggle Theme (Dark/Light)"
      title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '34px',
        height: '34px',
        borderRadius: '6px',
        backgroundColor: 'var(--bg-surface-raised)',
        border: '1px solid var(--border-default)',
        color: 'var(--text-secondary)',
        cursor: 'pointer',
        padding: 0,
        outline: 'none'
      }}
    >
      <div className={`theme-icon-toggle ${theme === 'light' ? 'theme-icon-rotate' : ''}`}>
        {theme === 'dark' ? (
          <Sun size={16} color="var(--accent-warning)" />
        ) : (
          <Moon size={16} color="var(--text-primary)" />
        )}
      </div>
    </button>
  );
}
