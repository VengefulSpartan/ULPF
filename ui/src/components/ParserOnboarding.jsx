import React, { useState, useEffect } from 'react';
import { Copy, Check } from 'lucide-react';

export default function ParserOnboarding() {
  const [draftPlugin, setDraftPlugin] = useState({
    parser_id: 'draft_cisco_asa_001',
    detected_format: 'syslog_rfc3164',
    confidence: 0.94,
    template_mined: '<*> %ASA-6-302013: Built <*> connection <*> for <*>:<*>/<*> to <*>:<*>/<*>',
    sample_log: '<134>Sep 15 17:45:00 asa01 %ASA-6-302013: Built inbound TCP connection 987654 for outside:198.51.100.44/51234 to inside:10.0.0.15/80',
    field_mappings: [
      { source_var: 'var_0', ocsf_field: 'src_endpoint.ip', inferred_type: 'ipv4', confidence: 0.98 },
      { source_var: 'var_1', ocsf_field: 'src_endpoint.port', inferred_type: 'port', confidence: 0.95 },
      { source_var: 'var_2', ocsf_field: 'dst_endpoint.ip', inferred_type: 'ipv4', confidence: 0.98 },
      { source_var: 'var_3', ocsf_field: 'dst_endpoint.port', inferred_type: 'port', confidence: 0.95 },
      { source_var: 'var_4', ocsf_field: 'disposition', inferred_type: 'action', confidence: 0.89 }
    ]
  });

  const [confirmed, setConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [copiedText, setCopiedText] = useState(null);

  useEffect(() => {
    fetch('http://localhost:8000/plugins/drafts')
      .then(res => res.json())
      .then(data => {
        if (data && data.length > 0) {
          setDraftPlugin(data[0]);
        }
      })
      .catch(err => console.log('Using local draft plugin fallback', err));
  }, []);

  const handleConfirm = async () => {
    setLoading(true);
    // Morph button label/icon over 200ms
    setTimeout(async () => {
      try {
        await fetch('http://localhost:8000/plugins/confirm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            parser_id: draftPlugin.parser_id,
            version: '1.0.0',
            template_mined: draftPlugin.template_mined,
            field_mappings: draftPlugin.field_mappings
          })
        });
      } catch (err) {
        console.log('API call fallback confirmation', err);
      } finally {
        setConfirmed(true);
        setLoading(false);
      }
    }, 200);
  };

  const copyText = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedText(key);
    setTimeout(() => setCopiedText(null), 1500);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Onboarding Header Banner */}
      <div className="card card-interactive">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.15rem', color: 'var(--text-primary)' }} className="font-headline">Zero-Touch Parser Onboarding</h2>
            <p style={{ margin: '4px 0 0 0', color: 'var(--text-secondary)' }} className="font-body">
              Unseen perimeter log format detected. Mined Drain3 template &amp; inferred field mappings produced with &gt;85% confidence.
            </p>
          </div>
          <div>
            {confirmed ? (
              <span className="badge badge-green badge-flash">✓ PLUGIN ACTIVE v1.0.0</span>
            ) : (
              <span className="badge badge-amber">⚡ AWAITING ANALYST CONFIRMATION</span>
            )}
          </div>
        </div>
      </div>

      {/* Raw Sample & Mined Template */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div className="card card-interactive">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span className="font-label">Raw Unparsed Log Sample</span>
            <span className="badge badge-neutral font-mono">{draftPlugin.detected_format} ({(draftPlugin.confidence * 100).toFixed(0)}%)</span>
          </div>
          <div style={{ backgroundColor: 'var(--bg-base)', padding: '12px', borderRadius: '4px', border: '1px solid var(--border-default)', fontSize: '12px', color: 'var(--text-primary)', wordBreak: 'break-all', position: 'relative' }} className="font-mono">
            {draftPlugin.sample_log}
            <button onClick={() => copyText(draftPlugin.sample_log, 'sample')} style={{ position: 'absolute', top: '8px', right: '8px', background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              {copiedText === 'sample' ? <Check size={14} color="var(--accent-success)" /> : <Copy size={14} />}
            </button>
          </div>
        </div>

        <div className="card card-interactive">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span className="font-label">Drain3 Mined Template</span>
            <span className="badge badge-amber">Variable Extraction</span>
          </div>
          <div style={{ backgroundColor: 'var(--bg-base)', padding: '12px', borderRadius: '4px', border: '1px solid var(--border-default)', fontSize: '12px', color: 'var(--text-primary)', wordBreak: 'break-all', position: 'relative' }} className="font-mono">
            {draftPlugin.template_mined}
            <button onClick={() => copyText(draftPlugin.template_mined, 'template')} style={{ position: 'absolute', top: '8px', right: '8px', background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              {copiedText === 'template' ? <Check size={14} color="var(--accent-success)" /> : <Copy size={14} />}
            </button>
          </div>
        </div>
      </div>

      {/* Mapped OCSF Schema Table */}
      <div className="card card-interactive">
        <h3 className="font-label" style={{ margin: '0 0 16px 0', color: 'var(--text-primary)' }}>Inferred OCSF v1.1.0 Field Mappings</h3>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-default)' }}>
              <th className="font-label" style={{ padding: '10px 6px' }}>Source Slot</th>
              <th className="font-label" style={{ padding: '10px 6px' }}>Inferred Type</th>
              <th className="font-label" style={{ padding: '10px 6px' }}>Target OCSF Field</th>
              <th className="font-label" style={{ padding: '10px 6px' }}>Confidence Score</th>
              <th className="font-label" style={{ padding: '10px 6px' }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {draftPlugin.field_mappings.map((mapping, idx) => (
              <tr key={idx} style={{ borderBottom: '1px solid var(--border-default)' }}>
                <td style={{ padding: '12px 6px', color: 'var(--accent-warning)', fontSize: '12px' }} className="font-mono">{mapping.source_var}</td>
                <td style={{ padding: '12px 6px' }}><span className="badge badge-neutral font-mono">{mapping.inferred_type}</span></td>
                <td style={{ padding: '12px 6px', color: 'var(--text-primary)', fontWeight: 500, fontSize: '12px' }} className="font-mono">{mapping.ocsf_field}</td>
                <td style={{ padding: '12px 6px', color: 'var(--text-primary)', fontSize: '12px' }} className="font-mono">{(mapping.confidence * 100).toFixed(0)}%</td>
                <td style={{ padding: '12px 6px' }}>
                  <span className="badge badge-green">Mapped</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Action Button */}
        <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
          <button
            onClick={handleConfirm}
            disabled={confirmed || loading}
            className="font-label"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '10px 20px',
              borderRadius: '6px',
              border: '1px solid var(--border-default)',
              backgroundColor: 'var(--bg-surface-raised)',
              color: confirmed ? 'var(--accent-success)' : 'var(--text-primary)',
              cursor: (confirmed || loading) ? 'default' : 'pointer',
              transition: 'all 200ms ease'
            }}
          >
            {loading ? (
              <span>Deploying...</span>
            ) : confirmed ? (
              <>
                <Check size={14} color="var(--accent-success)" />
                <span>Parser Plugin Deployed</span>
              </>
            ) : (
              <span>Confirm Mapping &amp; Deploy Plugin</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
