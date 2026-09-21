import React, { useState } from 'react';
import { BookOpen, FileCode, ShieldAlert, Sparkles } from 'lucide-react';

export default function LogExplained() {
  const [events, setEvents] = useState([
    {
      uuid: 'evt-001-firewall-block',
      raw_log: 'CEF:0|CheckPoint|Firewall-1|1.0.0|100|Traffic Log|4|src=192.168.1.50 dst=10.0.0.5 spt=54321 dpt=80 user=attacker_x act=BLOCK',
      ocsf: {
        class_name: 'Network Activity',
        class_uid: 4001,
        activity_name: 'Traffic Log',
        disposition: 'BLOCK',
        src_endpoint: { ip: '192.168.1.50', port: 54321 },
        dst_endpoint: { ip: '10.0.0.5', port: 80 },
        user: { name: 'attacker_x' }
      },
      explanation: 'Perimeter firewall blocked an inbound network traffic attempt from 192.168.1.50:54321 to destination 10.0.0.5:80.',
      intent: 'policy_violation'
    },
    {
      uuid: 'evt-002-ids-alert',
      raw_log: '<132>Sep 15 17:45:30 ids01 suricata[4102]: [1:2001211:3] ET SCAN Potential SSH Scan [Classification: Attempted Reconnaissance] [Priority: 1] {TCP} 192.168.1.50:54321 -> 10.0.0.5:80',
      ocsf: {
        class_name: 'Security Finding',
        class_uid: 2001,
        activity_name: 'IDS Alert',
        disposition: 'ALERT',
        src_endpoint: { ip: '192.168.1.50', port: 54321 },
        dst_endpoint: { ip: '10.0.0.5', port: 80 }
      },
      explanation: 'Intrusion Detection System (IDS) flagged suspicious activity originating from 192.168.1.50 targeting 10.0.0.5.',
      intent: 'reconnaissance'
    },
    {
      uuid: 'evt-003-failed-auth',
      raw_log: 'LEEF:1.0|Linux|PAM|1.0|FailedAuth|src=192.168.1.50 usrName=attacker_x status=FAILURE',
      ocsf: {
        class_name: 'Authentication',
        class_uid: 3002,
        activity_name: 'Logon Attempt',
        disposition: 'FAILURE',
        src_endpoint: { ip: '192.168.1.50' },
        user: { name: 'attacker_x' }
      },
      explanation: "Failed authentication attempt for user 'attacker_x' originating from host IP 192.168.1.50.",
      intent: 'credential_attack'
    },
    {
      uuid: 'evt-004-process-spawn',
      raw_log: '{"event_id": 4688, "host": "server-01", "user": "attacker_x", "process": "cmd.exe", "disposition": "SUCCESS"}',
      ocsf: {
        class_name: 'System Activity',
        class_uid: 1001,
        activity_name: 'Process Execution',
        disposition: 'SUCCESS',
        device: { hostname: 'server-01' },
        user: { name: 'attacker_x' },
        process: { name: 'cmd.exe' }
      },
      explanation: "Process 'cmd.exe' was spawned by user 'attacker_x' on device 'server-01'.",
      intent: 'exfiltration_attempt'
    }
  ]);

  const [selectedUuid, setSelectedUuid] = useState('evt-001-firewall-block');

  const getIntentBadge = (intent) => {
    switch (intent) {
      case 'credential_attack':
      case 'exfiltration_attempt':
        return <span className="badge badge-red font-mono">⚡ {intent.toUpperCase()}</span>;
      case 'policy_violation':
        return <span className="badge badge-amber font-mono">⚠ POLICY VIOLATION</span>;
      case 'reconnaissance':
        return <span className="badge badge-green font-mono">🔍 RECONNAISSANCE</span>;
      default:
        return <span className="badge badge-neutral font-mono">⚙ OPERATIONAL NOISE</span>;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div className="card card-interactive">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.15rem', color: 'var(--text-primary)' }} className="font-headline">
              Semantic Annotation Layer ("Log Explained")
            </h2>
            <p style={{ margin: '4px 0 0 0', color: 'var(--text-secondary)' }} className="font-body">
              Deterministic rule-based translation converting raw payloads into plain-English explanations &amp; security intent tags.
            </p>
          </div>
          <div>
            <span className="badge badge-green">
              <Sparkles size={12} /> AIR-GAPPED RULE ENGINE
            </span>
          </div>
        </div>
      </div>

      {/* 3-Column Cards List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {events.map((evt) => (
          <div
            key={evt.uuid}
            onClick={() => setSelectedUuid(evt.uuid)}
            className="card card-interactive"
            style={{
              borderColor: selectedUuid === evt.uuid ? 'var(--border-strong)' : 'var(--border-default)',
              backgroundColor: selectedUuid === evt.uuid ? 'var(--bg-surface-raised)' : 'var(--bg-surface)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <span className="font-mono" style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                {evt.uuid}
              </span>
              <div>{getIntentBadge(evt.intent)}</div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr', gap: '16px' }}>
              {/* Column 1: Raw Payload */}
              <div style={{ backgroundColor: 'var(--bg-base)', padding: '12px', borderRadius: '4px', border: '1px solid var(--border-default)', overflow: 'hidden' }}>
                <div className="font-label" style={{ marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <FileCode size={12} /> Column 1: Raw Log Payload
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-primary)', wordBreak: 'break-all', lineHeight: '1.4' }} className="font-mono">
                  {evt.raw_log}
                </div>
              </div>

              {/* Column 2: OCSF Standardized Schema */}
              <div style={{ backgroundColor: 'var(--bg-base)', padding: '12px', borderRadius: '4px', border: '1px solid var(--border-default)', overflow: 'hidden' }}>
                <div className="font-label" style={{ marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <ShieldAlert size={12} /> Column 2: OCSF v1.1.0 Fields
                </div>
                <div style={{ fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '4px' }} className="font-mono">
                  <div><span style={{ color: 'var(--text-secondary)' }}>Class:</span> <span style={{ color: 'var(--text-primary)' }}>{evt.ocsf.class_name} ({evt.ocsf.class_uid})</span></div>
                  <div><span style={{ color: 'var(--text-secondary)' }}>Activity:</span> <span style={{ color: 'var(--text-primary)' }}>{evt.ocsf.activity_name}</span></div>
                  <div><span style={{ color: 'var(--text-secondary)' }}>Disposition:</span> <span style={{ color: evt.ocsf.disposition === 'BLOCK' || evt.ocsf.disposition === 'FAILURE' ? 'var(--accent-critical)' : 'var(--accent-success)', fontWeight: 600 }}>{evt.ocsf.disposition}</span></div>
                  {evt.ocsf.src_endpoint && <div><span style={{ color: 'var(--text-secondary)' }}>Src IP:</span> <span style={{ color: 'var(--text-primary)' }}>{evt.ocsf.src_endpoint.ip}</span></div>}
                </div>
              </div>

              {/* Column 3: Plain-English Explanation */}
              <div style={{ backgroundColor: 'var(--bg-base)', padding: '12px', borderRadius: '4px', border: '1px solid var(--border-default)', borderLeft: '3px solid var(--accent-success)', overflow: 'hidden' }}>
                <div className="font-label" style={{ marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <BookOpen size={12} /> Column 3: Plain-English Explanation
                </div>
                <div style={{ color: 'var(--text-primary)', lineHeight: '1.5' }} className="font-body">
                  "{evt.explanation}"
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
