import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { useTheme } from '../context/ThemeContext';

export default function RCAGraph() {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [rcaData, setRcaData] = useState(null);
  const { theme } = useTheme();

  useEffect(() => {
    fetch('http://localhost:8000/rca/inc-1001?window_seconds=300')
      .then(res => res.json())
      .then(data => {
        setRcaData(data);
        initCytoscape(data, theme);
      })
      .catch(err => {
        console.log('Using local RCA fallback', err);
        const fallback = {
          incident_id: 'inc-1001',
          total_events: 4,
          root_causes: [
            {
              rank: 1,
              event_uuid: 'evt-001-firewall-block',
              score: 0.885,
              explanation: 'Perimeter firewall blocked an inbound network traffic attempt from 192.168.1.50:54321 to destination 10.0.0.5:80.',
              intent: 'policy_violation',
              chained_narrative: 'Initially, perimeter firewall blocked an inbound network traffic attempt from 192.168.1.50:54321 to destination 10.0.0.5:80. Subsequently, intrusion detection system (IDS) flagged suspicious activity originating from 192.168.1.50 targeting 10.0.0.5. Subsequently, failed authentication attempt for user \'attacker_x\' originating from host IP 192.168.1.50. Subsequently, process \'cmd.exe\' was spawned by user \'attacker_x\' on device \'server-01\'.',
              factors: { time_score: 1.0, reachability_count: 3, severity_id: 4, pagerank: 0.142 },
              causal_chain: ['evt-001-firewall-block', 'evt-002-ids-alert', 'evt-003-failed-auth', 'evt-004-process-spawn'],
              raw_event: {
                class_name: 'Network Activity',
                disposition: 'BLOCK',
                time: 1726423200,
                src_endpoint: { ip: '192.168.1.50', port: 54321 },
                dst_endpoint: { ip: '10.0.0.5', port: 80 },
                user: { name: 'attacker_x' },
                raw_ref: { uuid: 'evt-001-firewall-block', sha256: '1111111111111111111111111111111111111111111111111111111111111111' }
              }
            },
            {
              rank: 2,
              event_uuid: 'evt-002-ids-alert',
              score: 0.725,
              explanation: 'Intrusion Detection System (IDS) flagged suspicious activity originating from 192.168.1.50 targeting 10.0.0.5.',
              intent: 'reconnaissance',
              factors: { time_score: 0.67, reachability_count: 2, severity_id: 5, pagerank: 0.125 },
              causal_chain: ['evt-002-ids-alert', 'evt-003-failed-auth', 'evt-004-process-spawn'],
              raw_event: {
                class_name: 'Security Finding',
                disposition: 'ALERT',
                time: 1726423230,
                src_endpoint: { ip: '192.168.1.50', port: 54321 },
                dst_endpoint: { ip: '10.0.0.5', port: 80 },
                user: { name: 'attacker_x' }
              }
            },
            {
              rank: 3,
              event_uuid: 'evt-003-failed-auth',
              score: 0.460,
              explanation: "Failed authentication attempt for user 'attacker_x' originating from host IP 192.168.1.50.",
              intent: 'credential_attack',
              factors: { time_score: 0.33, reachability_count: 1, severity_id: 3, pagerank: 0.095 },
              causal_chain: ['evt-003-failed-auth', 'evt-004-process-spawn'],
              raw_event: {
                class_name: 'Authentication',
                disposition: 'FAILURE',
                time: 1726423260,
                src_endpoint: { ip: '192.168.1.50' },
                user: { name: 'attacker_x' }
              }
            },
            {
              rank: 4,
              event_uuid: 'evt-004-process-spawn',
              score: 0.220,
              explanation: "Process 'cmd.exe' was spawned by user 'attacker_x' on device 'server-01'.",
              intent: 'exfiltration_attempt',
              factors: { time_score: 0.0, reachability_count: 0, severity_id: 2, pagerank: 0.078 },
              causal_chain: ['evt-004-process-spawn'],
              raw_event: {
                class_name: 'System Activity',
                disposition: 'SUCCESS',
                time: 1726423290,
                device: { hostname: 'server-01' },
                user: { name: 'attacker_x' },
                process: { name: 'cmd.exe' }
              }
            }
          ]
        };
        setRcaData(fallback);
        initCytoscape(fallback, theme);
      });
  }, []);

  // Re-render Cytoscape graph when theme toggles
  useEffect(() => {
    if (rcaData) {
      initCytoscape(rcaData, theme);
    }
  }, [theme]);

  const initCytoscape = (data, currentTheme) => {
    if (!containerRef.current) return;

    const isLight = currentTheme === 'light';

    // Theme-dependent Cytoscape Color Scheme
    const nodeBg = isLight ? '#FFFFFF' : '#161B24';
    const nodeBorder = isLight ? '#CBD0D8' : '#1F2530';
    const nodeTextColor = isLight ? '#111418' : '#E8EAED';

    const entityBg = isLight ? '#F7F8FA' : '#0A0E14';
    const entityBorder = isLight ? '#8A919C' : '#5C6472';
    const entityTextColor = isLight ? '#4B5563' : '#8B949E';

    const rootBg = isLight ? '#FEF2F2' : '#1E1215';
    const rootBorder = isLight ? '#C6362B' : '#E4483C';
    const rootTextColor = isLight ? '#C6362B' : '#E4483C';

    const edgeLineColor = isLight ? '#CBD0D8' : '#2A3140';
    const edgeTextColor = isLight ? '#4B5563' : '#8B949E';
    const edgeTextBg = isLight ? '#F7F8FA' : '#0A0E14';

    const elements = [];

    // Context Entity Nodes
    elements.push({ data: { id: 'ent_ip', label: 'IP: 192.168.1.50', type: 'entity' } });
    elements.push({ data: { id: 'ent_user', label: 'User: attacker_x', type: 'entity' } });

    // Event Nodes
    data.root_causes.forEach((candidate) => {
      const isRoot = candidate.rank === 1;
      elements.push({
        data: {
          id: candidate.event_uuid,
          label: isRoot ? `ROOT CAUSE (#1)\n${candidate.event_uuid}` : `${candidate.event_uuid}\n(${candidate.raw_event?.disposition || 'EVENT'})`,
          type: 'event',
          isRoot: isRoot,
          severity: candidate.factors?.severity_id || 1,
          candidate: candidate
        }
      });

      // Context edges to entities
      elements.push({ data: { source: candidate.event_uuid, target: 'ent_ip', label: 'context' } });
      elements.push({ data: { source: candidate.event_uuid, target: 'ent_user', label: 'context' } });
    });

    // Directed Temporal Causal Edges
    elements.push({ data: { source: 'evt-001-firewall-block', target: 'evt-002-ids-alert', label: 'causal +30s' } });
    elements.push({ data: { source: 'evt-002-ids-alert', target: 'evt-003-failed-auth', label: 'causal +30s' } });
    elements.push({ data: { source: 'evt-003-failed-auth', target: 'evt-004-process-spawn', label: 'causal +30s' } });

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: elements,
      style: [
        {
          selector: 'node[type = "event"]',
          style: {
            'background-color': nodeBg,
            'border-width': 1,
            'border-color': nodeBorder,
            'color': nodeTextColor,
            'label': 'data(label)',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '10px',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'width': '135px',
            'height': '55px',
            'shape': 'round-rectangle'
          }
        },
        {
          selector: 'node[type = "entity"]',
          style: {
            'background-color': entityBg,
            'border-color': entityBorder,
            'border-width': 1,
            'border-style': 'dashed',
            'shape': 'ellipse',
            'width': '100px',
            'height': '36px',
            'color': entityTextColor,
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '9px',
            'text-valign': 'center',
            'text-halign': 'center'
          }
        },
        {
          selector: 'node[isRoot]',
          style: {
            'background-color': rootBg,
            'border-color': rootBorder,
            'border-width': 2,
            'color': rootTextColor,
            'font-weight': 'bold',
            'width': '155px',
            'height': '65px'
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': edgeLineColor,
            'target-arrow-color': edgeTextColor,
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '8px',
            'color': edgeTextColor,
            'text-background-color': edgeTextBg,
            'text-background-opacity': 1,
            'text-background-padding': '3px'
          }
        }
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        spacingFactor: 1.25,
        padding: 30
      }
    });

    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      const data = node.data();
      if (data.candidate) {
        setSelectedNode(data);
      }
    });

    cyRef.current = cy;
    if (data.root_causes && data.root_causes.length > 0) {
      setSelectedNode({
        id: data.root_causes[0].event_uuid,
        isRoot: true,
        candidate: data.root_causes[0]
      });
    }
  };

  const topRoot = rcaData?.root_causes?.[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header Info */}
      <div className="card card-interactive">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.15rem', color: 'var(--text-primary)' }} className="font-headline">Cross-Source Root Cause Analysis (RCA) Graph</h2>
            <p style={{ margin: '4px 0 0 0', color: 'var(--text-secondary)' }} className="font-body">
              Temporal Entity Graph constructed in NetworkX. Top root cause candidate automatically identified via composite multi-factor scoring.
            </p>
          </div>
          {topRoot && (
            <div style={{ textAlign: 'right' }}>
              <span className="badge badge-red font-mono root-pulse-ring" style={{ padding: '6px 12px' }}>
                🔥 ROOT CAUSE (#1): {topRoot.event_uuid}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Narrative Summary Bar */}
      {topRoot && topRoot.chained_narrative && (
        <div className="card card-interactive" style={{ borderLeft: '3px solid var(--accent-critical)' }}>
          <div className="font-label" style={{ color: 'var(--accent-critical)', marginBottom: '4px' }}>Causal Incident Narrative</div>
          <div style={{ color: 'var(--text-primary)' }} className="font-body">
            "{topRoot.chained_narrative}"
          </div>
        </div>
      )}

      {/* Main Canvas & Inspector Split */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px' }}>
        {/* Cytoscape Canvas */}
        <div className="card card-interactive" style={{ height: '480px', padding: 0, overflow: 'hidden', position: 'relative' }}>
          <div style={{ position: 'absolute', top: 12, left: 12, zIndex: 10, display: 'flex', gap: '8px' }}>
            <span className="badge badge-red">Root Cause</span>
            <span className="badge badge-neutral">Event Node</span>
            <span className="badge badge-neutral" style={{ borderStyle: 'dashed' }}>Context Entity</span>
          </div>
          <div ref={containerRef} style={{ width: '100%', height: '100%', backgroundColor: 'var(--graph-canvas-bg)' }} />
        </div>

        {/* Node Inspector Panel */}
        <div className="card card-interactive" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <h3 className="font-label" style={{ margin: 0, color: 'var(--text-primary)', borderBottom: '1px solid var(--border-default)', paddingBottom: '10px' }}>
            Node Inspector
          </h3>

          {selectedNode && selectedNode.candidate ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <span className="font-label">Event UUID</span>
                <div style={{ fontSize: '0.88rem', color: 'var(--text-primary)', fontWeight: 500, marginTop: '2px' }} className="font-mono">
                  {selectedNode.candidate.event_uuid}
                </div>
              </div>

              <div>
                <span className="font-label">RCA Score &amp; Rank</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                  <span className={selectedNode.candidate.rank === 1 ? 'badge badge-red' : 'badge badge-neutral'}>
                    RANK #{selectedNode.candidate.rank}
                  </span>
                  <span className="font-headline" style={{ fontSize: '1.25rem', color: 'var(--text-primary)' }}>{selectedNode.candidate.score}</span>
                </div>
              </div>

              <div>
                <span className="font-label">Score Factor Breakdown</span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '6px' }} className="font-mono">
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Time Priority (Stime):</span>
                    <span style={{ color: 'var(--text-primary)' }}>{selectedNode.candidate.factors.time_score}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Downstream Reach (Sreach):</span>
                    <span style={{ color: 'var(--text-primary)' }}>{selectedNode.candidate.factors.reachability_count} nodes</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Severity Score (Ssev):</span>
                    <span style={{ color: 'var(--text-primary)' }}>{selectedNode.candidate.factors.severity_id} / 5</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>PageRank (Spagerank):</span>
                    <span style={{ color: 'var(--text-primary)' }}>{selectedNode.candidate.factors.pagerank}</span>
                  </div>
                </div>
              </div>

              <div>
                <span className="font-label">Single Event Explanation</span>
                <div style={{ backgroundColor: 'var(--bg-base)', padding: '8px', borderRadius: '4px', border: '1px solid var(--border-default)', marginTop: '4px' }} className="font-body">
                  "{selectedNode.candidate.explanation}"
                </div>
              </div>

              <div>
                <span className="font-label">Causal Chain</span>
                <div style={{ backgroundColor: 'var(--bg-base)', padding: '8px', borderRadius: '4px', border: '1px solid var(--border-default)', marginTop: '4px', fontSize: '11px', color: 'var(--text-secondary)' }} className="font-mono">
                  {selectedNode.candidate.causal_chain.join(' ➔ ')}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ color: 'var(--text-secondary)', marginTop: '20px', textAlign: 'center' }} className="font-body">
              Click any graph node to inspect factors.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
