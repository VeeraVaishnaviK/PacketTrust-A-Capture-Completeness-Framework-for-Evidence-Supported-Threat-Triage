import React, { useState } from 'react';

function scoreBadge(score) {
  if (score >= 80) return 'badge badge-high';
  if (score >= 50) return 'badge badge-med';
  return 'badge badge-low';
}

export default function FlowTable({ flows, limitForPrint = false }) {
  const [filter, setFilter] = useState('issues'); // 'issues', 'top25', 'all'

  if (!flows || flows.length === 0) return <p className="muted">No TCP flows captured.</p>;

  const flowsWithIssues = flows.filter((f) => f.issues && f.issues.length > 0);
  
  let displayedFlows = flows;
  if (filter === 'issues') {
    displayedFlows = flowsWithIssues.length > 0 ? flowsWithIssues : flows.slice(0, 25);
  } else if (filter === 'top25') {
    displayedFlows = flows.slice(0, 25);
  }

  // If in print view, cap at 30 so reports don't print 16 pages of single-packet probes
  const printFlows = flowsWithIssues.length > 0 ? flowsWithIssues.slice(0, 30) : flows.slice(0, 30);
  const itemsToRender = limitForPrint ? printFlows : displayedFlows;

  return (
    <div>
      <div className="flex-between no-print" style={{ marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <span className="muted" style={{ fontSize: '0.9rem' }}>
          Total flows: <strong>{flows.length}</strong> | Flows with gaps/issues: <strong>{flowsWithIssues.length}</strong>
        </span>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            className={`btn ${filter === 'issues' ? 'btn-primary' : ''}`}
            style={{ fontSize: '0.8rem', padding: '0.3rem 0.8rem' }}
            onClick={() => setFilter('issues')}
          >
            Issues Only ({flowsWithIssues.length})
          </button>
          <button
            type="button"
            className={`btn ${filter === 'top25' ? 'btn-primary' : ''}`}
            style={{ fontSize: '0.8rem', padding: '0.3rem 0.8rem' }}
            onClick={() => setFilter('top25')}
          >
            Top 25
          </button>
          <button
            type="button"
            className={`btn ${filter === 'all' ? 'btn-primary' : ''}`}
            style={{ fontSize: '0.8rem', padding: '0.3rem 0.8rem' }}
            onClick={() => setFilter('all')}
          >
            Show All ({flows.length})
          </button>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Flow</th>
            <th style={{ width: '90px' }}>Packets</th>
            <th style={{ width: '90px' }}>Score</th>
            <th>Forensic Gaps &amp; Issues</th>
          </tr>
        </thead>
        <tbody>
          {itemsToRender.map((f, i) => (
            <tr key={i}>
              <td style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                {f.flow_id}
              </td>
              <td>{f.packets}</td>
              <td>
                <span className={scoreBadge(f.score)}>{f.score}</span>
              </td>
              <td>
                {f.issues && f.issues.length > 0 ? (
                  <span style={{ color: '#d29922' }}>{f.issues.join(', ')}</span>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {itemsToRender.length < flows.length && (
        <p className="muted mt-1" style={{ fontSize: '0.85rem' }}>
          Showing {itemsToRender.length} of {flows.length} flows. Use the buttons above to view more.
        </p>
      )}
    </div>
  );
}
