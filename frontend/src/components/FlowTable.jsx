import React from 'react';

function scoreBadge(score) {
  if (score >= 80) return 'badge badge-high';
  if (score >= 50) return 'badge badge-med';
  return 'badge badge-low';
}

export default function FlowTable({ flows }) {
  if (!flows || flows.length === 0) return <p className="muted">No flows.</p>;
  return (
    <table>
      <thead>
        <tr>
          <th>Flow</th>
          <th>Packets</th>
          <th>Score</th>
          <th>Issues</th>
        </tr>
      </thead>
      <tbody>
        {flows.map((f, i) => (
          <tr key={i}>
            <td><code>{f.flow_id}</code></td>
            <td>{f.packets}</td>
            <td><span className={scoreBadge(f.score)}>{f.score}</span></td>
            <td>{f.issues.length > 0 ? f.issues.join(', ') : '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
