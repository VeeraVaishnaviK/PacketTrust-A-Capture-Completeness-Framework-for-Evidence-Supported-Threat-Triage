import React from 'react';

export default function FindingsTable({ findings }) {
  if (!findings || findings.length === 0)
    return <p className="muted">No threats detected.</p>;

  return (
    <table>
      <thead>
        <tr>
          <th>Attack</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Detail</th>
          <th>Confidence</th>
          <th>Packets</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f, i) => (
          <tr key={i}>
            <td>{f.attack}</td>
            <td className={`severity-${f.severity}`}>{f.severity}</td>
            <td className={`status-${f.status}`}>{f.status}</td>
            <td>{f.detail}</td>
            <td>{(f.confidence * 100).toFixed(0)}%</td>
            <td>{f.supporting_packets.length}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
