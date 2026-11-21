import React from 'react';

/**
 * Simple text-based heatmap: rows = attacks, columns = loss levels.
 * Cell colour intensity reflects detection rate.
 */
export default function HeatMap({ data }) {
  if (!data) return null;

  const { ground_truth, results } = data;
  if (!ground_truth || ground_truth.length === 0)
    return <p className="muted">No ground-truth attacks to map.</p>;

  // We only have aggregate detection rate per loss level.
  // Show it as a single-row heat strip.
  const maxRate = 1;

  function cellColor(rate) {
    if (rate >= 0.9) return 'rgba(63,185,80,0.7)';
    if (rate >= 0.6) return 'rgba(210,153,34,0.6)';
    return 'rgba(248,81,73,0.6)';
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Metric</th>
          {results.map((r) => (
            <th key={r.loss_pct}>{r.loss_pct}% loss</th>
          ))}
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Detection Rate</td>
          {results.map((r) => (
            <td
              key={r.loss_pct}
              style={{
                background: cellColor(r.detection_rate),
                textAlign: 'center',
                fontWeight: 600,
              }}
            >
              {(r.detection_rate * 100).toFixed(0)}%
            </td>
          ))}
        </tr>
        <tr>
          <td>False Negative</td>
          {results.map((r) => (
            <td
              key={r.loss_pct}
              style={{
                background: cellColor(1 - r.false_negative_rate),
                textAlign: 'center',
                fontWeight: 600,
              }}
            >
              {(r.false_negative_rate * 100).toFixed(0)}%
            </td>
          ))}
        </tr>
        <tr>
          <td>Reliability</td>
          {results.map((r) => (
            <td
              key={r.loss_pct}
              style={{ textAlign: 'center' }}
              className={`badge-${r.reliability.toLowerCase()}`}
            >
              {r.reliability}
            </td>
          ))}
        </tr>
      </tbody>
    </table>
  );
}
