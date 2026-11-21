import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { getCompleteness } from '../api';
import FlowTable from '../components/FlowTable';

function scoreBadge(score) {
  if (score >= 80) return 'badge badge-high';
  if (score >= 50) return 'badge badge-med';
  return 'badge badge-low';
}

export default function CompletenessPage() {
  const [params] = useSearchParams();
  const file = params.get('file') || localStorage.getItem('packettrust_file');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    if (!file) return;
    setLoading(true);
    getCompleteness(file)
      .then((r) => setData(r.data))
      .catch((e) => setError(e.response?.data?.error || 'Failed'))
      .finally(() => setLoading(false));
  }, [file]);

  if (!file) return <p className="muted">Upload a PCAP first from the Upload page.</p>;
  if (loading) return <p><span className="loader" /> Analysing…</p>;
  if (error) return <p className="error">{error}</p>;
  if (!data) return null;

  return (
    <div>
      <h1>📊 Capture Completeness</h1>
      <div className="card mt-2">
        <div className="flex-between">
          <div>
            <p><strong>File:</strong> {data.file}</p>
            <p><strong>Packets:</strong> {data.packet_count} &nbsp;|&nbsp; <strong>Duration:</strong> {data.duration_sec}s</p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div className="muted" style={{ fontSize: '.85rem' }}>Overall Score</div>
            <span className={scoreBadge(data.overall_score)} style={{ fontSize: '1.6rem' }}>
              {data.overall_score}
            </span>
          </div>
        </div>
      </div>

      <div className="card">
        <h2>Gap Summary</h2>
        <table>
          <thead><tr><th>Gap Type</th><th>Count</th></tr></thead>
          <tbody>
            <tr><td>TCP Sequence Gaps</td><td>{data.gaps.tcp_seq_gaps}</td></tr>
            <tr><td>IP ID Gaps</td><td>{data.gaps.ip_id_gaps}</td></tr>
            <tr><td>Timestamp Jumps</td><td>{data.gaps.timestamp_jumps}</td></tr>
            <tr><td>Missing Handshakes</td><td>{data.gaps.missing_handshakes}</td></tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <h2>Per-Flow Breakdown</h2>
        <FlowTable flows={data.flows} />
      </div>

      <button
        className="btn btn-primary mt-2"
        onClick={() => navigate(`/loss-sim?file=${file}`)}
      >
        Test Loss Simulation →
      </button>
    </div>
  );
}
