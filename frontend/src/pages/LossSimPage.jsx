import React, { useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { simulateLoss, getTriage } from '../api';
import FindingsTable from '../components/FindingsTable';

export default function LossSimPage() {
  const [params] = useSearchParams();
  const file = params.get('file') || localStorage.getItem('packettrust_file');
  const [lossPct, setLossPct] = useState(20);
  const [mode, setMode] = useState('random');
  const [simResult, setSimResult] = useState(null);
  const [triageData, setTriageData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  async function runSimAndTriage() {
    if (!file) return;
    setLoading(true);
    setError('');
    try {
      const sim = await simulateLoss(file, lossPct, mode);
      setSimResult(sim.data);
      const tri = await getTriage(sim.data.output_file);
      setTriageData(tri.data);
    } catch (e) {
      setError(e.response?.data?.error || 'Failed');
    } finally {
      setLoading(false);
    }
  }

  if (!file) return <p className="muted">Upload a PCAP first from the Upload page.</p>;

  return (
    <div>
      <h1>🎚️ Loss Simulation &amp; Triage</h1>

      <div className="card mt-2">
        <h2>Simulate Packet Loss</h2>
        <p className="muted">File: {file}</p>

        <div className="mt-2">
          <label>
            <strong>Loss: {lossPct}%</strong>
            <input
              type="range" min="0" max="80" step="5"
              value={lossPct}
              onChange={(e) => setLossPct(Number(e.target.value))}
              style={{ display: 'block', marginTop: '.5rem' }}
            />
          </label>
        </div>

        <div className="mt-1">
          <label style={{ marginRight: '1.5rem' }}>
            <input type="radio" name="mode" value="random"
              checked={mode === 'random'} onChange={() => setMode('random')} />
            {' '}Random
          </label>
          <label>
            <input type="radio" name="mode" value="burst"
              checked={mode === 'burst'} onChange={() => setMode('burst')} />
            {' '}Burst
          </label>
        </div>

        <button
          className="btn btn-primary mt-2"
          onClick={runSimAndTriage}
          disabled={loading}
        >
          {loading ? <><span className="loader" /> Running…</> : 'Simulate & Triage'}
        </button>
      </div>

      {error && <p className="error mt-2">{error}</p>}

      {simResult && (
        <div className="card">
          <h2>Simulation Result</h2>
          <p>Original: {simResult.original_packets} packets → Remaining: {simResult.remaining_packets} ({simResult.dropped} dropped)</p>
        </div>
      )}

      {triageData && (
        <div className="card">
          <h2>Triage Findings (at {lossPct}% loss)</h2>
          <FindingsTable findings={triageData.findings} />
        </div>
      )}

      <button
        className="btn btn-primary mt-2"
        onClick={() => navigate(`/charts?file=${file}`)}
      >
        Run Full Experiment →
      </button>
    </div>
  );
}
