import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  BarChart, Bar, ResponsiveContainer,
} from 'recharts';
import { runExperiment } from '../api';
import HeatMap from '../components/HeatMap';

export default function ChartsPage() {
  const [params] = useSearchParams();
  const file = params.get('file');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!file) return;
    setLoading(true);
    runExperiment(file, [0, 10, 20, 30, 50], 5)
      .then((r) => setData(r.data))
      .catch((e) => setError(e.response?.data?.error || 'Experiment failed'))
      .finally(() => setLoading(false));
  }, [file]);

  if (!file) return <p className="muted">Upload a PCAP first from the Upload page.</p>;
  if (loading) return <p><span className="loader" /> Running experiment (this may take a moment)…</p>;
  if (error) return <p className="error">{error}</p>;
  if (!data) return null;

  const chartData = data.results.map((r) => ({
    loss: `${r.loss_pct}%`,
    'Detection Rate': +(r.detection_rate * 100).toFixed(1),
    'False Negative': +(r.false_negative_rate * 100).toFixed(1),
    'Avg Confidence': +(r.avg_confidence * 100).toFixed(1),
  }));

  return (
    <div>
      <h1>📈 Experiment Results</h1>
      <p className="muted mt-1">
        File: {file} &nbsp;|&nbsp; Ground truth: {data.ground_truth.join(', ') || 'None'}
      </p>

      {/* Line Chart: Detection Rate & Confidence vs Loss */}
      <div className="card mt-2">
        <h2>Detection Rate vs Packet Loss</h2>
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
            <XAxis dataKey="loss" stroke="#8b949e" />
            <YAxis domain={[0, 100]} stroke="#8b949e" />
            <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d' }} />
            <Legend />
            <Line type="monotone" dataKey="Detection Rate" stroke="#3fb950" strokeWidth={2} dot={{ r: 4 }} />
            <Line type="monotone" dataKey="Avg Confidence" stroke="#58a6ff" strokeWidth={2} dot={{ r: 4 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Bar Chart: False Negatives */}
      <div className="card">
        <h2>False Negative Rate by Loss Level</h2>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
            <XAxis dataKey="loss" stroke="#8b949e" />
            <YAxis domain={[0, 100]} stroke="#8b949e" />
            <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d' }} />
            <Bar dataKey="False Negative" fill="#f85149" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Heatmap */}
      <div className="card">
        <h2>Attack Detection Heatmap</h2>
        <HeatMap data={data} />
      </div>
    </div>
  );
}
