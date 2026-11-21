import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { getCompleteness, getTriage, getReportUrl } from '../api';
import FlowTable from '../components/FlowTable';
import FindingsTable from '../components/FindingsTable';

export default function ReportPage() {
  const [params] = useSearchParams();
  const file = params.get('file') || localStorage.getItem('packettrust_file');
  const [comp, setComp] = useState(null);
  const [tri, setTri] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!file) return;
    setLoading(true);
    Promise.all([getCompleteness(file), getTriage(file)])
      .then(([c, t]) => {
        setComp(c.data);
        setTri(t.data);
      })
      .finally(() => setLoading(false));
  }, [file]);

  if (!file) return <p className="muted">Upload a PCAP first from the Upload page.</p>;
  if (loading) return <p><span className="loader" /> Generating forensic report…</p>;
  if (!comp || !tri) return null;

  return (
    <div>
      <div className="flex-between no-print">
        <div>
          <h1>🔒 Forensic Evidence &amp; Threat Triage Report</h1>
          <p className="muted" style={{ fontSize: '0.9rem' }}>
            Evidence-supported network threat verification and capture completeness assessment.
          </p>
        </div>
        <div>
          <button className="btn btn-primary" onClick={() => window.print()}>
            🖨️ Print Report
          </button>
          &nbsp;
          <a
            className="btn btn-primary"
            href={getReportUrl(file)}
            target="_blank"
            rel="noreferrer"
          >
            HTML Report ↗
          </a>
        </div>
      </div>

      {/* 1. Executive Summary & File Info */}
      <div className="card mt-2">
        <div className="flex-between" style={{ alignItems: 'flex-start' }}>
          <div>
            <h2>Capture Summary</h2>
            <p><strong>PCAP File:</strong> <code>{comp.file}</code></p>
            <p><strong>Total Packets:</strong> {comp.packet_count} &nbsp;|&nbsp; <strong>Capture Duration:</strong> {comp.duration_sec}s</p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div className="muted" style={{ fontSize: '.85rem' }}>Capture Completeness</div>
            <span
              className={`badge ${
                comp.overall_score >= 80 ? 'badge-high' :
                comp.overall_score >= 50 ? 'badge-med' : 'badge-low'
              }`}
              style={{ fontSize: '1.5rem', padding: '0.4rem 1.2rem' }}
            >
              {comp.overall_score} / 100
            </span>
          </div>
        </div>
      </div>

      {/* 2. Threat Findings (Prominently First) */}
      <div className="card">
        <h2>1. Evidence-Supported Threat Findings</h2>
        <p className="muted" style={{ fontSize: '0.9rem', marginBottom: '1rem' }}>
          Threats detected strictly from captured packet artifacts. Each finding references supporting packet indices.
        </p>
        <FindingsTable findings={tri.findings} />
      </div>

      {/* 3. Gap Analysis */}
      <div className="card">
        <h2>2. Capture Completeness &amp; Gap Analysis</h2>
        <p className="muted" style={{ fontSize: '0.9rem', marginBottom: '1rem' }}>
          Identifies packet loss, capture buffer drops, and protocol state anomalies that impact forensic reliability.
        </p>
        <table>
          <thead>
            <tr>
              <th>Gap Type</th>
              <th>Count</th>
              <th>Forensic Implication</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>TCP Sequence Gaps</strong></td>
              <td>{comp.gaps.tcp_seq_gaps}</td>
              <td className="muted">Missing payload segments dropped in transit or capture buffer</td>
            </tr>
            <tr>
              <td><strong>IP ID Gaps</strong></td>
              <td>{comp.gaps.ip_id_gaps}</td>
              <td className="muted">Non-sequential IP IDs indicating packets dropped upstream</td>
            </tr>
            <tr>
              <td><strong>Timestamp Jumps</strong></td>
              <td>{comp.gaps.timestamp_jumps}</td>
              <td className="muted">Gaps &gt; 3s between frames indicating capture buffer stall</td>
            </tr>
            <tr>
              <td><strong>Missing Handshakes</strong></td>
              <td>{comp.gaps.missing_handshakes}</td>
              <td className="muted">Data observed without initial 3-way SYN handshake</td>
            </tr>
            <tr>
              <td><strong>Missing Teardowns</strong></td>
              <td>{comp.gaps.missing_teardowns}</td>
              <td className="muted">Flows truncated before FIN/RST teardown was recorded</td>
            </tr>
            <tr>
              <td><strong>Retransmissions</strong></td>
              <td>{comp.gaps.retransmissions}</td>
              <td className="muted">Duplicate sequence numbers indicating packet retransmissions</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* 4. Flow Breakdown */}
      <div className="card">
        <h2>3. Flow Completeness Breakdown</h2>
        <p className="muted" style={{ fontSize: '0.9rem', marginBottom: '1rem' }}>
          Per-flow completeness scores (flows with gaps/anomalies listed first).
        </p>
        <FlowTable flows={comp.flows} limitForPrint={true} />
      </div>

      <div className="card" style={{ color: '#8b949e', fontSize: '.85rem', textAlign: 'center' }}>
        Generated by <strong>PacketTrust Framework</strong> — Measuring the Impact of Capture Completeness on Forensic Reliability.
        <br />Lab use only. Never infer beyond captured packets.
      </div>
    </div>
  );
}
