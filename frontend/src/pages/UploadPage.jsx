import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { uploadPcap } from '../api';

export default function UploadPage() {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const inputRef = useRef();
  const navigate = useNavigate();

  async function handleFile(file) {
    if (!file) return;
    setUploading(true);
    setError('');
    setResult(null);
    try {
      const res = await uploadPcap(file);
      setResult(res.data);
      // Persist current file so other pages can find it
      localStorage.setItem('packettrust_file', res.data.filename);
    } catch (err) {
      setError(err.response?.data?.error || 'Upload failed');
    } finally {
      setUploading(false);
    }
  }

  function onDrop(e) {
    e.preventDefault();
    setDragging(false);
    handleFile(e.dataTransfer.files[0]);
  }

  return (
    <div>
      <h1>📁 Upload PCAP</h1>
      <p className="muted mt-1">
        Upload a packet capture file (.pcap / .pcapng) to begin analysis.
      </p>

      <div
        className={`upload-zone mt-2 ${dragging ? 'dragging' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current.click()}
      >
        {uploading ? (
          <><span className="loader" /> Uploading…</>
        ) : (
          <>Drop a PCAP file here or <strong>click to browse</strong></>
        )}
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          hidden
          onChange={(e) => handleFile(e.target.files[0])}
        />
      </div>

      {error && <p className="error mt-2">{error}</p>}

      {result && (
        <div className="card mt-2">
          <h2>✅ Upload Successful</h2>
          <p><strong>File:</strong> {result.filename}</p>
          <p><strong>Size:</strong> {(result.size_bytes / 1024).toFixed(1)} KB</p>
          <p><strong>Packets:</strong> {result.packet_count}</p>
          <div className="mt-2">
            <button
              className="btn btn-primary"
              onClick={() => navigate(`/completeness?file=${result.filename}`)}
            >
              Analyse Completeness →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
