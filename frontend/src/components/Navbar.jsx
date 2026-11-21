import React from 'react';
import { Link, useLocation, useSearchParams } from 'react-router-dom';

const links = [
  { to: '/', label: 'Upload' },
  { to: '/completeness', label: 'Completeness' },
  { to: '/loss-sim', label: 'Loss Sim' },
  { to: '/charts', label: 'Charts' },
  { to: '/report', label: 'Report' },
];

export default function Navbar() {
  const { pathname } = useLocation();
  const [params] = useSearchParams();
  const fileFromUrl = params.get('file');
  const currentFile = fileFromUrl || localStorage.getItem('packettrust_file') || '';

  return (
    <nav className="navbar">
      <Link to="/" className="logo">🔒 PacketTrust</Link>
      {links.map((l) => {
        // Append ?file= to all pages except Upload
        const href = l.to === '/' || !currentFile
          ? l.to
          : `${l.to}?file=${encodeURIComponent(currentFile)}`;
        return (
          <Link
            key={l.to}
            to={href}
            className={pathname === l.to ? 'active' : ''}
          >
            {l.label}
          </Link>
        );
      })}
      {currentFile && (
        <span className="muted" style={{ marginLeft: 'auto', fontSize: '.85rem' }}>
          📄 {currentFile}
        </span>
      )}
    </nav>
  );
}
