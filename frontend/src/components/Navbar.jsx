import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const links = [
  { to: '/', label: 'Upload' },
  { to: '/completeness', label: 'Completeness' },
  { to: '/loss-sim', label: 'Loss Sim' },
  { to: '/charts', label: 'Charts' },
  { to: '/report', label: 'Report' },
];

export default function Navbar() {
  const { pathname } = useLocation();
  return (
    <nav className="navbar">
      <Link to="/" className="logo">🔒 PacketTrust</Link>
      {links.map((l) => (
        <Link
          key={l.to}
          to={l.to}
          className={pathname === l.to ? 'active' : ''}
        >
          {l.label}
        </Link>
      ))}
    </nav>
  );
}
