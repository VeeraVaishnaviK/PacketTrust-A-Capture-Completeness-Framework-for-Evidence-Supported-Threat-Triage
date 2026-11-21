import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import UploadPage from './pages/UploadPage';
import CompletenessPage from './pages/CompletenessPage';
import LossSimPage from './pages/LossSimPage';
import ChartsPage from './pages/ChartsPage';
import ReportPage from './pages/ReportPage';

function App() {
  return (
    <Router>
      <div className="app">
        <Navbar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<UploadPage />} />
            <Route path="/completeness" element={<CompletenessPage />} />
            <Route path="/loss-sim" element={<LossSimPage />} />
            <Route path="/charts" element={<ChartsPage />} />
            <Route path="/report" element={<ReportPage />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
