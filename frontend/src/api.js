import axios from 'axios';

const api = axios.create({ baseURL: '/api', timeout: 300000 }); // 5 min timeout for heavy ops

export const uploadPcap = (file) => {
  const fd = new FormData();
  fd.append('file', file);
  return api.post('/upload', fd);
};

export const getCompleteness = (file) =>
  api.get('/completeness', { params: { file } });

export const simulateLoss = (file, lossPct, mode = 'random') =>
  api.post('/simulate-loss', { file, loss_pct: lossPct, mode });

export const getTriage = (file) =>
  api.get('/triage', { params: { file } });

export const runExperiment = (file, lossLevels, trials) =>
  api.post('/experiment', { file, loss_levels: lossLevels, trials });

export const getReportUrl = (file) => `/api/report?file=${encodeURIComponent(file)}`;

export default api;
