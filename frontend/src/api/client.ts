import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001'

export const api = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
})

// Attach token from localStorage
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('spaider_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// ── API functions ─────────────────────────────────────────────────────────

export const scanApi = {
  list: (params?: any) => api.get('/scans', { params }).then(r => r.data),
  create: (data: any) => api.post('/scans', data).then(r => r.data),
  get: (id: string) => api.get(`/scans/${id}`).then(r => r.data),
  cancel: (id: string) => api.delete(`/scans/${id}/cancel`).then(r => r.data),
}

export const assetApi = {
  list: (params?: any) => api.get('/assets', { params }).then(r => r.data),
  create: (data: any) => api.post('/assets', data).then(r => r.data),
  get: (id: string) => api.get(`/assets/${id}`).then(r => r.data),
  graph: () => api.get('/assets/graph').then(r => r.data),
}

export const findingApi = {
  list: (params?: any) => api.get('/findings', { params }).then(r => r.data),
  get: (id: string) => api.get(`/findings/${id}`).then(r => r.data),
  stats: () => api.get('/findings/stats').then(r => r.data),
}

export const alertApi = {
  list: (params?: any) => api.get('/alerts', { params }).then(r => r.data),
  updateStatus: (id: string, status: string) =>
    api.patch(`/alerts/${id}/status`, null, { params: { new_status: status } }).then(r => r.data),
  timeline: (hours?: number) => api.get('/alerts/timeline', { params: { hours } }).then(r => r.data),
}

export const malwareApi = {
  list: () => api.get('/malware').then(r => r.data),
  get: (id: string) => api.get(`/malware/${id}`).then(r => r.data),
  upload: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post('/malware/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)
  },
}

export const networkApi = {
  discover: (data: any) => api.post('/network/discover', data).then(r => r.data),
  topology: (targets: string[]) => api.post('/network/topology', targets).then(r => r.data),
}

export const aiApi = {
  analyze: (data: any) => api.post('/ai/analyze', data).then(r => r.data),
  query: (query: string) => api.post('/ai/query', null, { params: { query } }).then(r => r.data),
  dashboardSummary: () => api.get('/ai/dashboard-summary').then(r => r.data),
}

export const pluginApi = {
  list: () => api.get('/plugins').then(r => r.data),
  get: (name: string) => api.get(`/plugins/${name}`).then(r => r.data),
}

export const purpleApi = {
  validate: (data: any) => api.post('/purple/validate', data).then(r => r.data),
  gaps: () => api.get('/purple/gaps').then(r => r.data),
}

export const siemApi = {
  status: () => api.get('/siem/status').then(r => r.data),
  ingest: (event: any) => api.post('/siem/ingest', event).then(r => r.data),
  ingestBatch: (events: any[]) => api.post('/siem/ingest/batch', events).then(r => r.data),
  timeline: (hours?: number) => api.get('/siem/timeline', { params: { hours } }).then(r => r.data),
  stats: () => api.get('/siem/stats').then(r => r.data),
}

export const reportApi = {
  list: () => api.get('/reports').then(r => r.data),
  generate: (data: any) => api.post('/reports/generate', data).then(r => r.data),
  get: (id: string) => api.get(`/reports/${id}`).then(r => r.data),
  delete: (id: string) => api.delete(`/reports/${id}`).then(r => r.data),
}

export const webApi = {
  scan: (data: any) => api.post('/web/scan', data).then(r => r.data),
  categories: () => api.get('/web/categories').then(r => r.data),
  scanStatus: (taskId: string) => api.get(`/web/scan/${taskId}/status`).then(r => r.data),
  burpSync: (findings: any[]) => api.post('/web/burp/sync', findings).then(r => r.data),
  caidoSync: (findings: any[]) => api.post('/web/caido/sync', findings).then(r => r.data),
}

export const authApi = {
  login: (username: string, password: string) => {
    const form = new URLSearchParams()
    form.append('username', username)
    form.append('password', password)
    return api.post('/auth/login', form, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }).then(r => r.data)
  },
  register: (data: any) => api.post('/auth/register', data).then(r => r.data),
  me: () => api.get('/auth/me').then(r => r.data),
}
