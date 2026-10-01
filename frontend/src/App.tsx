import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import Assets from './pages/Assets'
import Findings from './pages/Findings'
import Alerts from './pages/Alerts'
import NetworkMap from './pages/NetworkMap'
import MalwareAnalysis from './pages/MalwareAnalysis'
import AIAnalyst from './pages/AIAnalyst'
import PurpleTeam from './pages/PurpleTeam'
import Plugins from './pages/Plugins'
import Reports from './pages/Reports'
import MitreAttack from './pages/MitreAttack'
import WebSecurity from './pages/WebSecurity'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="scans" element={<Scans />} />
          <Route path="assets" element={<Assets />} />
          <Route path="findings" element={<Findings />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="network-map" element={<NetworkMap />} />
          <Route path="web-security" element={<WebSecurity />} />
          <Route path="malware" element={<MalwareAnalysis />} />
          <Route path="ai-analyst" element={<AIAnalyst />} />
          <Route path="purple" element={<PurpleTeam />} />
          <Route path="mitre" element={<MitreAttack />} />
          <Route path="plugins" element={<Plugins />} />
          <Route path="reports" element={<Reports />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
