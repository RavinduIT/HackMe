import { Routes, Route, Navigate } from 'react-router-dom';
import AppLayout from './components/layout/AppLayout';
import Dashboard from './pages/Dashboard';
import Intercept from './pages/proxy/Intercept';
import HttpHistory from './pages/proxy/HttpHistory';
import Scope from './pages/proxy/Scope';
import NewScan from './pages/scanner/NewScan';
import ActiveScan from './pages/scanner/ActiveScan';
import Findings from './pages/Findings';
import Repeater from './pages/Repeater';
import Decoder from './pages/Decoder';
import ScanHistory from './pages/ScanHistory';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import AiAnalysis from './pages/AiAnalysis';
import Intruder from './pages/Intruder';
import Comparer from './pages/Comparer';

export default function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/proxy/intercept" element={<Intercept />} />
        <Route path="/proxy/history" element={<HttpHistory />} />
        <Route path="/proxy/scope" element={<Scope />} />
        <Route path="/scanner/new" element={<NewScan />} />
        <Route path="/scanner/active/:scanId" element={<ActiveScan />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/ai" element={<AiAnalysis />} />
        <Route path="/repeater" element={<Repeater />} />
        <Route path="/decoder" element={<Decoder />} />
        <Route path="/history" element={<ScanHistory />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/intruder" element={<Intruder />} />
        <Route path="/comparer" element={<Comparer />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppLayout>
  );
}
