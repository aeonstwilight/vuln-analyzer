import { useState } from 'react'
import Dashboard from './pages/Dashboard'
import Compare from './pages/Compare'

const NAV = [
  { key: 'dashboard', label: 'Dashboard',      dot: '#378ADD' },
  { key: 'compare',   label: 'Scan comparison', dot: '#1D9E75' },
]

const PROFILES = ['FedRAMP Moderate/High', 'PCI DSS', 'NIST 800-53', 'Custom']
const VENDORS  = ['Auto Detect', 'Nessus', 'Qualys', 'Rapid7']

export default function App() {
  const [page, setPage]           = useState('dashboard')
  const [profileName, setProfile] = useState('FedRAMP Moderate/High')
  const [vendorOverride, setVendor] = useState('Auto Detect')

  return (
    <>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'DM Sans', 'Segoe UI', sans-serif; background: #F7F7F5; color: #1a1a2e; }
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');
        @keyframes spin { to { transform: rotate(360deg); } }
        select, input[type=text] {
          font-family: inherit;
          border: 1px solid #DEDEDE;
          border-radius: 7px;
          padding: 7px 10px;
          font-size: 12px;
          outline: none;
          background: #fff;
          width: 100%;
          color: #1a1a2e;
        }
        select:focus, input[type=text]:focus { border-color: #378ADD; }
      `}</style>

      <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>

        {/* Sidebar */}
        <aside style={{
          width: 220, flexShrink: 0,
          background: '#1a1a2e', color: '#fff',
          display: 'flex', flexDirection: 'column',
          padding: '0 0 16px',
        }}>
          {/* Logo */}
          <div style={{ padding: '22px 20px 18px', borderBottom: '1px solid #ffffff14' }}>
            <div style={{ fontSize: 15, fontWeight: 700, letterSpacing: '-0.02em' }}>VulnAnalyzer</div>
            <div style={{ fontSize: 11, color: '#6B7FA3', marginTop: 3 }}>Multi-vendor · v1.0</div>
          </div>

          {/* Nav */}
          <nav style={{ padding: '12px 10px', flex: 1 }}>
            {NAV.map(n => (
              <button key={n.key} onClick={() => setPage(n.key)} style={{
                display: 'flex', alignItems: 'center', gap: 10,
                width: '100%', padding: '9px 12px', borderRadius: 8,
                background: page === n.key ? '#ffffff14' : 'none',
                border: 'none', color: page === n.key ? '#fff' : '#8A9BB8',
                fontSize: 13, fontWeight: page === n.key ? 600 : 400,
                cursor: 'pointer', textAlign: 'left',
                marginBottom: 2, transition: 'all 0.12s',
              }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: n.dot, flexShrink: 0 }} />
                {n.label}
              </button>
            ))}
          </nav>

          {/* Settings */}
          <div style={{ padding: '14px 16px', borderTop: '1px solid #ffffff14' }}>
            <div style={{ fontSize: 10, color: '#6B7FA3', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 10 }}>
              Settings
            </div>
            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: '#8A9BB8', marginBottom: 5 }}>Compliance profile</div>
              <select value={profileName} onChange={e => setProfile(e.target.value)}
                style={{ background: '#ffffff0f', color: '#fff', border: '1px solid #ffffff20' }}>
                {PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div>
              <div style={{ fontSize: 11, color: '#8A9BB8', marginBottom: 5 }}>Vendor override</div>
              <select value={vendorOverride} onChange={e => setVendor(e.target.value)}
                style={{ background: '#ffffff0f', color: '#fff', border: '1px solid #ffffff20' }}>
                {VENDORS.map(v => <option key={v} value={v}>{v}</option>)}
              </select>
            </div>
          </div>
        </aside>

        {/* Main content */}
        <main style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
          {/* Topbar */}
          <header style={{
            padding: '14px 28px', borderBottom: '1px solid #EBEBEB',
            background: '#fff', display: 'flex', alignItems: 'center',
            justifyContent: 'space-between', flexShrink: 0,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600 }}>
              {NAV.find(n => n.key === page)?.label}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{
                fontSize: 11, padding: '3px 10px', borderRadius: 20,
                background: '#EBF4FF', color: '#0C447C',
                border: '1px solid #B5D4F4', fontWeight: 600,
              }}>
                {profileName}
              </span>
              <span style={{
                fontSize: 11, padding: '3px 10px', borderRadius: 20,
                background: '#F5F5F5', color: '#555',
                border: '1px solid #DEDEDE',
              }}>
                {vendorOverride}
              </span>
            </div>
          </header>

          {/* Page content */}
          <div style={{ padding: 28, flex: 1 }}>
            {page === 'dashboard' && <Dashboard profileName={profileName} vendorOverride={vendorOverride} />}
            {page === 'compare'   && <Compare   profileName={profileName} vendorOverride={vendorOverride} />}
          </div>
        </main>
      </div>
    </>
  )
}
