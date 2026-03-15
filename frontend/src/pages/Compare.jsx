import { useState } from 'react'
import { FileDropZone, Button, ErrorBanner, MetricCard, VulnTable, StatusBadge } from '../components'
import { compareFiles } from '../api/client'

export default function Compare({ profileName, vendorOverride }) {
  const [oldFile, setOldFile] = useState(null)
  const [newFile, setNewFile] = useState(null)
  const [result, setResult]   = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)
  const [activeTab, setActiveTab] = useState('new')

  async function handleCompare() {
    if (!oldFile || !newFile) return
    setLoading(true)
    setError(null)
    try {
      const data = await compareFiles({ oldFile, newFile, vendorOverride, profileName })
      setResult(data)
      setActiveTab('new')
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const tabs = result ? [
    { key: 'new',       label: `New (${result.summary.new})` },
    { key: 'resolved',  label: `Resolved (${result.summary.resolved})` },
    { key: 'unchanged', label: `Unchanged (${result.summary.unchanged})` },
  ] : []

  const activeRows = result
    ? (result[activeTab] || []).map(r => ({ ...r, status: activeTab === 'new' ? 'New' : activeTab === 'resolved' ? 'Resolved' : 'Unchanged' }))
    : []

  return (
    <div>
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
        <FileDropZone label="Old scan CSV" onFile={setOldFile} file={oldFile} />
        <FileDropZone label="New scan CSV" onFile={setNewFile} file={newFile} />
      </div>

      <div style={{ marginBottom: 28 }}>
        <Button onClick={handleCompare} disabled={!oldFile || !newFile} loading={loading}>
          {loading ? 'Comparing…' : 'Compare Scans'}
        </Button>
      </div>

      {result && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0,1fr))', gap: 10, marginBottom: 28 }}>
            <MetricCard label="New"       value={result.summary.new}       sub="introduced since last scan" accentColor="#E24B4A" />
            <MetricCard label="Resolved"  value={result.summary.resolved}  sub="fixed since last scan"      accentColor="#639922" />
            <MetricCard label="Unchanged" value={result.summary.unchanged} sub="persisting"                 accentColor="#888" />
          </div>

          {/* Tabs */}
          <div style={{ display: 'flex', borderBottom: '1px solid #EBEBEB', marginBottom: 16 }}>
            {tabs.map(t => (
              <button key={t.key} onClick={() => setActiveTab(t.key)} style={{
                padding: '9px 18px', fontSize: 13, cursor: 'pointer',
                background: 'none', border: 'none',
                borderBottom: activeTab === t.key ? '2px solid #1a1a2e' : '2px solid transparent',
                color: activeTab === t.key ? '#1a1a2e' : '#888',
                fontWeight: activeTab === t.key ? 600 : 400,
                marginBottom: -1,
              }}>
                {t.label}
              </button>
            ))}
          </div>

          <VulnTable
            rows={activeRows}
            extraColumns={[{ key: 'status', label: 'Status', width: 90 }]}
          />

          <div style={{ marginTop: 16 }}>
            <Button variant="secondary" onClick={() => {
              const rows = [...result.new.map(r => ({...r, status:'New'})),
                           ...result.resolved.map(r => ({...r, status:'Resolved'})),
                           ...result.unchanged.map(r => ({...r, status:'Unchanged'}))]
              const keys = Object.keys(rows[0] || {})
              const csv = [keys.join(','), ...rows.map(r => keys.map(k => JSON.stringify(r[k] ?? '')).join(','))].join('\n')
              const blob = new Blob([csv], { type: 'text/csv' })
              const a = document.createElement('a')
              a.href = URL.createObjectURL(blob)
              a.download = 'scan_comparison.csv'
              a.click()
            }}>
              Export Comparison CSV
            </Button>
          </div>
        </>
      )}
    </div>
  )
}
