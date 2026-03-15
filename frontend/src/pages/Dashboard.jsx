import { useState, useMemo } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { MetricCard, RiskPill, VulnTable, FileDropZone, Button, ErrorBanner } from '../components'
import { analyzeFile, downloadPdfReport } from '../api/client'

const SEV_COLORS = {
  Critical: '#E24B4A',
  High:     '#EF9F27',
  Medium:   '#378ADD',
  Low:      '#639922',
}

const AGING_COLORS = ['#639922','#639922','#EF9F27','#EF9F27','#E24B4A','#E24B4A']

export default function Dashboard({ profileName, vendorOverride }) {
  const [file, setFile]         = useState(null)
  const [result, setResult]     = useState(null)
  const [loading, setLoading]   = useState(false)
  const [pdfLoading, setPdfLoading] = useState(false)
  const [error, setError]       = useState(null)
  const [sevFilter, setSevFilter] = useState([])
  const [hostSearch, setHostSearch] = useState('')
  const [expiredOnly, setExpiredOnly] = useState(false)

  async function handleAnalyze() {
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      const data = await analyzeFile({ file, vendorOverride, profileName })
      setResult(data)
      setSevFilter([])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function handlePdf() {
    if (!file) return
    setPdfLoading(true)
    setError(null)
    try {
      await downloadPdfReport({ file, vendorOverride, profileName })
    } catch (e) {
      setError(e.message)
    } finally {
      setPdfLoading(false)
    }
  }

  const filteredVulns = useMemo(() => {
    if (!result) return []
    let rows = result.vulnerabilities
    if (sevFilter.length) rows = rows.filter(r => sevFilter.includes(r.severity))
    if (hostSearch) rows = rows.filter(r => r.host?.includes(hostSearch))
    if (expiredOnly) rows = rows.filter(r => r.expired)
    return rows
  }, [result, sevFilter, hostSearch, expiredOnly])

  const agingData = useMemo(() => {
    if (!result) return []
    const buckets = ['0–30d','31–60d','61–90d','91–180d','181–365d','365d+']
    const edges = [0, 30, 60, 90, 180, 365, Infinity]
    const counts = new Array(6).fill(0)
    for (const v of result.vulnerabilities) {
      const age = v.age_days ?? 0
      for (let i = 0; i < 6; i++) {
        if (age > edges[i] && age <= edges[i + 1]) { counts[i]++; break }
      }
    }
    return buckets.map((b, i) => ({ name: b, count: counts[i] }))
  }, [result])

  const topHosts = useMemo(() => {
    if (!result) return []
    const freq = {}
    for (const v of result.vulnerabilities) freq[v.host] = (freq[v.host] || 0) + 1
    return Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, 8)
      .map(([host, count]) => ({ host, count }))
  }, [result])

  const sevData = useMemo(() => {
    if (!result) return []
    return ['Critical','High','Medium','Low']
      .map(s => ({ name: s, value: result.metrics[s.toLowerCase()] }))
      .filter(d => d.value > 0)
  }, [result])

  return (
    <div>
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      {/* Upload + analyze */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 12, alignItems: 'end', marginBottom: 24 }}>
        <FileDropZone label="Drop Nessus / Qualys / Rapid7 CSV here, or click to browse" onFile={setFile} file={file} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <Button onClick={handleAnalyze} disabled={!file} loading={loading}>
            {loading ? 'Analyzing…' : 'Analyze'}
          </Button>
          {result && (
            <Button onClick={handlePdf} disabled={!file} loading={pdfLoading} variant="secondary">
              {pdfLoading ? 'Generating…' : 'Export PDF'}
            </Button>
          )}
        </div>
      </div>

      {result && (
        <>
          {/* Vendor + profile banner */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 12, color: '#888' }}>
              Detected: <strong style={{ color: '#1a1a2e' }}>{result.vendor}</strong>
            </span>
            <span style={{ fontSize: 12, color: '#888' }}>
              Profile: <strong style={{ color: '#1a1a2e' }}>{result.profile_name}</strong>
            </span>
            <RiskPill rating={result.risk.rating} score={result.risk.score} />
            {result.missing_columns?.length > 0 && (
              <span style={{ fontSize: 11, color: '#7A4100', background: '#FEF3E2', padding: '3px 10px', borderRadius: 20 }}>
                Missing columns: {result.missing_columns.join(', ')}
              </span>
            )}
          </div>

          {/* Metric cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0,1fr))', gap: 10, marginBottom: 28 }}>
            <MetricCard label="Critical" value={result.metrics.critical} sub="SLA: 30 days" accentColor="#E24B4A" />
            <MetricCard label="High"     value={result.metrics.high}     sub="SLA: 30 days" accentColor="#EF9F27" />
            <MetricCard label="Medium"   value={result.metrics.medium}   sub="SLA: 90 days" accentColor="#378ADD" />
            <MetricCard label="Low"      value={result.metrics.low}      sub="SLA: 180 days" accentColor="#639922" />
            <MetricCard label="Expired"  value={result.metrics.expired}  sub="SLA breached" accentColor="#E24B4A" />
          </div>

          {/* Charts row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 28 }}>
            <div style={{ background: '#FAFAFA', border: '1px solid #EBEBEB', borderRadius: 10, padding: 20 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#666', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Severity distribution</div>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={sevData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={55} outerRadius={80}>
                    {sevData.map(d => <Cell key={d.name} fill={SEV_COLORS[d.name]} />)}
                  </Pie>
                  <Tooltip formatter={(v, n) => [v, n]} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', justifyContent: 'center', gap: 14, flexWrap: 'wrap', marginTop: 8 }}>
                {sevData.map(d => (
                  <span key={d.name} style={{ fontSize: 11, color: SEV_COLORS[d.name], fontWeight: 600 }}>
                    ● {d.name} ({d.value})
                  </span>
                ))}
              </div>
            </div>

            <div style={{ background: '#FAFAFA', border: '1px solid #EBEBEB', borderRadius: 10, padding: 20 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#666', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Top hosts</div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={topHosts} layout="vertical" margin={{ left: 10, right: 20 }}>
                  <XAxis type="number" tick={{ fontSize: 10 }} />
                  <YAxis type="category" dataKey="host" tick={{ fontSize: 10 }} width={110} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#378ADD" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Aging chart */}
          <div style={{ background: '#FAFAFA', border: '1px solid #EBEBEB', borderRadius: 10, padding: 20, marginBottom: 28 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#666', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Vulnerability aging</div>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={agingData}>
                <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip />
                {agingData.map((d, i) => null)}
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {agingData.map((d, i) => <Cell key={i} fill={AGING_COLORS[i]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Filters */}
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 12, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', gap: 6 }}>
              {['Critical','High','Medium','Low'].map(s => (
                <button key={s} onClick={() => setSevFilter(f => f.includes(s) ? f.filter(x => x !== s) : [...f, s])}
                  style={{
                    fontSize: 12, padding: '4px 12px', borderRadius: 20, cursor: 'pointer',
                    border: `1px solid ${sevFilter.includes(s) ? SEV_COLORS[s] : '#DEDEDE'}`,
                    background: sevFilter.includes(s) ? SEV_COLORS[s] + '18' : '#fff',
                    color: sevFilter.includes(s) ? SEV_COLORS[s] : '#666',
                    fontWeight: sevFilter.includes(s) ? 600 : 400,
                  }}>
                  {s}
                </button>
              ))}
            </div>
            <input value={hostSearch} onChange={e => setHostSearch(e.target.value)}
              placeholder="Filter by host…"
              style={{ fontSize: 12, padding: '5px 12px', border: '1px solid #DEDEDE', borderRadius: 8, outline: 'none', width: 180 }} />
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#666', cursor: 'pointer' }}>
              <input type="checkbox" checked={expiredOnly} onChange={e => setExpiredOnly(e.target.checked)} />
              Expired only
            </label>
            <span style={{ fontSize: 12, color: '#AAA', marginLeft: 'auto' }}>
              {filteredVulns.length} of {result.vulnerabilities.length} vulnerabilities
            </span>
          </div>

          <VulnTable rows={filteredVulns} />
        </>
      )}
    </div>
  )
}
