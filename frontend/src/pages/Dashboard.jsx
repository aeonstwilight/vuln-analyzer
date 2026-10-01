import { useState, useMemo } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { MetricCard, RiskPill, VulnTable, FileDropZone, Button, ErrorBanner, FixFirst, TIER_COLORS, PAIN_COLORS } from '../components'
import { analyzeFile, downloadPdfReport, downloadJsonReport, downloadOscalReport, downloadVerReport } from '../api/client'

const SEV_COLORS = {
  Critical: '#E24B4A',
  High:     '#EF9F27',
  Medium:   '#378ADD',
  Low:      '#639922',
}

const AGING_COLORS = ['#639922','#639922','#EF9F27','#EF9F27','#E24B4A','#E24B4A']

// Extra table columns shown when a FedRAMP 2026 profile produced the result.
const VER_COLUMNS = [
  { key: 'ver_pain', label: 'Impact',      width: 75 },
  { key: 'ver_lev',  label: 'Exploitable', width: 100 },
  { key: 'ver_irv',  label: 'Internet',    width: 85 },
]

export default function Dashboard({ profileName, vendorOverride }) {
  const [file, setFile]           = useState(null)
  const [result, setResult]       = useState(null)
  const [loading, setLoading]     = useState(false)
  const [pdfLoading, setPdfLoading]   = useState(false)
  const [jsonLoading, setJsonLoading] = useState(false)
  const [oscalLoading, setOscalLoading] = useState(false)
  const [error, setError]         = useState(null)
  const [sevFilter, setSevFilter] = useState([])
  const [tierFilter, setTierFilter] = useState([])
  const [hostSearch, setHostSearch] = useState('')
  const [expiredOnly, setExpiredOnly] = useState(false)
  const [assetContext, setAssetContext] = useState(null)
  const [assumeReachable, setAssumeReachable] = useState(false)
  const [verLoading, setVerLoading] = useState(false)

  const isVerProfile = profileName.startsWith('FedRAMP 2026')
  const ver = isVerProfile ? { assetContext, assumeReachable } : null

  async function handleAnalyze() {
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      const data = await analyzeFile({ file, vendorOverride, profileName, ver })
      setResult(data)
      setSevFilter([])
      setTierFilter([])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleExport(fn, setLoadingFn) {
    if (!file) return
    setLoadingFn(true)
    setError(null)
    try {
      await fn({ file, vendorOverride, profileName, ver })
    } catch (e) {
      setError(e.message)
    } finally {
      setLoadingFn(false)
    }
  }

  const filteredVulns = useMemo(() => {
    if (!result) return []
    let rows = result.vulnerabilities
    if (sevFilter.length) rows = rows.filter(r => sevFilter.includes(r.severity))
    if (tierFilter.length) rows = rows.filter(r => tierFilter.includes(r.priority_tier))
    if (hostSearch) rows = rows.filter(r => r.host?.includes(hostSearch))
    if (expiredOnly) rows = rows.filter(r => r.expired)
    return rows
  }, [result, sevFilter, tierFilter, hostSearch, expiredOnly])

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

  // Severity-based profiles have one window per severity; the 2026 profiles do not.
  const slaLabel = sev => {
    const days = result?.profile?.[sev]
    return days != null ? `SLA: ${days} days` : ''
  }

  return (
    <div>
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      {/* Upload + analyze */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 12, alignItems: 'end', marginBottom: 24 }}>
        <FileDropZone
          label="Drop Nessus / Qualys / Rapid7 / OpenVAS / Wiz / Defender CSV here, or click to browse"
          onFile={setFile}
          file={file}
        />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <Button onClick={handleAnalyze} disabled={!file} loading={loading}>
            {loading ? 'Analyzing…' : 'Analyze'}
          </Button>
          {result && (
            <>
              <Button onClick={() => handleExport(downloadPdfReport, setPdfLoading)} disabled={!file} loading={pdfLoading} variant="secondary">
                {pdfLoading ? 'Generating…' : 'Export PDF'}
              </Button>
              <Button onClick={() => handleExport(downloadJsonReport, setJsonLoading)} disabled={!file} loading={jsonLoading} variant="secondary">
                {jsonLoading ? 'Generating…' : 'Export JSON'}
              </Button>
              <Button onClick={() => handleExport(downloadOscalReport, setOscalLoading)} disabled={!file} loading={oscalLoading} variant="secondary">
                {oscalLoading ? 'Generating…' : 'Export OSCAL'}
              </Button>
              {result.ver && isVerProfile && (
                <Button onClick={() => handleExport(downloadVerReport, setVerLoading)} disabled={!file} loading={verLoading} variant="secondary">
                  {verLoading ? 'Generating…' : 'Export VER detail'}
                </Button>
              )}
            </>
          )}
        </div>
      </div>

      {/* FedRAMP 2026 inputs: what a scanner export cannot know */}
      {isVerProfile && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, alignItems: 'center', marginBottom: 24 }}>
          <FileDropZone
            label="Optional: asset context CSV (host, internet_reachable, impact)"
            onFile={setAssetContext}
            file={assetContext}
          />
          <div style={{ fontSize: 12, color: '#666', lineHeight: 1.6 }}>
            <div style={{ marginBottom: 8 }}>
              The 2026 rules set deadlines from three things a scan cannot see on its own: whether a finding is
              likely exploitable, whether it is internet-reachable, and its impact on agency customers (N1 to N5).
              The asset context file supplies the last two per host.
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
              <input type="checkbox" checked={assumeReachable} onChange={e => setAssumeReachable(e.target.checked)} />
              Treat hosts missing from the file as internet-reachable
            </label>
          </div>
        </div>
      )}

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
            {result.enrichment_errors?.length > 0 && (
              <span style={{ fontSize: 11, color: '#555', background: '#F5F5F5', padding: '3px 10px', borderRadius: 20 }}
                title={result.enrichment_errors.join('\n')}>
                ⚠ CVE intel partially unavailable
              </span>
            )}
          </div>

          {/* Metric cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(0,1fr))', gap: 10, marginBottom: 28 }}>
            <MetricCard label="Critical" value={result.metrics.critical} sub={slaLabel('Critical')} accentColor="#E24B4A" />
            <MetricCard label="High"     value={result.metrics.high}     sub={slaLabel('High')}     accentColor="#EF9F27" />
            <MetricCard label="Medium"   value={result.metrics.medium}   sub={slaLabel('Medium')}   accentColor="#378ADD" />
            <MetricCard label="Low"      value={result.metrics.low}      sub={slaLabel('Low')}      accentColor="#639922" />
            <MetricCard label={result.ver ? 'Overdue' : 'Expired'} value={result.metrics.expired}
              sub={result.ver ? 'Past 2026 timeframe' : 'SLA breached'} accentColor="#E24B4A" />
            <MetricCard label="CISA KEV" value={result.metrics.kev ?? 0} sub="Actively exploited" accentColor="#4A0000" />
          </div>

          {/* FedRAMP 2026 evaluation summary */}
          {result.ver && (
            <div style={{ border: '1px solid #EBEBEB', borderRadius: 10, padding: '16px 18px', marginBottom: 24, background: '#FAFAFA' }}>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap', marginBottom: 12 }}>
                <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  FedRAMP 2026 evaluation · Class {result.ver.class}
                </span>
                <span style={{ fontSize: 11, color: '#999' }}>
                  Proposed values for an analyst to confirm. Hover a value in the table for its basis.
                </span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0,1fr))', gap: 10 }}>
                <MetricCard label="Likely exploitable" value={result.ver.likely_exploitable} sub="KEV, EPSS or exploit" accentColor="#E24B4A" />
                <MetricCard label="Internet-reachable" value={result.ver.internet_reachable} sub="From asset context" accentColor="#EF9F27" />
                <MetricCard label="Both" value={result.ver.lev_and_irv} sub="Shortest timeframes" accentColor="#8B1A1A" />
                <MetricCard label="Report as accepted" value={result.ver.accept_required} sub="Open over 192 days" accentColor="#7A4100" />
                <MetricCard label="Incident rules" value={result.ver.incident_should}
                  sub={`should be reported · ${result.ver.incident_may} may`} accentColor="#4A0000" />
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginTop: 12 }}>
                <span style={{ fontSize: 11, color: '#999', textTransform: 'uppercase', letterSpacing: '0.06em', marginRight: 4 }}>
                  Agency impact
                </span>
                {[5, 4, 3, 2, 1].map(n => (
                  <span key={n} style={{
                    fontSize: 12, padding: '4px 12px', borderRadius: 20, background: '#fff',
                    border: `1px solid ${PAIN_COLORS[n]}55`, color: '#666',
                  }}>
                    N{n} <strong style={{ color: PAIN_COLORS[n] }}>{result.ver.pain[`N${n}`]}</strong>
                  </span>
                ))}
              </div>
              {result.ver.hosts_with_assumed_reachability > 0 && (
                <div style={{ fontSize: 11.5, color: '#7A4100', background: '#FEF3E2', padding: '6px 12px', borderRadius: 8, marginTop: 12 }}>
                  Internet reachability was assumed for {result.ver.hosts_with_assumed_reachability} host
                  {result.ver.hosts_with_assumed_reachability === 1 ? '' : 's'} not covered by an asset context file
                  (marked * in the table). Deadlines for those hosts depend on that assumption.
                </div>
              )}
            </div>
          )}

          {/* Priority tier strip */}
          {result.metrics.tiers && (
            <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap', alignItems: 'center' }}>
              <span style={{ fontSize: 11, color: '#999', textTransform: 'uppercase', letterSpacing: '0.06em', marginRight: 4 }}>
                Priority
              </span>
              {['Immediate','Urgent','Scheduled','Routine'].map(t => {
                const active = tierFilter.includes(t)
                const color = TIER_COLORS[t]
                return (
                  <button key={t}
                    onClick={() => setTierFilter(f => f.includes(t) ? f.filter(x => x !== t) : [...f, t])}
                    title={`Filter the table to ${t} findings`}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: 7,
                      fontSize: 12, padding: '5px 13px', borderRadius: 20, cursor: 'pointer',
                      border: `1px solid ${active ? color : '#DEDEDE'}`,
                      background: active ? color + '18' : '#fff',
                      color: active ? color : '#666', fontWeight: active ? 600 : 400,
                    }}>
                    <span style={{ width: 7, height: 7, borderRadius: '50%', background: color }} />
                    {t}
                    <strong style={{ color }}>{result.metrics.tiers[t] ?? 0}</strong>
                  </button>
                )
              })}
            </div>
          )}

          {/* Ranked remediation guidance */}
          <FixFirst plan={result.remediation_plan} findings={result.vulnerabilities} limit={10} />

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

          <VulnTable rows={filteredVulns} extraColumns={result.ver ? VER_COLUMNS : []} />
        </>
      )}
    </div>
  )
}
