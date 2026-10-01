import { Fragment, useState } from 'react'

// ─── Severity badge ────────────────────────────────────────────────────────
const SEV_STYLES = {
  Critical: { bg: '#FCEBEB', color: '#8B1A1A', border: '#F09595' },
  High:     { bg: '#FEF3E2', color: '#7A4100', border: '#FAC775' },
  Medium:   { bg: '#EBF4FF', color: '#0C3B6E', border: '#85B7EB' },
  Low:      { bg: '#EDFBE8', color: '#1A4D0F', border: '#97C459' },
}

export function SeverityBadge({ severity }) {
  const s = SEV_STYLES[severity] || { bg: '#F5F5F5', color: '#555', border: '#CCC' }
  return (
    <span style={{
      background: s.bg, color: s.color,
      border: `1px solid ${s.border}`,
      borderRadius: 20, fontSize: 11, fontWeight: 600,
      padding: '2px 10px', letterSpacing: '0.02em',
      display: 'inline-block',
    }}>
      {severity}
    </span>
  )
}

// ─── KEV badge ────────────────────────────────────────────────────────────
export function KevBadge({ dueDate }) {
  return (
    <span title={dueDate ? `CISA KEV — due ${dueDate}` : 'CISA Known Exploited Vulnerability'} style={{
      background: '#4A0000', color: '#FF9A9A',
      border: '1px solid #8B1A1A',
      borderRadius: 4, fontSize: 10, fontWeight: 700,
      padding: '1px 6px', letterSpacing: '0.06em',
      display: 'inline-block', marginLeft: 6, verticalAlign: 'middle',
      cursor: 'default', flexShrink: 0,
    }}>
      KEV
    </span>
  )
}

// ─── EPSS pill ────────────────────────────────────────────────────────────
export function EpssPill({ score, percentile }) {
  if (!score && score !== 0) return <span style={{ color: '#CCC' }}>—</span>
  const pct = (score * 100).toFixed(1)
  const color = score >= 0.5 ? '#E24B4A' : score >= 0.1 ? '#EF9F27' : '#639922'
  return (
    <span title={`EPSS: ${pct}% probability of exploitation\nPercentile: ${(percentile * 100).toFixed(0)}th`}
      style={{ fontSize: 12, fontWeight: 600, color, cursor: 'default' }}>
      {pct}%
    </span>
  )
}

// ─── FedRAMP 2026 evaluation ──────────────────────────────────────────────
export const PAIN_COLORS = {
  5: '#8B1A1A', 4: '#E24B4A', 3: '#EF9F27', 2: '#378ADD', 1: '#639922',
}

/** Potential Agency Impact N-rating. */
export function PainBadge({ pain, basis }) {
  if (pain == null) return <span style={{ color: '#CCC' }}>—</span>
  const color = PAIN_COLORS[pain] || '#888'
  return (
    <span title={basis} style={{
      background: color + '18', color, border: `1px solid ${color}55`,
      borderRadius: 4, fontSize: 11, fontWeight: 700,
      padding: '1px 7px', display: 'inline-block', cursor: 'default',
    }}>
      N{pain}
    </span>
  )
}

/** Yes / no for likely-exploitable and internet-reachable, with the evidence on hover. */
export function YesNo({ value, basis }) {
  if (value == null) return <span style={{ color: '#CCC' }}>—</span>
  const assumed = basis?.startsWith('Assumed')
  return (
    <span title={basis} style={{
      fontSize: 12, fontWeight: value ? 600 : 400, cursor: 'default',
      color: value ? '#8B1A1A' : '#888',
      borderBottom: assumed ? '1px dotted #AAA' : 'none',
    }}>
      {value ? 'Yes' : 'No'}{assumed ? ' *' : ''}
    </span>
  )
}

// ─── Priority tier ────────────────────────────────────────────────────────
export const TIER_COLORS = {
  Immediate: '#E24B4A',
  Urgent:    '#EF9F27',
  Scheduled: '#378ADD',
  Routine:   '#639922',
}

export const TIER_ORDER = ['Immediate', 'Urgent', 'Scheduled', 'Routine']

export function TierChip({ tier }) {
  const color = TIER_COLORS[tier] || '#888'
  return (
    <span style={{
      background: color + '18', color, border: `1px solid ${color}55`,
      borderRadius: 20, fontSize: 10, fontWeight: 700,
      padding: '2px 9px', textTransform: 'uppercase', letterSpacing: '0.05em',
      display: 'inline-block', whiteSpace: 'nowrap',
    }}>
      {tier}
    </span>
  )
}

/** Numeric priority with an inline magnitude bar. */
export function PriorityScore({ score, tier, width = 44 }) {
  if (score == null) return <span style={{ color: '#CCC' }}>—</span>
  const color = TIER_COLORS[tier] || '#888'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
      <span style={{ fontSize: 12, fontWeight: 700, color, minWidth: 26, textAlign: 'right' }}>
        {Math.round(score)}
      </span>
      <span style={{ width, height: 4, background: '#EDEDED', borderRadius: 2, overflow: 'hidden', flexShrink: 0 }}>
        <span style={{ display: 'block', width: `${Math.max(0, Math.min(100, score))}%`, height: '100%', background: color }} />
      </span>
    </div>
  )
}

// ─── Fix These First ──────────────────────────────────────────────────────

function FixFirstRow({ rank, title, score, tier, kev, cve, reason, meta, solution }) {
  const color = TIER_COLORS[tier] || '#888'
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '30px 76px 1fr auto',
      gap: 12, alignItems: 'start',
      padding: '12px 14px', borderBottom: '1px solid #F2F2F2',
      borderLeft: `3px solid ${color}`, background: rank % 2 ? '#FAFAFA' : '#fff',
    }}>
      <div style={{ fontSize: 15, fontWeight: 700, color: '#CFCFCF', lineHeight: 1.3 }}>
        {rank}
      </div>

      <div style={{ paddingTop: 1 }}>
        <div style={{ fontSize: 19, fontWeight: 700, color, lineHeight: 1 }}>
          {Math.round(score)}
        </div>
        <div style={{ width: 56, height: 4, background: '#EDEDED', borderRadius: 2, marginTop: 5, overflow: 'hidden' }}>
          <div style={{ width: `${Math.max(0, Math.min(100, score))}%`, height: '100%', background: color }} />
        </div>
      </div>

      <div style={{ minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 3 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: '#1a1a2e' }} title={title}>
            {title}
          </span>
          {kev && <KevBadge />}
          {cve && <span style={{ fontSize: 11, color: '#378ADD', fontWeight: 600 }}>{cve}</span>}
          <TierChip tier={tier} />
        </div>
        <div style={{ fontSize: 11.5, color: '#777', lineHeight: 1.5 }}>{reason}</div>
        {solution && (
          <div style={{ fontSize: 11.5, color: '#1A4D0F', marginTop: 5, lineHeight: 1.45 }}>
            <span style={{ color: '#9A9A9A' }}>Fix: </span>{solution}
          </div>
        )}
      </div>

      <div style={{ fontSize: 11, color: '#999', textAlign: 'right', whiteSpace: 'nowrap', lineHeight: 1.6 }}>
        {meta}
      </div>
    </div>
  )
}

/**
 * Ranked "what do we do Monday morning" panel.
 * Two views over the same scoring: one fix action per row, or one finding per row.
 */
export function FixFirst({ plan = [], findings = [], limit = 10 }) {
  const [mode, setMode] = useState('action')

  const rows = mode === 'action'
    ? plan.slice(0, limit).map((a, i) => ({
        key: `${a.plugin_id}-${i}`,
        rank: i + 1,
        title: a.plugin_name,
        score: a.priority_score,
        tier: a.priority_tier,
        kev: a.kev_listed,
        cve: a.cve_id,
        reason: a.reason,
        solution: a.solution && a.solution !== 'nan' ? a.solution : '',
        meta: (
          <>
            {a.hosts_affected} host{a.hosts_affected === 1 ? '' : 's'}<br />
            {a.findings} finding{a.findings === 1 ? '' : 's'}
            {a.expired > 0 && <><br /><span style={{ color: '#8B1A1A' }}>{a.expired} past SLA</span></>}
          </>
        ),
      }))
    : [...findings]
        .sort((a, b) => (b.priority_score ?? 0) - (a.priority_score ?? 0))
        .slice(0, limit)
        .map((v, i) => ({
          key: `${v.plugin_id}-${v.host}-${i}`,
          rank: i + 1,
          title: v.plugin_name,
          score: v.priority_score,
          tier: v.priority_tier,
          kev: v.kev_listed,
          cve: v.cve_id,
          reason: v.priority_reason,
          solution: v.solution && v.solution !== 'nan' ? v.solution : '',
          meta: <>{v.host}<br />{v.severity} · CVSS {Number(v.cvss || 0).toFixed(1)}</>,
        }))

  const TOGGLE = (value, label) => (
    <button onClick={() => setMode(value)} style={{
      fontSize: 11, padding: '4px 12px', borderRadius: 20, cursor: 'pointer',
      border: `1px solid ${mode === value ? '#1a1a2e' : '#DEDEDE'}`,
      background: mode === value ? '#1a1a2e' : '#fff',
      color: mode === value ? '#fff' : '#666',
      fontWeight: mode === value ? 600 : 400,
    }}>{label}</button>
  )

  return (
    <div style={{ border: '1px solid #EBEBEB', borderRadius: 10, marginBottom: 28, overflow: 'hidden' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap',
        padding: '14px 18px', background: '#FAFAFA', borderBottom: '1px solid #EBEBEB',
      }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#1a1a2e', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Fix these first
          </div>
          <div style={{ fontSize: 11, color: '#999', marginTop: 3 }}>
            Ranked by exploitation likelihood, impact, fleet exposure and SLA pressure — not severity alone.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, marginLeft: 'auto' }}>
          {TOGGLE('action', 'By fix action')}
          {TOGGLE('finding', 'By finding')}
        </div>
      </div>

      {rows.length === 0 ? (
        <div style={{ padding: 28, textAlign: 'center', color: '#AAA', fontSize: 13 }}>
          Nothing to prioritize.
        </div>
      ) : rows.map(r => <FixFirstRow key={r.key} {...r} />)}
    </div>
  )
}

// ─── Status badge (New / Resolved / Unchanged) ────────────────────────────
const STATUS_STYLES = {
  New:       { bg: '#FCEBEB', color: '#8B1A1A', border: '#F09595' },
  Resolved:  { bg: '#EDFBE8', color: '#1A4D0F', border: '#97C459' },
  Unchanged: { bg: '#F5F5F5', color: '#555',    border: '#CCC' },
}

export function StatusBadge({ status }) {
  const s = STATUS_STYLES[status] || STATUS_STYLES.Unchanged
  return (
    <span style={{
      background: s.bg, color: s.color,
      border: `1px solid ${s.border}`,
      borderRadius: 20, fontSize: 11, fontWeight: 600,
      padding: '2px 10px', display: 'inline-block',
    }}>
      {status}
    </span>
  )
}

// ─── Metric card ──────────────────────────────────────────────────────────
export function MetricCard({ label, value, sub, accentColor }) {
  return (
    <div style={{
      background: '#FAFAFA',
      border: '1px solid #EBEBEB',
      borderRadius: 10,
      borderTop: `3px solid ${accentColor}`,
      padding: '14px 18px',
      minWidth: 0,
    }}>
      <div style={{ fontSize: 11, color: '#999', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
        {label}
      </div>
      <div style={{ fontSize: 28, fontWeight: 700, color: '#1a1a2e', lineHeight: 1 }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: 11, color: '#AAA', marginTop: 5 }}>{sub}</div>}
    </div>
  )
}

// ─── Risk pill ────────────────────────────────────────────────────────────
const RISK_COLORS = {
  Low:      '#639922',
  Moderate: '#378ADD',
  High:     '#EF9F27',
  Severe:   '#E24B4A',
}

export function RiskPill({ rating, score }) {
  const color = RISK_COLORS[rating] || '#888'
  return (
    <div style={{
      display: 'inline-flex', alignItems: 'center', gap: 10,
      background: color + '18', border: `1px solid ${color}55`,
      borderRadius: 24, padding: '6px 16px',
    }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />
      <span style={{ fontSize: 13, fontWeight: 600, color }}>
        {rating} risk
      </span>
      <span style={{ fontSize: 12, color: '#888' }}>score {score}</span>
    </div>
  )
}

// ─── Sortable vulnerability table ─────────────────────────────────────────
const TH_STYLE = {
  padding: '9px 12px', textAlign: 'left',
  fontSize: 11, fontWeight: 600, color: '#888',
  textTransform: 'uppercase', letterSpacing: '0.05em',
  borderBottom: '1px solid #EBEBEB',
  cursor: 'pointer', userSelect: 'none',
  whiteSpace: 'nowrap', background: '#FAFAFA',
}

const TD_STYLE = {
  padding: '8px 12px', fontSize: 12, color: '#1a1a2e',
  borderBottom: '1px solid #F2F2F2',
  maxWidth: 220, overflow: 'hidden',
  textOverflow: 'ellipsis', whiteSpace: 'nowrap',
}

export function VulnTable({ rows, extraColumns = [] }) {
  const hasPriority = rows.some(r => r.priority_score != null)
  const [sortCol, setSortCol] = useState(hasPriority ? 'priority_score' : 'epss_score')
  const [sortDir, setSortDir] = useState('desc')
  const [expanded, setExpanded] = useState(null)

  const hasEnrichment = rows.some(r => r.cve_id || r.epss_score > 0 || r.kev_listed)

  const columns = [
    ...(hasPriority ? [{ key: 'priority_score', label: 'Priority', width: 110 }] : []),
    { key: 'plugin_name', label: 'Vulnerability', width: 260 },
    { key: 'severity',    label: 'Severity',       width: 90 },
    { key: 'host',        label: 'Host',            width: 130 },
    { key: 'cvss',        label: 'CVSS',            width: 60 },
    ...(hasEnrichment ? [
      { key: 'epss_score', label: 'EPSS',           width: 70 },
      { key: 'cwe',        label: 'CWE',            width: 90 },
    ] : []),
    { key: 'age_days',    label: 'Age (d)',          width: 70 },
    { key: 'days_left',   label: 'Days Left',        width: 80 },
    { key: 'expired',     label: 'SLA',              width: 70 },
    ...extraColumns,
  ]

  const sorted = [...rows].sort((a, b) => {
    const av = a[sortCol] ?? (typeof a[sortCol] === 'number' ? -Infinity : '')
    const bv = b[sortCol] ?? (typeof b[sortCol] === 'number' ? -Infinity : '')
    if (av < bv) return sortDir === 'asc' ? -1 : 1
    if (av > bv) return sortDir === 'asc' ? 1 : -1
    return 0
  })

  function handleSort(key) {
    if (sortCol === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortCol(key); setSortDir('desc') }
  }

  function renderCell(col, row) {
    switch (col.key) {
      case 'plugin_name':
        return (
          <div style={{ display: 'flex', alignItems: 'center', overflow: 'hidden' }}>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
              title={row.plugin_name}>
              {row.plugin_name || '—'}
            </span>
            {row.kev_listed && <KevBadge dueDate={row.kev_due_date} />}
          </div>
        )
      case 'priority_score':
        return <PriorityScore score={row.priority_score} tier={row.priority_tier} />
      case 'severity':
        return <SeverityBadge severity={row.severity} />
      case 'expired':
        return <SlaStatus expired={row.expired} daysLeft={row.days_left} />
      case 'cvss':
        return Number(row.cvss || 0).toFixed(1)
      case 'epss_score':
        return <EpssPill score={row.epss_score} percentile={row.epss_percentile} />
      case 'cwe':
        return row.cwe
          ? <span style={{ fontSize: 11, background: '#F0F0F0', borderRadius: 4, padding: '2px 6px', color: '#444' }}>{row.cwe}</span>
          : <span style={{ color: '#CCC' }}>—</span>
      case 'status':
        return <StatusBadge status={row.status} />
      case 'ver_pain':
        return <PainBadge pain={row.ver_pain} basis={row.ver_pain_basis} />
      case 'ver_lev':
        return <YesNo value={row.ver_lev} basis={row.ver_lev_basis} />
      case 'ver_irv':
        return <YesNo value={row.ver_irv} basis={row.ver_irv_basis} />
      default:
        return row[col.key] ?? '—'
    }
  }

  return (
    <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid #EBEBEB' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
        <thead>
          <tr>
            {columns.map(col => (
              <th key={col.key} style={{ ...TH_STYLE, width: col.width }}
                onClick={() => handleSort(col.key)}>
                {col.label}
                {sortCol === col.key ? (sortDir === 'asc' ? ' ↑' : ' ↓') : ''}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => (
            <Fragment key={`${row.plugin_id}-${row.host}-${i}`}>
              <tr
                onClick={() => setExpanded(expanded === i ? null : i)}
                style={{
                  background: i % 2 === 0 ? '#fff' : '#FAFAFA',
                  cursor: (row.nvd_description || row.priority_reason || row.ver_pain != null) ? 'pointer' : 'default',
                }}>
                {columns.map(col => (
                  <td key={col.key} style={TD_STYLE}>
                    {renderCell(col, row)}
                  </td>
                ))}
              </tr>
              {expanded === i && (row.nvd_description || row.cve_id || row.priority_reason || row.ver_pain != null) && (
                <tr style={{ background: '#F7F7FF' }}>
                  <td colSpan={columns.length} style={{ padding: '10px 16px', fontSize: 12, color: '#444', borderBottom: '1px solid #EBEBEB' }}>
                    {row.priority_reason && (
                      <div style={{ marginBottom: 8 }}>
                        <span style={{ color: '#999', marginRight: 8 }}>Why this rank:</span>
                        {row.priority_reason}
                        <PriorityFactors row={row} />
                      </div>
                    )}
                    {row.ver_pain != null && (
                      <div style={{ marginBottom: 8, lineHeight: 1.7 }}>
                        <span style={{ color: '#999', marginRight: 8 }}>FedRAMP 2026 evaluation (proposed):</span>
                        <PainBadge pain={row.ver_pain} />
                        {row.ver_due_days != null
                          ? <span style={{ marginLeft: 8 }}>{row.ver_due_days}-day timeframe</span>
                          : <span style={{ marginLeft: 8 }}>no fixed timeframe</span>}
                        {row.ver_accept_required && (
                          <span style={{ marginLeft: 12, color: '#7A4100' }}>Over 192 days: report as an accepted vulnerability</span>
                        )}
                        {row.ver_incident && (
                          <span style={{ marginLeft: 12, color: '#B00000' }}>
                            {row.ver_incident === 'should' ? 'Should' : 'May'} be treated as a reportable incident
                          </span>
                        )}
                        <br />
                        <span style={{ color: '#999' }}>Impact: </span>{row.ver_pain_basis}<br />
                        <span style={{ color: '#999' }}>Likely exploitable: </span>{row.ver_lev ? 'Yes' : 'No'}. {row.ver_lev_basis}<br />
                        <span style={{ color: '#999' }}>Internet-reachable: </span>{row.ver_irv ? 'Yes' : 'No'}. {row.ver_irv_basis}
                      </div>
                    )}
                    {row.cve_id && (
                      <span style={{ fontWeight: 600, color: '#378ADD', marginRight: 12 }}>
                        {row.cve_id}
                      </span>
                    )}
                    {row.kev_listed && (
                      <span style={{ color: '#B00000', marginRight: 12 }}>
                        ⚠ CISA KEV — remediation due {row.kev_due_date || 'N/A'}
                      </span>
                    )}
                    {row.nvd_description || <span style={{ color: '#AAA' }}>No NVD description available.</span>}
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
          {sorted.length === 0 && (
            <tr><td colSpan={columns.length} style={{ ...TD_STYLE, textAlign: 'center', color: '#AAA', padding: 32 }}>
              No vulnerabilities match the current filter.
            </td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

/** The four weighted components behind a priority score, so the rank is auditable. */
function PriorityFactors({ row }) {
  const factors = [
    { label: 'Threat',   value: row.factor_threat,   weight: '40%' },
    { label: 'Severity', value: row.factor_severity, weight: '25%' },
    { label: 'Exposure', value: row.factor_exposure, weight: '20%' },
    { label: 'Urgency',  value: row.factor_urgency,  weight: '15%' },
  ].filter(f => f.value != null)

  if (!factors.length) return null

  return (
    <div style={{ display: 'flex', gap: 18, marginTop: 8, flexWrap: 'wrap' }}>
      {factors.map(f => (
        <div key={f.label} style={{ minWidth: 96 }}>
          <div style={{ fontSize: 10, color: '#999', marginBottom: 3 }}>
            {f.label} <span style={{ color: '#C4C4C4' }}>{f.weight}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 54, height: 4, background: '#E4E4E4', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ width: `${Math.round(f.value * 100)}%`, height: '100%', background: '#378ADD' }} />
            </div>
            <span style={{ fontSize: 10, color: '#666', fontWeight: 600 }}>
              {Math.round(f.value * 100)}
            </span>
          </div>
        </div>
      ))}
    </div>
  )
}

function SlaStatus({ expired, daysLeft }) {
  if (expired) return (
    <span style={{ fontSize: 11, fontWeight: 600, color: '#8B1A1A', background: '#FCEBEB', padding: '2px 8px', borderRadius: 20 }}>
      Expired
    </span>
  )
  if (daysLeft == null) return (
    <span style={{ fontSize: 11, color: '#999' }} title="No fixed timeframe for this finding">Routine</span>
  )
  const warn = daysLeft < 14
  return (
    <span style={{ fontSize: 11, color: warn ? '#7A4100' : '#1A4D0F' }}>
      {daysLeft}d left
    </span>
  )
}

// ─── File drop zone ───────────────────────────────────────────────────────
export function FileDropZone({ label, onFile, file, accept = '.csv' }) {
  const [drag, setDrag] = useState(false)

  function handleDrop(e) {
    e.preventDefault()
    setDrag(false)
    const f = e.dataTransfer.files[0]
    if (f) onFile(f)
  }

  return (
    <label style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', gap: 8,
      border: `2px dashed ${drag ? '#378ADD' : '#DEDEDE'}`,
      borderRadius: 10, padding: '28px 20px',
      cursor: 'pointer', background: drag ? '#EBF4FF' : '#FAFAFA',
      transition: 'all 0.15s',
    }}
      onDragOver={e => { e.preventDefault(); setDrag(true) }}
      onDragLeave={() => setDrag(false)}
      onDrop={handleDrop}
    >
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#AAA" strokeWidth="1.5">
        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/>
      </svg>
      <span style={{ fontSize: 13, color: file ? '#378ADD' : '#AAA', fontWeight: file ? 600 : 400 }}>
        {file ? file.name : label}
      </span>
      <input type="file" accept={accept} style={{ display: 'none' }}
        onChange={e => onFile(e.target.files[0])} />
    </label>
  )
}

// ─── Button ───────────────────────────────────────────────────────────────
export function Button({ children, onClick, disabled, variant = 'primary', loading }) {
  const styles = {
    primary:   { background: '#1a1a2e', color: '#fff', border: '1px solid #1a1a2e' },
    secondary: { background: '#fff', color: '#1a1a2e', border: '1px solid #DEDEDE' },
    danger:    { background: '#E24B4A', color: '#fff', border: '1px solid #E24B4A' },
  }
  return (
    <button onClick={onClick} disabled={disabled || loading} style={{
      ...styles[variant],
      borderRadius: 8, padding: '9px 20px', fontSize: 13,
      fontWeight: 600, cursor: disabled || loading ? 'not-allowed' : 'pointer',
      opacity: disabled ? 0.5 : 1, transition: 'opacity 0.15s',
      display: 'inline-flex', alignItems: 'center', gap: 6,
    }}>
      {loading && <span style={{ width: 12, height: 12, border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.7s linear infinite' }} />}
      {children}
    </button>
  )
}

// ─── Error banner ─────────────────────────────────────────────────────────
export function ErrorBanner({ message, onDismiss }) {
  if (!message) return null
  return (
    <div style={{
      background: '#FCEBEB', border: '1px solid #F09595',
      borderRadius: 8, padding: '10px 16px', marginBottom: 16,
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      fontSize: 13, color: '#8B1A1A',
    }}>
      {message}
      <button onClick={onDismiss} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#8B1A1A', fontSize: 16 }}>×</button>
    </div>
  )
}
