import { useState } from 'react'

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
  maxWidth: 200, overflow: 'hidden',
  textOverflow: 'ellipsis', whiteSpace: 'nowrap',
}

export function VulnTable({ rows, extraColumns = [] }) {
  const [sortCol, setSortCol] = useState('age_days')
  const [sortDir, setSortDir] = useState('desc')

  const columns = [
    { key: 'plugin_id',   label: 'Plugin ID',  width: 90 },
    { key: 'plugin_name', label: 'Name',        width: 220 },
    { key: 'severity',    label: 'Severity',    width: 90 },
    { key: 'host',        label: 'Host',        width: 130 },
    { key: 'cvss',        label: 'CVSS',        width: 60 },
    { key: 'age_days',    label: 'Age (d)',      width: 70 },
    { key: 'days_left',   label: 'Days Left',   width: 80 },
    { key: 'expired',     label: 'SLA',         width: 70 },
    ...extraColumns,
  ]

  const sorted = [...rows].sort((a, b) => {
    const av = a[sortCol] ?? ''
    const bv = b[sortCol] ?? ''
    if (av < bv) return sortDir === 'asc' ? -1 : 1
    if (av > bv) return sortDir === 'asc' ? 1 : -1
    return 0
  })

  function handleSort(key) {
    if (sortCol === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortCol(key); setSortDir('desc') }
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
            <tr key={i} style={{ background: i % 2 === 0 ? '#fff' : '#FAFAFA' }}>
              {columns.map(col => (
                <td key={col.key} style={TD_STYLE} title={String(row[col.key] ?? '')}>
                  {col.key === 'severity'  ? <SeverityBadge severity={row.severity} /> :
                   col.key === 'expired'   ? <SlaStatus expired={row.expired} daysLeft={row.days_left} /> :
                   col.key === 'cvss'      ? Number(row.cvss || 0).toFixed(1) :
                   col.key === 'status'    ? <StatusBadge status={row.status} /> :
                   (row[col.key] ?? '—')}
                </td>
              ))}
            </tr>
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

function SlaStatus({ expired, daysLeft }) {
  if (expired) return (
    <span style={{ fontSize: 11, fontWeight: 600, color: '#8B1A1A', background: '#FCEBEB', padding: '2px 8px', borderRadius: 20 }}>
      Expired
    </span>
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
    primary: { background: '#1a1a2e', color: '#fff', border: '1px solid #1a1a2e' },
    secondary: { background: '#fff', color: '#1a1a2e', border: '1px solid #DEDEDE' },
    danger: { background: '#E24B4A', color: '#fff', border: '1px solid #E24B4A' },
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
