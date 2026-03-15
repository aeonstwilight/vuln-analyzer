const BASE = ''  // Vite proxy handles routing to http://localhost:8000

function buildForm(fields) {
  const form = new FormData()
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined && v !== null) form.append(k, v)
  }
  return form
}

export async function analyzeFile({ file, vendorOverride = 'Auto Detect', profileName = 'FedRAMP Moderate/High', customProfile = null }) {
  const form = buildForm({
    file,
    vendor_override: vendorOverride,
    profile_name: profileName,
    ...(customProfile && {
      critical_days: customProfile.Critical,
      high_days:     customProfile.High,
      medium_days:   customProfile.Medium,
      low_days:      customProfile.Low,
    })
  })
  const res = await fetch(`${BASE}/analyze`, { method: 'POST', body: form })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Analysis failed')
  }
  return res.json()
}

export async function compareFiles({ oldFile, newFile, vendorOverride = 'Auto Detect', profileName = 'FedRAMP Moderate/High' }) {
  const form = buildForm({
    old_file: oldFile,
    new_file: newFile,
    vendor_override: vendorOverride,
    profile_name: profileName,
  })
  const res = await fetch(`${BASE}/compare`, { method: 'POST', body: form })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Comparison failed')
  }
  return res.json()
}

export async function downloadPdfReport({ file, vendorOverride = 'Auto Detect', profileName = 'FedRAMP Moderate/High' }) {
  const form = buildForm({ file, vendor_override: vendorOverride, profile_name: profileName })
  const res = await fetch(`${BASE}/report/pdf`, { method: 'POST', body: form })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Report generation failed')
  }
  // Trigger browser download directly — no state gymnastics needed
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `vuln_report_${new Date().toISOString().slice(0,10)}.pdf`
  a.click()
  URL.revokeObjectURL(url)
}

export async function fetchProfiles() {
  const res = await fetch(`${BASE}/profiles`)
  return res.json()
}
