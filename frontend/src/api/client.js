const BASE = ''  // Vite proxy handles routing to http://localhost:8000

function buildForm(fields) {
  const form = new FormData()
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined && v !== null) form.append(k, v)
  }
  return form
}

// Extra form fields for the FedRAMP 2026 profiles; the backend ignores them otherwise.
function verFields(ver) {
  if (!ver) return {}
  return {
    asset_context: ver.assetContext,
    assume_internet_reachable: ver.assumeReachable ? 'true' : 'false',
  }
}

async function downloadBlob(res, filename) {
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export async function analyzeFile({ file, vendorOverride = 'Auto Detect', profileName = 'FedRAMP Moderate/High', customProfile = null, ver = null }) {
  const form = buildForm({
    file,
    vendor_override: vendorOverride,
    profile_name: profileName,
    ...verFields(ver),
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

export async function downloadPdfReport({ file, vendorOverride = 'Auto Detect', profileName = 'FedRAMP Moderate/High', ver = null }) {
  const form = buildForm({ file, vendor_override: vendorOverride, profile_name: profileName, ...verFields(ver) })
  const date = new Date().toISOString().slice(0, 10)
  await downloadBlob(
    await fetch(`${BASE}/report/pdf`, { method: 'POST', body: form }),
    `vuln_report_${date}.pdf`
  )
}

export async function downloadJsonReport({ file, vendorOverride = 'Auto Detect', profileName = 'FedRAMP Moderate/High', ver = null }) {
  const form = buildForm({ file, vendor_override: vendorOverride, profile_name: profileName, ...verFields(ver) })
  const date = new Date().toISOString().slice(0, 10)
  await downloadBlob(
    await fetch(`${BASE}/report/json`, { method: 'POST', body: form }),
    `vuln_report_${date}.json`
  )
}

export async function downloadOscalReport({ file, vendorOverride = 'Auto Detect', profileName = 'FedRAMP Moderate/High', systemName = 'Information System', ver = null }) {
  const form = buildForm({ file, vendor_override: vendorOverride, profile_name: profileName, system_name: systemName, ...verFields(ver) })
  const date = new Date().toISOString().slice(0, 10)
  await downloadBlob(
    await fetch(`${BASE}/report/oscal`, { method: 'POST', body: form }),
    `poam_oscal_${date}.json`
  )
}

export async function downloadVerReport({ file, vendorOverride = 'Auto Detect', profileName = 'FedRAMP 2026 Class B', ver = null }) {
  const form = buildForm({ file, vendor_override: vendorOverride, profile_name: profileName, ...verFields(ver) })
  const date = new Date().toISOString().slice(0, 10)
  await downloadBlob(
    await fetch(`${BASE}/report/ver`, { method: 'POST', body: form }),
    `ver_detail_${date}.json`
  )
}

export async function fetchProfiles() {
  const res = await fetch(`${BASE}/profiles`)
  return res.json()
}
