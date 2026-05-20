const API_BASE = '/api'

export async function uploadFile(file, onProgress) {
  const formData = new FormData()
  formData.append('file', file)

  const xhr = new XMLHttpRequest()
  return new Promise((resolve, reject) => {
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) {
        onProgress(Math.round((e.loaded / e.total) * 100))
      }
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(JSON.parse(xhr.responseText))
      } else {
        try {
          reject(new Error(JSON.parse(xhr.responseText).detail || 'Upload failed'))
        } catch {
          reject(new Error('Upload failed'))
        }
      }
    }
    xhr.onerror = () => reject(new Error('Network error'))
    xhr.open('POST', `${API_BASE}/analyze`)
    xhr.send(formData)
  })
}

export async function getResult(id) {
  const res = await fetch(`${API_BASE}/results/${id}`)
  if (!res.ok) throw new Error('Failed to fetch result')
  return res.json()
}

export async function downloadReport(id) {
  const res = await fetch(`${API_BASE}/report/${id}`)
  if (!res.ok) throw new Error('Failed to download report')
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `securescan_report_${id}.pdf`
  a.click()
  URL.revokeObjectURL(url)
}

export async function listResults() {
  const res = await fetch(`${API_BASE}/results`)
  if (!res.ok) throw new Error('Failed to fetch results')
  return res.json()
}
