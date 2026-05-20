import React, { useState, useRef } from 'react'

const MAX_SIZE = 25 * 1024 * 1024
const ALLOWED_TYPES = '.pdf,.exe,.dll,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.ps1,.bat,.sh,.py,.js,.vbs,.zip,.rar'

export default function FileUpload({ onFileSelect, disabled }) {
  const [dragOver, setDragOver] = useState(false)
  const [error, setError] = useState(null)
  const inputRef = useRef(null)

  const validate = (file) => {
    if (!file) return 'No file selected'
    const ext = '.' + file.name.split('.').pop().toLowerCase()
    if (!ALLOWED_TYPES.includes(ext)) return `File type "${ext}" is not supported`
    if (file.size > MAX_SIZE) return 'File exceeds max size of 25MB'
    if (file.size === 0) return 'File is empty'
    return null
  }

  const handleFile = (file) => {
    setError(null)
    const err = validate(file)
    if (err) {
      setError(err)
      return
    }
    onFileSelect(file)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }

  const handleChange = (e) => {
    const file = e.target.files[0]
    if (file) handleFile(file)
  }

  return (
    <div className="upload-section">
      <div
        className={`drop-zone ${dragOver ? 'drag-over' : ''} ${disabled ? 'disabled' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => !disabled && inputRef.current?.click()}
      >
        <div className="drop-zone-icon">📄</div>
        <div className="drop-zone-text">
          <strong>Click to browse</strong> or drag & drop a file here
        </div>
        <div className="drop-zone-hint">
          Supported: PDF, EXE, DLL, Office docs, scripts, archives (max 25MB)
        </div>
        <input
          ref={inputRef}
          type="file"
          hidden
          onChange={handleChange}
          accept={ALLOWED_TYPES}
          disabled={disabled}
        />
      </div>
      {error && <div className="error-message">{error}</div>}
    </div>
  )
}
