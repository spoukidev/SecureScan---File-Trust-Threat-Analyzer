import React, { useState } from 'react'
import FileUpload from './components/FileUpload'
import ProgressTracker from './components/ProgressTracker'
import ResultsDashboard from './components/ResultsDashboard'
import { uploadFile } from './api/client'

const STAGES = [
  'Queueing file...',
  'Running static analysis...',
  'Scanning with YARA rules...',
  'Checking hash databases...',
  'Extracting metadata...',
  'Analyzing behavior...',
  'Computing trust score...',
  'Finalizing results...',
]

export default function App() {
  const [analyzing, setAnalyzing] = useState(false)
  const [progress, setProgress] = useState(0)
  const [stage, setStage] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const handleFileSelect = async (file) => {
    setAnalyzing(true)
    setProgress(0)
    setStage('Queueing file...')
    setResult(null)
    setError(null)

    let stageIdx = 0
    const progInterval = setInterval(() => {
      stageIdx = (stageIdx + 1) % STAGES.length
      setStage(STAGES[stageIdx])
    }, 800)

    try {
      const res = await uploadFile(file, (pct) => {
        setProgress(Math.round(pct * 0.1))
      })
      clearInterval(progInterval)
      setProgress(100)
      setStage('Complete!')
      await new Promise(r => setTimeout(r, 300))
      setResult(res)
    } catch (err) {
      clearInterval(progInterval)
      setError(err.message)
    } finally {
      setAnalyzing(false)
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-content">
          <h1>🛡️ SecureScan</h1>
          <p className="subtitle">File Trust & Threat Analyzer</p>
        </div>
      </header>

      <main className="app-main">
        {!result && !analyzing && (
          <FileUpload onFileSelect={handleFileSelect} disabled={analyzing} />
        )}

        {analyzing && (
          <ProgressTracker progress={progress} stage={stage} />
        )}

        {error && (
          <div className="error-banner">
            <span>Error: {error}</span>
            <button onClick={() => setError(null)} className="btn-text">Dismiss</button>
          </div>
        )}

        {result && (
          <>
            <ResultsDashboard result={result} />
            <div className="analyze-again">
              <button className="btn-primary" onClick={() => { setResult(null); setError(null) }}>
                Analyze Another File
              </button>
            </div>
          </>
        )}
      </main>

      <footer className="app-footer">
        SecureScan v1.0 — File analysis is performed in-memory. Files are not stored after analysis.
      </footer>
    </div>
  )
}
