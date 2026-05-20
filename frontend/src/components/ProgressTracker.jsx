import React from 'react'

export default function ProgressTracker({ progress, stage }) {
  return (
    <div className="progress-section">
      <div className="progress-header">
        <span className="spinner" />
        <span>Analyzing file...</span>
      </div>
      <div className="progress-bar-bg">
        <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
      </div>
      <div className="progress-label">{stage}</div>
    </div>
  )
}
