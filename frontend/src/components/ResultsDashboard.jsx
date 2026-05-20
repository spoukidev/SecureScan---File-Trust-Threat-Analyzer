import React from 'react'
import ThreatDetails from './ThreatDetails'
import { downloadReport } from '../api/client'

function ScoreGauge({ score }) {
  const color = score >= 70 ? '#22c55e' : score >= 40 ? '#eab308' : '#ef4444'
  const r = 60
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ

  return (
    <div className="gauge-container">
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r={r} fill="none" stroke="#1e293b" strokeWidth="12" />
        <circle cx="80" cy="80" r={r} fill="none" stroke={color} strokeWidth="12"
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round" transform="rotate(-90 80 80)" style={{ transition: 'stroke-dashoffset 1s ease' }} />
        <text x="80" y="85" textAnchor="middle" fontSize="36" fontWeight="bold" fill="#f1f5f9">{score}</text>
      </svg>
      <div className="gauge-label">Trust Score</div>
    </div>
  )
}

export default function ResultsDashboard({ result }) {
  if (!result) return null

  const severityColor = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    safe: '#22c55e',
  }

  const allThreats = result.engines?.flatMap(e => e.threats || []) || []

  return (
    <div className="results-section">
      <div className="results-header">
        <h2>Analysis Results</h2>
        <button className="btn-secondary" onClick={() => downloadReport(result.analysis_id)}>
          📥 Download PDF Report
        </button>
      </div>

      <div className="results-grid">
        <ScoreGauge score={result.trust_score} />

        <div className="results-summary">
          <div className="summary-item">
            <span className="summary-label">File</span>
            <span className="summary-value">{result.filename}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">SHA256</span>
            <span className="summary-value mono">{result.file_hash?.slice(0, 32)}...</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">Threats Found</span>
            <span className="summary-value" style={{ color: result.threat_count > 0 ? '#ef4444' : '#22c55e' }}>
              {result.threat_count}
            </span>
          </div>
          <div className="summary-item">
            <span className="summary-label">Max Severity</span>
            <span className="summary-value">
              <span className={`badge badge-${result.max_severity}`}>{result.max_severity}</span>
            </span>
          </div>
          <div className="summary-item summary-item-full">
            <span className="summary-label">Summary</span>
            <span className="summary-value">{result.summary}</span>
          </div>
        </div>
      </div>

      <div className="engines-section">
        <h3>Engine Breakdown</h3>
        <div className="engine-cards">
          {result.engines?.map((engine, i) => (
            <div key={i} className={`engine-card ${engine.status === 'error' ? 'engine-error' : ''}`}>
              <div className="engine-header">
                <span className="engine-name">{engine.engine.replace(/_/g, ' ')}</span>
                <span className={`engine-score ${engine.score >= 70 ? 'score-good' : engine.score >= 40 ? 'score-warn' : 'score-bad'}`}>
                  {engine.score}
                </span>
              </div>
              <div className="engine-status">
                Status: {engine.status}
              </div>
              {engine.threats && engine.threats.length > 0 && (
                <div className="engine-threat-count">
                  {engine.threats.length} threat(s) detected
                </div>
              )}
              {engine.details && (
                <div className="engine-details">
                  {engine.details.entropy !== undefined && (
                    <div>Entropy: {engine.details.entropy}</div>
                  )}
                  {engine.details.rules_matched !== undefined && (
                    <div>YARA matches: {engine.details.rules_matched}</div>
                  )}
                  {engine.details.behaviors_detected !== undefined && (
                    <div>Behaviors: {engine.details.behaviors_detected}</div>
                  )}
                  {engine.details.metadata?.file_type && (
                    <div>Type: {engine.details.metadata.file_type}</div>
                  )}
                  {engine.details.malicious !== undefined && (
                    <div>Known threat: {engine.details.malicious ? '⚠️ Yes' : '✅ No'}</div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <ThreatDetails threats={allThreats} />
    </div>
  )
}
