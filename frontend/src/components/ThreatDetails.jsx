import React from 'react'

export default function ThreatDetails({ threats }) {
  if (!threats || threats.length === 0) return null

  return (
    <div className="threats-section">
      <h3>Threat Indicators</h3>
      {threats.map((t, i) => (
        <div key={i} className={`threat-item severity-${t.severity}`}>
          <span className={`badge badge-${t.severity}`}>{t.severity}</span>
          <span className="threat-type">{t.type}</span>
          <span className="threat-details">{t.details}</span>
          {t.samples && t.samples.length > 0 && (
            <div className="threat-samples">
              {t.samples.map((s, j) => (
                <code key={j}>{s}</code>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
