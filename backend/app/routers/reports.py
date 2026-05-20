from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..models import AnalysisRecord
from ..schemas import AnalysisResponse, EngineResult
from typing import List
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.lib import colors

router = APIRouter()

@router.get("/results/{analysis_id}", response_model=AnalysisResponse)
async def get_result(analysis_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.get(AnalysisRecord, analysis_id)
    if not result:
        raise HTTPException(404, "Analysis not found")
    engines = [EngineResult(**e) for e in result.engines_result]
    return AnalysisResponse(
        analysis_id=result.id,
        filename=result.filename,
        file_hash=result.file_hash,
        file_type=result.file_type,
        file_size=result.file_size,
        trust_score=result.trust_score,
        threat_count=result.threat_count,
        max_severity=result.max_severity,
        engines=engines,
        summary=result.summary,
        created_at=result.created_at,
    )

@router.get("/results")
async def list_results(limit: int = 20, db: AsyncSession = Depends(get_db)):
    q = select(AnalysisRecord).order_by(AnalysisRecord.created_at.desc()).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "analysis_id": r.id,
            "filename": r.filename,
            "trust_score": r.trust_score,
            "threat_count": r.threat_count,
            "max_severity": r.max_severity,
            "created_at": str(r.created_at),
        }
        for r in rows
    ]

@router.get("/report/{analysis_id}")
async def download_report(analysis_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.get(AnalysisRecord, analysis_id)
    if not result:
        raise HTTPException(404, "Analysis not found")

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"SecureScan Report - {result.filename}")
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(f"SecureScan Analysis Report", styles["Title"]))
    elements.append(Spacer(1, 0.25 * inch))
    elements.append(Paragraph(f"File: {result.filename}", styles["Heading2"]))
    elements.append(Paragraph(f"Hash: {result.file_hash}", styles["Normal"]))
    elements.append(Paragraph(f"Score: {result.trust_score}/100", styles["Normal"]))
    elements.append(Paragraph(f"Threats: {result.threat_count} (Max: {result.max_severity})", styles["Normal"]))
    elements.append(Spacer(1, 0.25 * inch))
    elements.append(Paragraph(f"Summary: {result.summary}", styles["Normal"]))
    elements.append(Spacer(1, 0.25 * inch))

    score_color = HexColor("#22c55e") if result.trust_score >= 70 else HexColor("#eab308") if result.trust_score >= 40 else HexColor("#ef4444")
    data = [["Engine", "Score", "Threats", "Status"]]
    for e in result.engines_result:
        threats = ", ".join(t.get("type", "") for t in e.get("threats", []))
        data.append([e["engine"], f"{e['score']}/100", threats or "None", e["status"]])
    t = Table(data, colWidths=[1.5*inch, 1*inch, 3*inch, 1*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(t)

    doc.build(elements)
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="securescan_report_{analysis_id}.pdf"'},
    )
