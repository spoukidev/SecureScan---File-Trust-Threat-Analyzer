import os
import uuid
import hashlib
import json
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db
from ..models import AnalysisRecord
from ..config import UPLOAD_DIR, MAX_FILE_SIZE, ALLOWED_EXTENSIONS
from ..analysis.pipeline import run_analysis
from ..scoring import calculate
from ..schemas import AnalysisResponse, EngineResult
from pathlib import Path

router = APIRouter()

@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_file(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    if not file.filename:
        raise HTTPException(400, "No file provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"File type '{ext}' is not supported")

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(400, f"File exceeds max size of 25MB")

    safe_name = f"{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(file_path, "wb") as f:
        f.write(content)

    try:
        raw_results = await run_analysis(file_path)

        scoring_result = calculate(raw_results)

        sha256 = hashlib.sha256(content).hexdigest()

        engines = []
        for engine_name, result in raw_results.items():
            engine_score = scoring_result["engine_scores"].get(engine_name, 100)
            threats = result.get("threats", [])
            details = {k: v for k, v in result.items() if k != "threats"}
            status = "completed"
            if "error" in result:
                status = "error"
            engines.append(EngineResult(
                engine=engine_name,
                status=status,
                threats=threats,
                score=engine_score,
                details=details,
            ))

        record = AnalysisRecord(
            filename=file.filename,
            file_hash=sha256,
            file_size=len(content),
            file_type=ext,
            trust_score=scoring_result["trust_score"],
            threat_count=scoring_result["threat_count"],
            max_severity=scoring_result["max_severity"],
            engines_result=[e.model_dump() for e in engines],
            summary=scoring_result["summary"],
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)

        return AnalysisResponse(
            analysis_id=record.id,
            filename=file.filename,
            file_hash=sha256,
            file_type=ext,
            file_size=len(content),
            trust_score=scoring_result["trust_score"],
            threat_count=scoring_result["threat_count"],
            max_severity=scoring_result["max_severity"],
            engines=engines,
            summary=scoring_result["summary"],
            created_at=record.created_at,
        )
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)
