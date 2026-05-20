from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class EngineResult(BaseModel):
    engine: str
    status: str
    threats: list[dict] = []
    score: float = 100.0
    details: Optional[dict] = None

class AnalysisResponse(BaseModel):
    analysis_id: int
    filename: str
    file_hash: str
    file_type: str
    file_size: int
    trust_score: float
    threat_count: int
    max_severity: str
    engines: list[EngineResult]
    summary: str
    created_at: datetime

class AnalysisStatus(BaseModel):
    analysis_id: int
    status: str
    progress: int
    stage: str
