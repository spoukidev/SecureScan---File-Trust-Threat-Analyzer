from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON
from sqlalchemy.sql import func
from .database import Base

class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), index=True)
    file_size = Column(Integer)
    file_type = Column(String(50))
    trust_score = Column(Float)
    threat_count = Column(Integer)
    max_severity = Column(String(20))
    engines_result = Column(JSON)
    summary = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
