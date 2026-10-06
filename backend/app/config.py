import os

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads")
MAX_FILE_SIZE = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".exe", ".dll", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".ps1", ".bat", ".sh", ".py", ".js", ".vbs", ".zip", ".rar"}
DATABASE_URL = "sqlite+aiosqlite:///securescan.db"
YARA_RULES_PATH = os.path.join(os.path.dirname(__file__), "analysis", "yara_rules")

# Keep browser access explicit; deployments can provide a comma-separated allowlist.
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
]
