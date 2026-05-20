import os
import json
from pathlib import Path

OFFICE_MACRO_INDICATORS = [
    b"Auto_Open", b"AutoOpen", b"Workbook_Open", b"Document_Open",
    b"VBA/", b"Module", b"Macro", b"ThisDocument",
    b"Attribute VB_Name", b"Declare Function", b"Declare Sub",
    b"Shell(", b"CreateObject(", b"WScript.Shell",
    b"PowerShell", b"cmd.exe", b"rundll32",
]

PE_METADATA_FIELDS = [
    "CompanyName", "FileDescription", "FileVersion", "ProductName",
    "OriginalFilename", "LegalCopyright", "InternalName",
]

async def extract(file_path: str) -> dict:
    path = Path(file_path)
    ext = path.suffix.lower()
    metadata = {
        "filename": path.name,
        "extension": ext,
        "size_bytes": path.stat().st_size,
        "file_type": classify_file_type(ext),
    }

    with open(file_path, "rb") as f:
        raw = f.read()
    raw_lower = raw.lower()

    if ext == ".pdf":
        metadata.update(extract_pdf_metadata(raw, raw_lower))
    elif ext in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"):
        metadata.update(extract_office_metadata(raw, raw_lower))
    elif ext in (".exe", ".dll"):
        metadata.update(extract_pe_metadata(raw, raw_lower))
    elif ext in (".ps1", ".bat", ".sh", ".py", ".js", ".vbs"):
        metadata.update(extract_script_metadata(raw, raw_lower))

    threats = []
    if metadata.get("has_macros"):
        threats.append({"type": "vba_macro", "severity": "high", "details": "Document contains VBA macros"})
    if metadata.get("has_embedded_ole"):
        threats.append({"type": "embedded_ole", "severity": "medium", "details": "Contains embedded OLE objects"})
    if metadata.get("has_js"):
        threats.append({"type": "pdf_javascript", "severity": "high", "details": "PDF contains JavaScript"})
    if metadata.get("has_openaction"):
        threats.append({"type": "pdf_openaction", "severity": "medium", "details": "PDF has auto-execute OpenAction"})
    if metadata.get("sections"):
        suspicious_sections = [s for s in metadata["sections"] if s.get("executable") and s.get("writable")]
        for s in suspicious_sections:
            threats.append({"type": "pe_suspicious_section", "severity": "medium", "details": f"Section {s['name']} is both executable and writable"})

    return {
        "metadata": metadata,
        "threats": threats,
    }

def classify_file_type(ext: str) -> str:
    mapping = {
        ".pdf": "PDF Document",
        ".exe": "PE Executable",
        ".dll": "PE Dynamic Link Library",
        ".doc": "Word Document (OLE2)",
        ".docx": "Word Document (OOXML)",
        ".xls": "Excel Spreadsheet (OLE2)",
        ".xlsx": "Excel Spreadsheet (OOXML)",
        ".ppt": "PowerPoint (OLE2)",
        ".pptx": "PowerPoint (OOXML)",
        ".ps1": "PowerShell Script",
        ".bat": "Batch Script",
        ".sh": "Shell Script",
        ".py": "Python Script",
        ".js": "JavaScript",
        ".vbs": "VBScript",
        ".zip": "ZIP Archive",
        ".rar": "RAR Archive",
    }
    return mapping.get(ext, f"Unknown ({ext})")

def extract_pdf_metadata(raw: bytes, raw_lower: bytes) -> dict:
    import re
    text = raw.decode("utf-8", errors="ignore")
    result = {
        "version": extract_pdf_version(text),
        "page_count": count_occurrences(text, r"/Type\s*/Page"),
        "has_js": bool(re.search(r"/JavaScript", text, re.IGNORECASE)),
        "has_openaction": bool(re.search(r"/OpenAction", text, re.IGNORECASE)),
        "has_embedded_file": bool(re.search(r"/EmbeddedFile", text, re.IGNORECASE)),
        "has_launch_action": bool(re.search(r"/Launch", text, re.IGNORECASE)),
        "has_auto_action": bool(re.search(r"/AA\s", text, re.IGNORECASE)),
        "has_acroform": bool(re.search(r"/AcroForm", text, re.IGNORECASE)),
        "stream_count": count_occurrences(text, r"stream\s"),
        "objects": count_occurrences(text, r"\d+\s+\d+\s+obj"),
    }
    return result

def extract_pdf_version(text: str) -> str:
    import re
    m = re.search(r"%PDF-(\d+\.\d+)", text)
    return m.group(1) if m else "unknown"

def extract_office_metadata(raw: bytes, raw_lower: bytes) -> dict:
    result = {
        "has_macros": any(ind in raw for ind in OFFICE_MACRO_INDICATORS),
        "has_embedded_ole": b"\x01\x05\x00\x00OLE" in raw or b"Embedded" in raw,
        "ole_indicators": [],
    }
    if result["has_macros"]:
        for ind in OFFICE_MACRO_INDICATORS:
            if ind in raw:
                result["ole_indicators"].append(ind.decode("utf-8", errors="replace"))
    result["macro_count"] = len(result["ole_indicators"])
    return result

def extract_pe_metadata(raw: bytes, raw_lower: bytes) -> dict:
    import re
    result = {
        "is_pe": raw[:2] == b"MZ",
        "strings_found": count_occurrences(raw.decode("utf-8", errors="ignore"), r"[a-zA-Z_]\w{4,}"),
    }
    if result["is_pe"]:
        for field in PE_METADATA_FIELDS:
            pattern = re.compile(rb"(%s\x00)([^\x00]{1,128})\x00" % field.encode(), re.IGNORECASE)
            m = pattern.search(raw)
            if m:
                val = m.group(2).decode("utf-8", errors="replace").strip("\x00")
                result[field] = val
    return result

def extract_script_metadata(raw: bytes, raw_lower: bytes) -> dict:
    text = raw.decode("utf-8", errors="ignore")
    lines = text.split("\n")
    result = {
        "line_count": len(lines),
        "has_shebang": lines[0].startswith("#!") if lines else False,
        "has_base64": "base64" in text.lower(),
        "has_urls": "http://" in text or "https://" in text,
        "has_eval": "eval(" in text.lower(),
        "has_encoded_command": "-enc " in text.lower() or "-e " in text.lower() or "-encode" in text.lower(),
    }
    return result

def count_occurrences(text: str, pattern: str) -> int:
    import re
    return len(re.findall(pattern, text, re.IGNORECASE))
