import os
import math
import re
from collections import Counter

SUSPICIOUS_PATTERNS = [
    (r"CreateRemoteThread", 30),
    (r"VirtualAllocEx", 25),
    (r"WriteProcessMemory", 25),
    (r"WinExec", 20),
    (r"ShellExecute", 15),
    (r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+", 10),
    (r"(?:A|a)lloc(?:C|c)onsole", 10),
    (r"(?:D|d)ecrypt(?:S|s)tring", 20),
    (r"(?:I|i)nject", 25),
    (r"(?:M|m)imikatz", 40),
    (r"(?:P|p)owerShell.*(?:-E|nop|bypass)", 30),
    (r"(?:R|r)eg (?:add|delete|import)", 15),
    (r"(?:S|s)chtasks", 15),
    (r"(?:W|w)mi (?:c|C)reate", 15),
    (r"base64", 10),
    (r"0[xX][0-9a-fA-F]{8,}", 10),
    (r"(?:C|c)md\.exe", 10),
    (r"(?:N|n)et\.(?:WebClient|HttpWebRequest)", 15),
    (r"(?:S|s)ystem\.(?:Diagnostics|IO|Reflection)", 15),
    (r"(?:U|u)nsafe (?:N|n)ative (?:M|m)ethods", 20),
]

SUSPICIOUS_STRINGS = [
    "password", "secret", "admin", "exploit", "payload",
    "backdoor", "keylogger", "ransomware", "trojan", "rootkit",
    "malware", "bypass", "obfuscate", "encoded", "decrypt",
]

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    size = len(data)
    counter = Counter(data)
    for count in counter.values():
        p = count / size
        entropy -= p * math.log2(p)
    return entropy

def find_suspicious_strings(data: bytes) -> list[dict]:
    text = data.decode("utf-8", errors="ignore")
    findings = []
    for pattern, weight in SUSPICIOUS_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            unique = list(set(matches))[:5]
            findings.append({
                "pattern": pattern,
                "matches": unique,
                "weight": weight,
                "count": len(matches),
            })
    for s in SUSPICIOUS_STRINGS:
        count = text.lower().count(s.lower())
        if count > 0:
            findings.append({
                "pattern": f"keyword:'{s}'",
                "matches": [s],
                "weight": 5,
                "count": count,
            })
    return findings

def detect_pe_header(data: bytes) -> dict:
    result = {"is_pe": False, "sections": [], "entry_point": None}
    if len(data) < 2:
        return result
    if data[:2] == b"MZ":
        result["is_pe"] = True
        if len(data) > 0x3C:
            pe_offset = int.from_bytes(data[0x3C:0x40], "little")
            if len(data) > pe_offset + 6:
                if data[pe_offset:pe_offset + 2] == b"PE":
                    machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], "little")
                    result["machine"] = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM"}.get(machine, f"unknown({hex(machine)})")
                    if len(data) > pe_offset + 0x28:
                        result["entry_point"] = hex(int.from_bytes(data[pe_offset + 0x28:pe_offset + 0x2C], "little"))
                    section_offset = pe_offset + 0xF8
                    num_sections = int.from_bytes(data[pe_offset + 6:pe_offset + 8], "little")
                    for i in range(min(num_sections, 20)):
                        start = section_offset + i * 40
                        if len(data) > start + 40:
                            name = data[start:start + 8].rstrip(b"\x00").decode("ascii", errors="replace")
                            sect_size = int.from_bytes(data[start + 16:start + 20], "little")
                            sect_chars = int.from_bytes(data[start + 36:start + 40], "little")
                            result["sections"].append({
                                "name": name,
                                "size": sect_size,
                                "executable": bool(sect_chars & 0x20000000),
                                "writable": bool(sect_chars & 0x80000000),
                            })
    return result

def detect_pdf_js(data: bytes) -> dict:
    text = data.decode("utf-8", errors="ignore")
    result = {"has_js": False, "has_openaction": False, "has_embedded_file": False, "js_indicators": []}
    if re.search(r"/JavaScript", text, re.IGNORECASE):
        result["has_js"] = True
        result["js_indicators"].append("JavaScript found in PDF")
    if re.search(r"/OpenAction", text, re.IGNORECASE):
        result["has_openaction"] = True
        result["js_indicators"].append("OpenAction detected (auto-execute on open)")
    if re.search(r"/EmbeddedFile", text, re.IGNORECASE):
        result["has_embedded_file"] = True
        result["js_indicators"].append("Embedded file found")
    if re.search(r"/AA\s|/OpenAction\s|/Launch\s", text, re.IGNORECASE):
        result["js_indicators"].append("Auto-action trigger found")
    if re.search(r"/URI\s*\(.*\)", text, re.IGNORECASE):
        result["js_indicators"].append("URI action found")
    return result

async def analyze(file_path: str) -> dict:
    with open(file_path, "rb") as f:
        data = f.read()

    entropy = calculate_entropy(data)
    suspicious = find_suspicious_strings(data)
    pe_info = detect_pe_header(data)
    pdf_info = detect_pdf_js(data)

    threat_count = sum(f["count"] for f in suspicious)
    severity = "safe"
    if entropy > 7.5:
        severity = "high"
    elif entropy > 6.5:
        severity = "medium"
    elif suspicious:
        severity = "medium" if any(f["weight"] >= 25 for f in suspicious) else "low"

    return {
        "file_size": len(data),
        "entropy": round(entropy, 2),
        "entropy_assessment": "high" if entropy > 7.5 else ("medium" if entropy > 6.5 else "low"),
        "suspicious_strings": suspicious[:20],
        "suspicious_count": threat_count,
        "pe_info": pe_info,
        "pdf_info": pdf_info,
        "severity": severity,
        "threats": [
            {"type": "suspicious_string", "details": f["matches"][:3], "severity": "high" if f["weight"] >= 25 else ("medium" if f["weight"] >= 15 else "low")}
            for f in suspicious[:10]
        ],
    }
