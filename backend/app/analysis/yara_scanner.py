import os
import re
from pathlib import Path
from ..config import YARA_RULES_PATH

BUILTIN_RULES = {
    "sus_powershell": {
        "name": "Suspicious_PowerShell",
        "description": "Detects suspicious PowerShell patterns including encoded commands and execution policies bypass",
        "severity": "high",
        "patterns": [
            r"powershell.*-(?:E|Encode|nop|NoP|bypass|Bypass)",
            r"-ExecutionPolicy\s+(?:Bypass|Unrestricted)",
            r"\[System\.Reflection\.Assembly\]::Load",
            r"IEX\s*\(.*New-Object",
        ],
    },
    "sus_network": {
        "name": "Suspicious_Network_Activity",
        "description": "Detects network-related indicators often used in malware C2 communications",
        "severity": "high",
        "patterns": [
            r"(?:http|https|ftp)://(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d+",
            r"WinHTTP|WinINet|HttpWebRequest|WebClient",
            r"(?:C|c)onnect(?:B|b)ack",
            r"POST\s+http",
        ],
    },
    "sus_memory": {
        "name": "Suspicious_Memory_Operations",
        "description": "Detects memory manipulation functions common in code injection",
        "severity": "critical",
        "patterns": [
            r"(?:CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread)",
            r"(?:VirtualAllocEx|VirtualProtectEx|WriteProcessMemory)",
            r"(?:NtUnmapViewOfSection|SetThreadContext|QueueUserAPC)",
        ],
    },
    "sus_persistence": {
        "name": "Persistence_Mechanism",
        "description": "Detects registry and scheduled task persistence mechanisms",
        "severity": "medium",
        "patterns": [
            r"(?:HKCU|HKLM|HKEY)[\\/].*[Rr]un",
            r"schtasks\s+/create",
            r"Startup\s*[Ff]older",
            r"ServiceInstaller|ServiceBase\.Run",
        ],
    },
    "sus_obfuscation": {
        "name": "Obfuscation_Techniques",
        "description": "Detects code obfuscation and anti-analysis techniques",
        "severity": "medium",
        "patterns": [
            r"(?:base64|Base64|ToBase64String)",
            r"char\(\d{2,}\)|chr\(\d{2,}\)",
            r"(?:XOR|AES|RC4|Rijndael)\.?(?:Encrypt|Decrypt)",
            r"FromBase64String|System\.Convert",
        ],
    },
    "sus_office_macro": {
        "name": "Suspicious_Office_Macro",
        "description": "Detects suspicious VBA macro patterns in Office documents",
        "severity": "critical",
        "patterns": [
            r"AutoOpen|AutoExec|Auto_Open|Workbook_Open",
            r"Shell\s*\(|CreateObject\s*\(\s*\"",
            r"WScript\.Shell|Shell\.Application",
            r"(?:Write|Read)ProcessMemory",
        ],
    },
}

async def scan(file_path: str) -> dict:
    try:
        ext = Path(file_path).suffix.lower()
        with open(file_path, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8", errors="ignore")

        matches = []
        for rule_id, rule in BUILTIN_RULES.items():
            for pat in rule["patterns"]:
                found = re.findall(pat, text, re.IGNORECASE | re.MULTILINE)
                if found:
                    matches.append({
                        "rule": rule["name"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "matches": len(found),
                        "samples": list(set(found))[:3],
                    })
                    break

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_sev = "safe"
        if matches:
            max_sev = max(matches, key=lambda m: severity_order.get(m["severity"], 0))["severity"]

        return {
            "rules_matched": len(matches),
            "max_severity": max_sev,
            "matches": matches,
            "threats": [
                {
                    "type": f"yara:{m['rule']}",
                    "severity": m["severity"],
                    "details": m["description"],
                    "samples": m.get("samples", []),
                }
                for m in matches
            ],
        }
    except Exception as e:
        return {"rules_matched": 0, "max_severity": "unknown", "matches": [], "threats": [], "error": str(e)}
