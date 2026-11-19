import re
from pathlib import Path

BEHAVIOR_PATTERNS = {
    "file_operations": {
        "patterns": [
            r"(?:Write|Create|Delete|Copy|Move)\s*(?:File|Stream|Text)",
            r"(?:File\.)?(?:WriteAll|Create|Delete|Copy|Move|Append)",
            r"(?:fopen|fwrite|fdelete|unlink|remove|rename)",
            r"(?:MkDir|RmDir|ChDir|Kill|SetAttr)",
        ],
        "severity": "medium",
        "description": "File system operations that may indicate data manipulation",
    },
    "network_operations": {
        "patterns": [
            r"(?:Socket|TcpClient|UdpClient|WebRequest|HttpClient)",
            r"(?:connect|send|recv|listen|accept)\s*\(",
            r"CreateProcess\s.{0,256}?\s(?:http|ftp|tcp)",
            r"URLDownloadToFile|downloading|upload",
        ],
        "severity": "high",
        "description": "Network communications (potential C2 or data exfiltration)",
    },
    "process_operations": {
        "patterns": [
            r"(?:CreateProcess|CreateRemoteThread|ShellExecute|WinExec|system\()",
            r"(?:Process\.)?Start\s*\(",
            r"NtCreateProcess|ZwCreateProcess",
            r"WScript\.Shell\s*\.\s*(?:Run|Exec)",
        ],
        "severity": "critical",
        "description": "Process creation/injection operations",
    },
    "registry_operations": {
        "patterns": [
            r"(?:RegCreate|RegOpen|RegSet|RegDelete|RegQuery)",
            r"(?:SetValue|CreateSubKey|DeleteSubKey|OpenSubKey)",
            r"(?:HKCU|HKLM|HKEY)[\\/].{0,256}?[Rr]un",
        ],
        "severity": "medium",
        "description": "Registry modifications (potential persistence)",
    },
    "crypto_operations": {
        "patterns": [
            r"(?:AES|RSA|RC4|DES|TripleDES|Rijndael)\w*\.",
            r"(?:CryptEncrypt|CryptDecrypt|CryptAcquireContext)",
            r"(?:CreateEncryptor|CreateDecryptor)",
            r"(?:XOR|bitwise|encrypt|decrypt)\s*\(",
        ],
        "severity": "medium",
        "description": "Cryptographic operations (ransomware or data protection bypass)",
    },
    "anti_debug": {
        "patterns": [
            r"(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)",
            r"(?:OutputDebugString|GetTickCount|rdtsc)",
            r"(?:TLS|AntiDebug|Sandboxie|VBox|VMware|VirtualBox)",
            r"(?:detect|check).{0,256}?(?:debug|vm|sandbox|analysis)",
        ],
        "severity": "high",
        "description": "Anti-analysis / anti-debugging techniques",
    },
    "privilege_escalation": {
        "patterns": [
            r"(?:AdjustTokenPrivileges|SeDebugPrivilege|SeTakeOwnershipPrivilege)",
            r"(?:OpenProcessToken|LookupPrivilegeValue|EnablePrivilege)",
            r"(?:runas|RunAs|ShellExecute.{0,256}?runas)",
            r"(?:UAC|bypass|elevat)",
        ],
        "severity": "high",
        "description": "Privilege escalation attempts",
    },
    "keylogging": {
        "patterns": [
            r"(?:SetWindowsHookEx|GetAsyncKeyState|GetKeyboardState|GetKeyState)",
            r"(?:KeyLogger|keylogger|Keyboard hook)",
            r"(?:WH_KEYBOARD|WH_MOUSE|WH_KEYBOARD_LL)",
            r"(?:Capture|log)\s*(?:key|keystroke|input)",
        ],
        "severity": "critical",
        "description": "Keystroke capture (keylogger)",
    },
}

MAX_STATIC_SCAN_BYTES = 10 * 1024 * 1024


async def analyze(file_path: str) -> dict:
    # This stage performs static string-pattern inspection only. It intentionally
    # never executes an untrusted upload, despite the historical "sandbox" name.
    # Read a bounded prefix so a very large upload cannot cause an avoidable
    # memory spike in the API worker.
    with open(file_path, "rb") as f:
        raw = f.read(MAX_STATIC_SCAN_BYTES + 1)
    scan_truncated = len(raw) > MAX_STATIC_SCAN_BYTES
    raw = raw[:MAX_STATIC_SCAN_BYTES]
    text = raw.decode("utf-8", errors="ignore")

    behaviors = []
    for category, info in BEHAVIOR_PATTERNS.items():
        for pat in info["patterns"]:
            found = re.findall(pat, text, re.IGNORECASE | re.MULTILINE)
            if found:
                behaviors.append({
                    "category": category.replace("_", " ").title(),
                    "severity": info["severity"],
                    "description": info["description"],
                    "match_count": len(found),
                    "samples": list(set(found))[:3],
                })
                break

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_severity = "safe"
    if behaviors:
        max_severity = max(behaviors, key=lambda b: severity_order.get(b["severity"], 0))["severity"]

    return {
        "analysis_type": "static_behavior_heuristics",
        "executed": False,
        "bytes_scanned": len(raw),
        "scan_truncated": scan_truncated,
        "behaviors_detected": len(behaviors),
        "max_severity": max_severity,
        "behaviors": behaviors,
        "threats": [
            {
                "type": f"behavior:{b['category'].lower().replace(' ', '_')}",
                "severity": b["severity"],
                "details": f"{b['description']} ({b['match_count']} matches)",
            }
            for b in behaviors
        ],
        # Kept for API compatibility. Static indicators are not evidence that a
        # sample would execute successfully in a real sandbox.
        "would_execute": False,
        "summary": generate_summary(behaviors),
    }


def generate_summary(behaviors: list) -> str:
    if not behaviors:
        return "No suspicious static behavior indicators detected."
    parts = []
    for b in behaviors:
        parts.append(f"{b['category']} ({b['severity']}): {b['description']}")
    return "Static behavior indicators: " + " | ".join(parts)
