import hashlib
import json

KNOWN_THREAT_DB = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"malicious": False, "name": "known_clean_empty"},
}

THREAT_INTEL = [
    {"hash_prefix": "a1b2c3", "malicious": True, "name": "Trojan.Generic.12345", "severity": "high"},
    {"hash_prefix": "deadbe", "malicious": True, "name": "Ransomware.WannaCry.Variant", "severity": "critical"},
    {"hash_prefix": "f00ba1", "malicious": True, "name": "Backdoor.RemoteAccess.001", "severity": "high"},
    {"hash_prefix": "cafeb0", "malicious": True, "name": "CoinMiner.XMRig", "severity": "medium"},
    {"hash_prefix": "badbad", "malicious": True, "name": "Worm.Python.Rabbit", "severity": "high"},
    {"hash_prefix": "123456", "malicious": True, "name": "AgentTesla.Keylogger", "severity": "critical"},
    {"hash_prefix": "555555", "malicious": True, "name": "LokiBot.Infostealer", "severity": "high"},
    {"hash_prefix": "aaaaaa", "malicious": False, "name": "known_clean_lib"},
    {"hash_prefix": "bbbbbb", "malicious": False, "name": "known_clean_system"},
]

def compute_hashes(file_path: str) -> dict:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}

async def lookup(file_path: str) -> dict:
    hashes = compute_hashes(file_path)
    sha256 = hashes["sha256"]

    if sha256 in KNOWN_THREAT_DB:
        entry = KNOWN_THREAT_DB[sha256]
        return {
            "hash": sha256,
            "md5": hashes["md5"],
            "known": True,
            "malicious": entry["malicious"],
            "name": entry["name"],
            "severity": "critical" if entry["malicious"] else "none",
            "detection_ratio": "1/1" if entry["malicious"] else "0/1",
            "threats": [
                {
                    "type": "hash_match",
                    "severity": "critical" if entry["malicious"] else "none",
                    "details": f"Known {entry['name']} (SHA256 match)",
                }
            ] if entry["malicious"] else [],
        }

    prefix = sha256[:6]
    for intel in THREAT_INTEL:
        if prefix == intel["hash_prefix"]:
            return {
                "hash": sha256,
                "md5": hashes["md5"],
                "known": True,
                "malicious": intel["malicious"],
                "name": intel["name"],
                "severity": intel["severity"] if intel["malicious"] else "none",
                "detection_ratio": "5/70" if intel["malicious"] else "0/70",
                "threats": [
                    {
                        "type": "hash_match",
                        "severity": intel["severity"],
                        "details": f"Matched threat intel: {intel['name']} (prefix: {prefix})",
                    }
                ] if intel["malicious"] else [],
            }

    return {
        "hash": sha256,
        "md5": hashes["md5"],
        "known": False,
        "malicious": False,
        "name": "unknown",
        "severity": "none",
        "detection_ratio": "0/70",
        "threats": [],
    }
