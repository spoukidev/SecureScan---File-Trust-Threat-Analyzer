SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
    "safe": 0,
    "none": 0,
    "unknown": 5,
}

ENGINE_WEIGHTS = {
    "static_analysis": 0.20,
    "yara_scanner": 0.25,
    "hash_lookup": 0.25,
    "metadata_extractor": 0.10,
    "sandbox": 0.20,
}

def calculate(all_results: dict) -> dict:
    total_deductions = 0.0
    max_possible = 100.0
    all_threats = []
    engine_scores = {}

    for engine_name, result in all_results.items():
        weight = ENGINE_WEIGHTS.get(engine_name, 0.15)
        threats = result.get("threats", [])
        engine_max_sev = result.get("max_severity", result.get("severity", "safe"))
        base_deduction = SEVERITY_WEIGHTS.get(engine_max_sev, 5)

        additional_deductions = sum(
            SEVERITY_WEIGHTS.get(t.get("severity", "low"), 5) for t in threats
        )
        total_deductions += (base_deduction + additional_deductions * 0.5) * weight
        all_threats.extend(threats)

        engine_deduction = (base_deduction + additional_deductions * 0.5)
        engine_scores[engine_name] = round(max(0, 100 - engine_deduction), 1)

    final_score = max(0, round(max_possible - total_deductions, 1))

    threat_count = len(all_threats)
    severity_order = ["critical", "high", "medium", "low", "safe", "none"]
    max_sev = "safe"
    if all_threats:
        max_sev = max(all_threats, key=lambda t: severity_order.index(t.get("severity", "safe")) if t.get("severity") in severity_order else 99).get("severity", "safe")

    summary = generate_summary(final_score, threat_count, max_sev)

    return {
        "trust_score": final_score,
        "threat_count": threat_count,
        "max_severity": max_sev,
        "summary": summary,
        "engine_scores": engine_scores,
        "all_threats": all_threats,
    }

def generate_summary(score: float, threat_count: int, severity: str) -> str:
    if score >= 90:
        return f"File appears safe (Score: {score}/100). {threat_count} potential indicators found, all low severity."
    elif score >= 70:
        return f"File shows minor suspicious characteristics (Score: {score}/100). {threat_count} indicators found, max severity: {severity}. Review recommended."
    elif score >= 40:
        return f"File shows significant suspicious characteristics (Score: {score}/100). {threat_count} indicators found, max severity: {severity}. Caution advised."
    else:
        return f"File is highly suspicious (Score: {score}/100). {threat_count} indicators found, max severity: {severity}. Strongly recommend against execution."
