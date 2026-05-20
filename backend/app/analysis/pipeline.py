import asyncio
from . import static_analysis, yara_scanner, hash_lookup, metadata_extractor, sandbox

async def run_analysis(file_path: str, progress_callback=None) -> dict:
    stages = [
        ("static_analysis", static_analysis.analyze),
        ("yara_scanner", yara_scanner.scan),
        ("hash_lookup", hash_lookup.lookup),
        ("metadata_extractor", metadata_extractor.extract),
        ("sandbox", sandbox.analyze),
    ]

    results = {}
    total = len(stages)

    async def run_stage(name, func):
        try:
            result = await func(file_path)
            return name, result
        except Exception as e:
            return name, {"error": str(e), "threats": []}

    tasks = [run_stage(name, func) for name, func in stages]
    done = await asyncio.gather(*tasks)

    for i, (name, result) in enumerate(done):
        results[name] = result
        if progress_callback:
            await progress_callback(int((i + 1) / total * 100))

    return results
