import asyncio
import os
import tempfile
import time
import unittest

from app.analysis import sandbox, static_analysis, yara_scanner


def _run(func, content: bytes) -> dict:
    fd, path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        return asyncio.run(func(path))
    finally:
        os.remove(path)


class PatternPerformanceTests(unittest.TestCase):
    """Wildcard gaps must stay bounded so one long line can't stall the worker."""

    # Each payload repeats a pattern prefix on a single line with no closing
    # keyword. With an unbounded ".*" gap the regex work grows quadratically.
    PAYLOADS = [
        b"check ",
        b"HKCU/x ",
        b"ShellExecute ",
        b"CreateProcess ",
        b"powershell ",
        b"IEX ( ",
        b"/URI ( ",
    ]
    SIZE = 400_000

    def test_pathological_single_line_input_is_fast(self):
        for payload in self.PAYLOADS:
            content = payload * (self.SIZE // len(payload))
            for engine in (sandbox.analyze, yara_scanner.scan, static_analysis.analyze):
                with self.subTest(payload=payload, engine=engine.__module__):
                    start = time.perf_counter()
                    _run(engine, content)
                    self.assertLess(time.perf_counter() - start, 5.0)

    def test_bounded_patterns_still_detect_indicators(self):
        content = (
            b"if check_for_debugger(): pass\n"
            b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            b"powershell.exe -nop -w hidden\n"
            b"IEX (New-Object Net.WebClient).DownloadString('x')\n"
        )
        behaviors = {b["category"] for b in _run(sandbox.analyze, content)["behaviors"]}
        self.assertIn("Anti Debug", behaviors)
        self.assertIn("Registry Operations", behaviors)

        rules = {m["rule"] for m in _run(yara_scanner.scan, content)["matches"]}
        self.assertIn("Suspicious_PowerShell", rules)
        self.assertIn("Persistence_Mechanism", rules)

        pdf = b"%PDF-1.4\n1 0 obj << /A << /S /URI /URI (http://example.com) >> >>\n"
        self.assertIn("URI action found", _run(static_analysis.analyze, pdf)["pdf_info"]["js_indicators"])


if __name__ == "__main__":
    unittest.main()
