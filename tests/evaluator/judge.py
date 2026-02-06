"""
GDPR Shift-Left MCP Server — Judge Framework

End-to-end evaluator ("judge") that validates MCP server behaviour.
Judges are run on every PR to ensure:
  - Tool registration is complete
  - Tool invocations return expected structures
  - GDPR compliance logic is correct
  - Disclaimer is always present
  - Error handling is graceful
"""
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class JudgeResult:
    """Result of a single judge evaluation."""
    name: str
    passed: bool
    message: str
    details: Optional[str] = None


@dataclass
class JudgeReport:
    """Aggregated report from all judges."""
    results: List[JudgeResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def failures(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    def summary(self) -> str:
        lines = [
            f"Judge Report: {self.total - self.failures}/{self.total} passed",
            "=" * 60,
        ]
        for r in self.results:
            icon = "✅" if r.passed else "❌"
            lines.append(f"  {icon} {r.name}: {r.message}")
            if r.details and not r.passed:
                for detail_line in r.details.splitlines():
                    lines.append(f"      {detail_line}")
        lines.append("=" * 60)
        status = "PASSED" if self.passed else "FAILED"
        lines.append(f"Overall: {status}")
        return "\n".join(lines)


class Judge:
    """Registers and runs evaluation judges for the MCP server."""

    def __init__(self):
        self._checks: List[Callable] = []

    def register(self, fn: Callable):
        """Decorator to register a judge function."""
        self._checks.append(fn)
        return fn

    async def run_all(self, **kwargs) -> JudgeReport:
        """Run all registered judges and return a report."""
        report = JudgeReport()
        for check in self._checks:
            try:
                result = await check(**kwargs)
                if isinstance(result, JudgeResult):
                    report.results.append(result)
                elif isinstance(result, list):
                    report.results.extend(result)
            except Exception as exc:
                report.results.append(JudgeResult(
                    name=check.__name__,
                    passed=False,
                    message=f"Judge crashed: {exc}",
                    details=str(exc),
                ))
        return report


# ─── Global judge instance ──────────────────────────────────────────────────

judge = Judge()
