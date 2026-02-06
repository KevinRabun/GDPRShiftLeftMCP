"""
CLI entry-point to run all judges.

Usage:
    python -m tests.evaluator.run_judges
"""
import asyncio
import sys

from .judge import judge
from . import checks  # noqa: F401 — registers all judges


async def main() -> int:
    report = await judge.run_all()
    print(report.summary())
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
