"""
Base benchmark infrastructure.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum
import time
import json


class BenchmarkStatus(Enum):
    """Benchmark result status."""
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""
    name: str
    status: BenchmarkStatus
    target: str  # What we're trying to achieve
    actual: str  # What we achieved
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'status': self.status.value,
            'target': self.target,
            'actual': self.actual,
            'details': self.details,
            'duration_ms': self.duration_ms,
            'error': self.error
        }

    @property
    def passed(self) -> bool:
        return self.status == BenchmarkStatus.PASS


class Benchmark(ABC):
    """Base class for benchmarks."""

    name: str = "benchmark"
    description: str = "Base benchmark"

    @abstractmethod
    def run(self) -> BenchmarkResult:
        """Run the benchmark."""
        pass

    def timed_run(self) -> BenchmarkResult:
        """Run with timing."""
        start = time.perf_counter()
        try:
            result = self.run()
        except Exception as e:
            result = BenchmarkResult(
                name=self.name,
                status=BenchmarkStatus.ERROR,
                target="Complete without error",
                actual=f"Error: {str(e)}",
                error=str(e)
            )
        end = time.perf_counter()
        result.duration_ms = (end - start) * 1000
        return result


@dataclass
class BenchmarkSuite:
    """Collection of benchmarks."""
    name: str
    benchmarks: List[Benchmark]
    results: List[BenchmarkResult] = field(default_factory=list)

    def run_all(self, verbose: bool = False) -> List[BenchmarkResult]:
        """Run all benchmarks in suite."""
        self.results = []
        for bench in self.benchmarks:
            if verbose:
                print(f"  Running {bench.name}...")
            result = bench.timed_run()
            self.results.append(result)
            if verbose:
                status = "✓" if result.passed else "✗"
                print(f"    {status} {result.status.value}: {result.actual}")
        return self.results

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def total_count(self) -> int:
        return len(self.results)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'suite': self.name,
            'passed': self.pass_count,
            'total': self.total_count,
            'all_passed': self.all_passed,
            'results': [r.to_dict() for r in self.results]
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
