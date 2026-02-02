"""
OpochBench Runners

Five runners that prove OpochHash dominance:
1. serpi_conformance - Prove Ser_Π is canonical and injective
2. mixer_microbench - Compare mixer performance against industry standards
3. end2end_object_hashbench - Full pipeline benchmarks
4. dominance_proofs - Mathematical proofs of system-level dominance
5. pareto_frontier - Prove two-regime mixer is Pareto-optimal
"""

from .serpi_conformance import SerPiConformanceRunner
from .mixer_microbench import MixerMicrobenchRunner
from .end2end_bench import End2EndBenchRunner
from .dominance_proofs import DominanceProofsRunner
from .pareto_frontier import ParetoFrontierRunner

__all__ = [
    'SerPiConformanceRunner',
    'MixerMicrobenchRunner',
    'End2EndBenchRunner',
    'DominanceProofsRunner',
    'ParetoFrontierRunner',
]
