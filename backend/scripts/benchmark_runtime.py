from __future__ import annotations

import argparse
import json
import math
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import ensure_production_demo_db
from app.security.ml_models import get_ml_models
from app.security.shadow_state import ShadowStateManager


def _summary(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)
    return {
        'p50_ms': round(statistics.median(ordered) * 1000, 3),
        'p95_ms': round(ordered[p95_index] * 1000, 3),
        'mean_ms': round(statistics.mean(ordered) * 1000, 3),
    }


def _measure(operation: Callable[[], object], iterations: int) -> tuple[dict[str, float], float]:
    samples: list[float] = []
    cpu_started = time.process_time()
    for _ in range(iterations):
        started = time.perf_counter()
        operation()
        samples.append(time.perf_counter() - started)
    cpu_ms_per_run = (time.process_time() - cpu_started) * 1000 / iterations
    return _summary(samples), round(cpu_ms_per_run, 3)


def benchmark(iterations: int, rows: int) -> dict[str, object]:
    models = get_ml_models()
    trust_tool = {
        'identity_valid': 1,
        'authenticated': 1,
        'permissions_revoked': 0,
        'prohibited_behavior': 0,
        'capabilities': ['read', 'write'],
        'permitted_resources': ['users'],
        'permission_violations': 0,
        'observed_behavior': {},
        'data_sensitivity': 'internal',
        'outbound_permissions': [],
        'approved_relationships': [],
        'transport_secure': True,
        'tool_definition_integrity_valid': True,
        'policy_compliant': True,
    }
    action = {
        'operation': 'SELECT',
        'classification': 'READ_ONLY',
        'target_resource': 'users',
        'capability': 'read',
    }
    trust_result, trust_cpu = _measure(
        lambda: models.predict_trust(trust_tool),
        iterations,
    )
    intent_result, intent_cpu = _measure(
        lambda: models.classify_intent(
            'list users and summarize their names',
            ['read'],
            'production_database',
            action,
            {'sql': 'SELECT id, name FROM users'},
            'CLEAN',
            0,
        ),
        iterations,
    )

    with tempfile.TemporaryDirectory(prefix='shadowguard-benchmark-') as directory:
        database_path = Path(directory) / 'production.db'
        ensure_production_demo_db(str(database_path))
        conn = sqlite3.connect(database_path)
        try:
            conn.executemany(
                'INSERT INTO users (id, name, email) VALUES (?, ?, ?)',
                [
                    (index + 4, f'user-{index}', f'user-{index}@example.test')
                    for index in range(rows)
                ],
            )
            conn.commit()
        finally:
            conn.close()
        shadow_state = ShadowStateManager(str(database_path))
        simulation_times: list[float] = []
        query_count = [0]
        original_connect = sqlite3.connect

        def traced_connect(*args, **kwargs):
            conn = original_connect(*args, **kwargs)
            conn.set_trace_callback(
                lambda _statement: query_count.__setitem__(0, query_count[0] + 1)
            )
            return conn

        sqlite3.connect = traced_connect
        tracemalloc.start()
        cpu_started = time.process_time()
        try:
            for _ in range(iterations):
                started = time.perf_counter()
                result = shadow_state.evaluate_statement(
                    'DELETE FROM users WHERE id = 4'
                )
                if result['simulation_status'] != 'supported':
                    raise RuntimeError('Benchmark shadow simulation did not complete.')
                simulation_times.append(time.perf_counter() - started)
            cpu_ms_per_run = (time.process_time() - cpu_started) * 1000 / iterations
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
            sqlite3.connect = original_connect

    return {
        'iterations': iterations,
        'database_rows': rows + 3,
        'trust_inference': {
            **trust_result,
            'cpu_ms_per_run': trust_cpu,
        },
        'intent_inference': {
            **intent_result,
            'cpu_ms_per_run': intent_cpu,
        },
        'shadow_simulation': {
            **_summary(simulation_times),
            'cpu_ms_per_run': round(cpu_ms_per_run, 3),
            'sqlite_statements_per_run': round(query_count[0] / iterations, 2),
            'python_tracemalloc_peak_kib': round(peak_bytes / 1024, 1),
        },
        'remote_requests': {
            'github': 0,
            'weather': 0,
            'note': 'Remote calls are deliberately excluded from this local benchmark.',
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Measure local ShadowGuard model inference and shadow simulation.'
    )
    parser.add_argument('--iterations', type=int, default=25)
    parser.add_argument('--rows', type=int, default=1000)
    args = parser.parse_args()
    if args.iterations < 1 or args.iterations > 10000:
        parser.error('--iterations must be between 1 and 10000.')
    if args.rows < 0 or args.rows > 1_000_000:
        parser.error('--rows must be between 0 and 1000000.')
    print(json.dumps(benchmark(args.iterations, args.rows), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
