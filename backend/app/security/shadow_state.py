from __future__ import annotations

import hashlib
import sqlite3
from typing import Any

from app.security.risk_engine import analyze_sql


class SimulationResult:
    """Typed wrapper so callers can distinguish outcomes unambiguously."""
    SUPPORTED   = 'supported'
    UNSUPPORTED = 'unsupported'
    FAILED      = 'failed'


class ShadowStateManager:
    def __init__(self, db_path: str):
        self.db_path = db_path

    # ------------------------------------------------------------------
    # Fingerprint
    # ------------------------------------------------------------------

    def snapshot_fingerprint(self, conn: sqlite3.Connection | None = None) -> str:
        close_connection = conn is None
        conn = conn or sqlite3.connect(self.db_path)
        try:
            digest = hashlib.sha256()
            for index, statement in enumerate(conn.iterdump()):
                if index:
                    digest.update(b'\n')
                digest.update(statement.encode('utf-8'))
            return digest.hexdigest()
        finally:
            if close_connection:
                conn.close()

    # ------------------------------------------------------------------
    # Clone
    # ------------------------------------------------------------------

    def _connect_shadow(self) -> tuple[sqlite3.Connection, str]:
        """
        Return ``(shadow_conn, fingerprint)`` where shadow_conn is an
        in-memory clone of the production database. The fingerprint is
        computed from the completed clone, so it describes exactly the state
        that the simulation evaluated.
        """
        prod = sqlite3.connect(self.db_path)
        try:
            shadow = sqlite3.connect(':memory:')
            prod.backup(shadow)
        finally:
            prod.close()
        fingerprint = self.snapshot_fingerprint(shadow)
        return shadow, fingerprint

    # ------------------------------------------------------------------
    # Sampling helpers
    # ------------------------------------------------------------------

    def _samples_for_tables(
        self,
        conn: sqlite3.Connection,
        tables: list[str],
        limit: int = 5,
        columns_by_table: dict[str, list[str]] | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        samples: dict[str, list[dict[str, Any]]] = {}
        for table in tables:
            rows = conn.execute(f'SELECT * FROM "{table}" LIMIT {limit}').fetchall()
            columns = columns_by_table.get(table) if columns_by_table is not None else None
            if columns is None:
                columns = [
                    desc[1]
                    for desc in conn.execute(f'PRAGMA table_info("{table}")').fetchall()
                ]
                if columns_by_table is not None:
                    columns_by_table[table] = columns
            samples[table] = [dict(zip(columns, row)) for row in rows]
        return samples

    def _count_tables(
        self, conn: sqlite3.Connection, tables: list[str]
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        for table in tables:
            counts[table] = conn.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone()[0]
        return counts

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate_statement(self, sql: str) -> dict[str, Any]:
        """
        Execute *sql* against an isolated in-memory clone of the
        production database and return a structured simulation result.

        The result always includes a ``simulation_status`` field:
        - ``supported``   — simulation ran and produced reliable figures.
        - ``unsupported`` — SQL was rejected by policy before execution.
        - ``failed``      — SQL passed policy but failed during execution
                            on the shadow clone.

        A ``failed`` simulation is never presented as zero impact.
        """
        risk = analyze_sql(sql)
        if not risk['allowed']:
            return {
                'simulation_status': SimulationResult.UNSUPPORTED,
                'allowed': False,
                'rejection_reasons': risk['reasons'],
                'statement_type': risk['statement_type'],
                'tables': risk['tables'],
                'affected_rows': None,
                'total_rows': None,
                'remaining_rows': None,
                'percentage_affected': None,
                'before': {},
                'after': {},
                'severity': risk['severity'],
                'snapshot_fingerprint': None,
                'destructive': risk['destructive'],
                'policy_reasons': risk['reasons'],
                'zero_row_reason': None,
            }

        shadow, fingerprint = self._connect_shadow()
        try:
            tables = risk['tables'] or []
            columns_by_table: dict[str, list[str]] = {}
            before = self._samples_for_tables(
                shadow,
                tables,
                columns_by_table=columns_by_table,
            )
            # Count rows BEFORE execution — this is the denominator for blast-radius %.
            before_counts = self._count_tables(shadow, tables)
            total_before = sum(before_counts.values())

            try:
                cursor = shadow.execute(sql)
                affected_rows = int(cursor.rowcount if cursor.rowcount >= 0 else 0)
            except sqlite3.Error as exc:
                return {
                    'simulation_status': SimulationResult.FAILED,
                    'allowed': True,
                    'rejection_reasons': [],
                    'statement_type': risk['statement_type'],
                    'tables': tables,
                    'affected_rows': None,
                    'total_rows': total_before,
                    'remaining_rows': None,
                    'percentage_affected': None,
                    'before': before,
                    'after': {},
                    'severity': risk['severity'],
                    'snapshot_fingerprint': fingerprint,
                    'destructive': risk['destructive'],
                    'policy_reasons': risk['reasons'],
                    'simulation_error': str(exc),
                    'zero_row_reason': None,
                }

            after = self._samples_for_tables(
                shadow,
                tables,
                columns_by_table=columns_by_table,
            )
            after_counts = self._count_tables(shadow, tables)
            total_after = sum(after_counts.values())

            # Blast-radius percentage: affected / original-count.
            # Guard against division by zero on empty tables.
            if total_before > 0:
                percentage = round((affected_rows / total_before) * 100, 2)
            else:
                percentage = 0.0

            # Explain zero-row outcomes where possible.
            zero_row_reason: str | None = None
            if affected_rows == 0 and risk['statement_type'] in ('DELETE', 'UPDATE'):
                if total_before == 0:
                    zero_row_reason = 'The target table is empty; no rows match.'
                else:
                    zero_row_reason = (
                        'No rows matched the WHERE clause at simulation time. '
                        'The production result may differ if data changes before approval.'
                    )

            return {
                'simulation_status': SimulationResult.SUPPORTED,
                'allowed': True,
                'rejection_reasons': [],
                'statement_type': risk['statement_type'],
                'tables': tables,
                'affected_rows': affected_rows,
                'total_rows': total_before,
                'remaining_rows': total_after,
                'percentage_affected': percentage,
                'before': before,
                'after': after,
                'severity': risk['severity'],
                'snapshot_fingerprint': fingerprint,
                'destructive': risk['destructive'],
                'policy_reasons': risk['reasons'],
                'zero_row_reason': zero_row_reason,
            }
        finally:
            shadow.close()

    # ------------------------------------------------------------------
    # TOCTOU-safe fingerprint check inside an existing transaction
    # ------------------------------------------------------------------

    def current_fingerprint_in_tx(self, conn: sqlite3.Connection) -> str:
        """
        Compute the fingerprint of the production database using an
        already-open connection that holds a transaction.  Call this
        *inside* the BEGIN IMMEDIATE that protects the execute step so
        the check and the mutation are atomic with respect to other writers.
        """
        return self.snapshot_fingerprint(conn)
