"""Auto-seed ``federation_sources`` rows on daemon boot.

Every registered adapter gets a skeleton row (default disabled) regardless
of whether credentials are configured yet. Rows already present are left
untouched so user edits in the Federation UI survive restarts.
"""

from __future__ import annotations

import logging
from typing import List

from daemon.federation.registry import list_adapters
from daemon.federation.store import upsert_source

logger = logging.getLogger(__name__)


def seed_federation_sources() -> List[str]:
    """Insert a skeleton row for every registered adapter (if not already present).

    Rows are seeded unconditionally regardless of whether credentials are
    configured yet. The adapter's fetch() handles the unconfigured case
    gracefully (returns empty findings, preserves cursor). Starting all rows
    as disabled means they are inert until the operator enables them via
    Settings → Federation — at which point the runner picks them up within
    one idle tick (~5 s) without any daemon restart.

    Returns the list of source_ids touched (created or already-existing).
    Failures on individual sources are logged and skipped.
    """
    seeded: List[str] = []
    for adapter in list_adapters():
        try:
            row = upsert_source(
                adapter.name,
                {
                    "enabled": False,
                    "interval_seconds": adapter.default_interval(),
                    "max_items": 1000,
                    "min_severity": None,
                    "cursor": {},
                    "consecutive_errors": 0,
                },
            )
            if row:
                seeded.append(adapter.name)
        except Exception as e:
            logger.warning(
                "Federation seed failed for %s: %s", getattr(adapter, "name", "?"), e
            )
    if seeded:
        logger.info("Federation seeded %d source(s): %s", len(seeded), seeded)
    return seeded
