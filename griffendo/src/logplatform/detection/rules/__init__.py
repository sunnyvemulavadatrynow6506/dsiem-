"""Detection rules: one module per rule, listed in index.py.

Folders
  windows/<source>/rule_<id>.py   imported (Elastic ELA-*, Wazuh WAZ-*) and v2-v4 catalog rules, by event source
  correlation/rule_<id>.py        Griffendo chain (CHN-*) and correlation (COR-*) rules
  behavior/rule_<id>.py           behaviour-model rule switches (BEH-*)
  custom/                         user-created rules live in triage.db (validated JSON, never code)
"""
from __future__ import annotations

from typing import Any


def load_all() -> tuple[list[Any], list[str]]:
    from ..engine.registry import load_modules
    from .index import MODULES
    return load_modules(MODULES)
