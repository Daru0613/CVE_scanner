"""Minimal local .env loader; avoids requiring a third-party package."""

from __future__ import annotations

import os
from pathlib import Path


def load_local_env(path: Path = Path('.env')) -> bool:
    """Load KEY=VALUE pairs without replacing environment variables already set."""
    if not path.is_file():
        return False
    for raw_line in path.read_text(encoding='utf-8-sig').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ[key] = value
    return True
