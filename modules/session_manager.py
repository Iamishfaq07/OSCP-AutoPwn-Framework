"""
session_manager.py - Save/restore pipeline state for resume capability
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Any

log = logging.getLogger("autopwn.session")


class SessionManager:
    """Persist and restore target scan state across interruptions."""

    def __init__(self, output_dir: Path, resume: bool = False):
        self.output_dir = Path(output_dir)
        self.resume = resume
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._state_cache: dict = {}

    def _state_file(self, target: str) -> Path:
        safe = target.replace("/", "_").replace(":", "_")
        return self.output_dir / safe / ".state.json"

    def save_state(self, target: str, data: dict):
        """Persist state dictionary to JSON."""
        path = self._state_file(target)
        path.parent.mkdir(parents=True, exist_ok=True)

        snapshot = {
            "target": target,
            "updated_at": datetime.utcnow().isoformat(),
            "data": self._make_serializable(data),
        }

        try:
            with open(path, "w") as f:
                json.dump(snapshot, f, indent=2)
            self._state_cache[target] = data
            log.debug(f"State saved for {target}")
        except Exception as e:
            log.warning(f"Could not save state for {target}: {e}")

    def load_state(self, target: str) -> Optional[dict]:
        """Load previously saved state, if resume mode and file exists."""
        if not self.resume:
            return None

        path = self._state_file(target)
        if not path.exists():
            return None

        try:
            with open(path) as f:
                snapshot = json.load(f)
            log.info(f"Resumed state for {target} (updated: {snapshot.get('updated_at')})")
            return snapshot.get("data", {})
        except Exception as e:
            log.warning(f"Could not load state for {target}: {e}")
            return None

    def clear_state(self, target: str):
        """Remove saved state for a target."""
        path = self._state_file(target)
        if path.exists():
            path.unlink()
        self._state_cache.pop(target, None)

    def _make_serializable(self, obj: Any) -> Any:
        """Recursively make object JSON-serializable."""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._make_serializable(i) for i in obj]
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        return str(obj)
