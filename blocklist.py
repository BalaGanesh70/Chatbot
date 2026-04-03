import time
from typing import Dict, Optional, Tuple

_BLOCK_STATE: Dict[str, Dict[str, float | int]] = {}

_ATTEMPT_THRESHOLD = 2  
_BLOCK_WINDOW_SECONDS = 120 


def _key(session_id: Optional[str], role: Optional[str]) -> Optional[str]:
    if not session_id:
        return None
    role_part = (role or "").strip()
    return f"{session_id}:{role_part}"


def register_sensitive_attempt(session_id: Optional[str], role: Optional[str]) -> Tuple[bool, int]:
    """
    Register a sensitive attempt for a specific session+role. If attempts reach threshold,
    start a block window for that role only. Returns (is_blocked_now, remaining_seconds).
    """
    k = _key(session_id, role)
    if not k:
        return False, 0
    now = time.time()
    state = _BLOCK_STATE.get(k) or {"count": 0, "blocked_until": 0.0}

    blocked_until = float(state.get("blocked_until", 0.0))
    if blocked_until > now:
        remaining = int(blocked_until - now)
        _BLOCK_STATE[k] = state
        return True, remaining

    count = int(state.get("count", 0)) + 1
    state["count"] = count

    if count >= _ATTEMPT_THRESHOLD:
        state["blocked_until"] = now + _BLOCK_WINDOW_SECONDS
        state["count"] = 0  
        _BLOCK_STATE[k] = state
        return True, _BLOCK_WINDOW_SECONDS

    _BLOCK_STATE[k] = state
    return False, 0


def is_blocked(session_id: Optional[str], role: Optional[str]) -> Tuple[bool, int]:
    """Return (blocked, remaining_seconds) for a session_id + role pair."""
    k = _key(session_id, role)
    if not k:
        return False, 0
    now = time.time()
    state = _BLOCK_STATE.get(k)
    if not state:
        return False, 0
    blocked_until = float(state.get("blocked_until", 0.0))
    if blocked_until > now:
        return True, int(blocked_until - now)
    return False, 0


def clear_block(session_id: Optional[str], role: Optional[str]) -> None:
    k = _key(session_id, role)
    if not k:
        return
    _BLOCK_STATE.pop(k, None)
