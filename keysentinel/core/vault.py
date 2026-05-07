"""Secure in-memory handling of API keys.

Keys are stored as mutable bytearrays and zeroed on scope exit.
They are never converted to immutable str unless strictly required by an external API call,
and even then the str reference is deleted immediately after use.
"""

from __future__ import annotations

import ctypes
import hashlib
import re
from types import TracebackType
from typing import Self


_REDACT_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9\-_]{10,}|AKIA[A-Z0-9]{16}|rk_live_[A-Za-z0-9]{20,}"
    r"|sk-ant-[A-Za-z0-9\-_]{10,}|ghp_[A-Za-z0-9]{36}|pk_live_[A-Za-z0-9]{20,})"
)


def redact(text: str) -> str:
    """Replace any recognisable key pattern with a masked version."""
    def _mask(m: re.Match) -> str:
        v = m.group(0)
        return v[:6] + "****" + v[-4:]
    return _REDACT_PATTERN.sub(_mask, text)


class SecureBytes:
    """Wraps a key as a zeroed-on-exit bytearray.

    Usage::

        with SecureBytes(raw_input) as key:
            do_something(key.to_str())   # str lives only inside the call
    """

    def __init__(self, value: str | bytes) -> None:
        if isinstance(value, str):
            self._buf = bytearray(value.encode())
        else:
            self._buf = bytearray(value)

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.wipe()

    def __del__(self) -> None:
        self.wipe()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def wipe(self) -> None:
        """Zero every byte and release the buffer."""
        if self._buf:
            n = len(self._buf)
            for i in range(n):
                self._buf[i] = 0
            # Zero the underlying C buffer via ctypes using the correct data pointer
            try:
                raw_ptr = (ctypes.c_char * n).from_buffer(self._buf)
                ctypes.memset(raw_ptr, 0, n)
            except (TypeError, ValueError):
                pass  # from_buffer may fail if buf was already released — zeroing above is sufficient  # nosec B110
            self._buf = bytearray()

    def to_str(self) -> str:
        """Return an immutable str copy. Caller must delete it ASAP."""
        return self._buf.decode(errors="replace")

    def sha256(self) -> str:
        """Return hex SHA-256 of the key (safe to send to GitGuardian)."""
        return hashlib.sha256(bytes(self._buf)).hexdigest()

    def masked(self) -> str:
        """Return a masked representation safe for logs and reports."""
        raw = self._buf.decode(errors="replace")
        if len(raw) <= 10:
            return "****"
        return raw[:6] + "****" + raw[-4:]

    def __len__(self) -> int:
        return len(self._buf)

    def __repr__(self) -> str:
        return f"SecureBytes(masked={self.masked()!r})"
