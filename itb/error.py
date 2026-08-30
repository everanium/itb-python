"""Exception type shared by every fallible call in the binding."""

from __future__ import annotations

from .status import Status


class ItbError(Exception):
    """Raised on every failed libitb call.

    ``status`` carries the libitb status code when the failure came
    from the shared library (``None`` for binding-side failures such
    as a library-load error). ``message`` carries the ``ITB_LastError``
    diagnostic captured immediately after the failing call
    (process-global last-write-wins — the message may belong to a
    different call under concurrent FFI use; the status code is
    always attributable).
    """

    def __init__(self, message: str, status: Status | None = None) -> None:
        self.status = status
        self.message = message
        if status is None:
            text = f"itb: {message}"
        elif message:
            text = f"itb: status={int(status)} ({status.label()}): {message}"
        else:
            text = f"itb: status={int(status)} ({status.label()})"
        super().__init__(text)
