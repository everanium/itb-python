"""Thin Python proxy over the libitb shared library's Triple Pipeline
surface.

The package wraps the ``ITB_Triple_*`` C ABI exported by
``cmd/cshared`` (libitb.so / .dylib / .dll) through :mod:`ctypes` —
runtime FFI, no compile-time link, no C compiler at install time.
Every hash-name / MAC-name / cipher-name / profile-name is an opaque
string passed through to Go for validation; the binding carries no
ITB construction logic of its own.

Example::

    import itb

    sender = itb.Pipeline.init("singlemsg-triple-mac-v1")
    receiver = itb.Pipeline.load(sender.save())
    wire = sender.encrypt_message(b"hello")
    assert receiver.decrypt_message(wire) == b"hello"
"""

from __future__ import annotations

from .error import ItbError
from .opts import Opts
from .pipeline import Pipeline, Profile, inspect, lookup, profiles, register
from .runtime import set_gc_percent, set_memory_limit, version
from .status import Status
from .stream import DecryptStream, EncryptStream

__version__ = "0.4.1"

__all__ = [
    "DecryptStream",
    "EncryptStream",
    "ItbError",
    "Opts",
    "Pipeline",
    "Profile",
    "Status",
    "__version__",
    "inspect",
    "lookup",
    "profiles",
    "register",
    "set_gc_percent",
    "set_memory_limit",
    "version",
]
