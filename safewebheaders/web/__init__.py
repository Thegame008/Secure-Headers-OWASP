"""Interfaz web local de SafeWebHeaders."""

from .server import create_server, run_server
from .service import analyze_web_payload, serialize_web_report

__all__ = [
    "analyze_web_payload",
    "create_server",
    "run_server",
    "serialize_web_report",
]
