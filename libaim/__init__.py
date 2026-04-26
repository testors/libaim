"""Public library surface for AiM Wi-Fi and telemetry helpers."""

from .export import build_export_footer
from .telemetry import (
    ChannelInfo,
    LapInfo,
    NumericResampler,
    SessionData,
    TrackInfo,
    build_session,
    compute_time_origin_ms,
    decode_session_bytes,
    looks_like_zlib,
    read_raw_bytes,
    read_session_bytes,
    repair_gps_timecodes,
)
from .wifi import (
    AimSession,
    DiscoveredDevice,
    FileReadResult,
    ProtocolError,
    Session,
    discover,
    parse_session_list,
)

__all__ = [
    "AimSession",
    "ChannelInfo",
    "DiscoveredDevice",
    "FileReadResult",
    "LapInfo",
    "NumericResampler",
    "ProtocolError",
    "Session",
    "SessionData",
    "TrackInfo",
    "build_export_footer",
    "build_session",
    "compute_time_origin_ms",
    "decode_session_bytes",
    "discover",
    "looks_like_zlib",
    "parse_session_list",
    "read_raw_bytes",
    "read_session_bytes",
    "repair_gps_timecodes",
]
