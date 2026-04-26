"""Helpers for building export-style XRK footers."""

from __future__ import annotations


def encode_tag(tag: str) -> bytes:
    encoded = tag.encode("ascii")
    if len(encoded) > 4:
        raise ValueError(f"tag must be at most 4 ASCII bytes: {tag!r}")
    return encoded.ljust(4, b"\0")


def wrap_frame(tag: str, payload: bytes, cls: int = 0x00) -> bytes:
    tag_bytes = encode_tag(tag)
    checksum = (sum(payload) & 0xFFFF).to_bytes(2, "little")
    header = b"<h" + tag_bytes + len(payload).to_bytes(4, "little") + bytes((cls,)) + b">"
    trailer = b"<" + tag_bytes + checksum + b">"
    return header + payload + trailer


def encode_footer_value(name: str, value: str, encoding: str) -> bytes:
    if "\0" in value:
        raise ValueError(f"{name} cannot contain NUL bytes")
    try:
        return value.encode(encoding)
    except UnicodeEncodeError as exc:
        raise ValueError(f"could not encode {name!r} with {encoding}: {exc}") from exc


def build_export_footer(
    *,
    racer: str = "",
    vehicle: str = "",
    vehicle_type: str = "",
    note: str = "",
    encoding: str = "utf-8",
) -> bytes:
    """Build the footer appended to raw XRK bodies by Race Studio exports."""
    footer = bytearray()
    fields = (
        ("RCR", "racer", racer),
        ("VEH", "vehicle", vehicle),
        ("VTY", "vehicle_type", vehicle_type),
        ("NTE", "note", note),
    )
    for tag, name, value in fields:
        payload = encode_footer_value(name, value, encoding)
        footer.extend(wrap_frame(tag, payload, cls=0x00))
    return bytes(footer)


__all__ = [
    "build_export_footer",
    "encode_footer_value",
    "encode_tag",
    "wrap_frame",
]
