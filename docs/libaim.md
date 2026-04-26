# `libaim` Library Notes

`libaim` is the shared Python library layer behind this repository's CLIs.

It is organized into three modules:

- `libaim.wifi` for logger discovery and Wi-Fi session operations
- `libaim.telemetry` for XRK/XRZ parsing and session reconstruction
- `libaim.export` for export-style XRK footer generation

## Import Style

Use either the package root:

```python
from libaim import AimSession, build_session, build_export_footer, parse_session_list
```

or module-level imports when you want explicit ownership:

```python
from libaim.wifi import AimSession, parse_session_list
from libaim.telemetry import build_session, read_session_bytes
from libaim.export import build_export_footer
```

## `libaim.wifi`

Primary types and functions:

| Name | Purpose |
|---|---|
| `discover()` | UDP probe for AiM devices |
| `AimSession` | High-level TCP session wrapper |
| `parse_session_list()` | Parse the CSV returned by the logger |
| `Session` | Parsed list entry with `remote_path` helper |
| `ProtocolError` | Framing / protocol-level exception |

Typical workflow:

```python
from libaim.wifi import AimSession, parse_session_list

with AimSession(timeout=30.0) as sess:
    sessions = parse_session_list(sess.fetch_list_csv())
    first = sessions[0]
    data = sess.read_file(first.remote_path)
```

Important `AimSession` methods:

- `fetch_list_csv()`
- `fetch_plain_list_csv()`
- `read_file(path)`
- `read_file_result(path)`
- `delete_file(path)`
- `fetch_device_info()`
- `reset()`

`read_file_result()` returns `FileReadResult(data, ready_size)`, which is useful
when you want to compare the downloaded byte count against the device's `READY size`.

## `libaim.telemetry`

Primary types and functions:

| Name | Purpose |
|---|---|
| `read_session_bytes(path)` | Load `.xrk` / `.xrz` and auto-decompress when needed |
| `read_raw_bytes(path, input_format)` | Read `.xrz` / raw telemetry for converter-style flows |
| `decode_session_bytes(data, ...)` | Explicit decompress / passthrough helper |
| `build_session(raw)` | Parse raw session bytes into `SessionData` |
| `SessionData` | Parsed session object |
| `ChannelInfo` | Decoded CHS metadata |
| `LapInfo` | Decoded LAP record |
| `TrackInfo` | Decoded TRK record |

Typical workflow:

```python
from libaim.telemetry import build_session, read_session_bytes

raw = read_session_bytes("session.xrz")
session = build_session(raw)

print(session.time_origin_ms)
print(session.gps_timing_fixed)
print(session.channels[0].long_name)
```

`SessionData` contains:

- `channels`
- `groups`
- `channel_samples`
- `gps_frames`
- `timeline`
- `time_origin_ms`
- `laps`
- `track`
- `warnings`
- `gps_timing_fixed`

The parser also:

- salvages truncated zlib streams when enough structure remains
- repairs the known GPS `~65533 ms` timing jump when detected
- decodes newer `(c)` expansion-device messages used by newer AiM hardware

## `libaim.export`

Primary function:

```python
from libaim.export import build_export_footer

footer = build_export_footer(
    racer="Driver",
    vehicle="SOLO2DL",
    vehicle_type="GT3",
    note="Qualifying",
)
```

This returns the byte footer equivalent to the metadata footer appended by AiM
Race Studio style XRK exports.

## Error Model

- Transport and socket failures surface as `ConnectionError`, `socket.timeout`, or `OSError`
- Framing and protocol mismatches surface as `libaim.wifi.ProtocolError`
- Telemetry parse failures surface as `ValueError` or `struct.error`

## Related Documents

- [`wifi_protocol.md`](wifi_protocol.md)
- [`xrk_format.md`](xrk_format.md)
