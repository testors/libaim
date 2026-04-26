# libaim

`libaim` is a pure-Python library for working with AiM data loggers and session files.

It provides:

- Wi-Fi discovery, session listing, download, delete, and device-info access
- XRK/XRZ session parsing and reconstruction
- Export-style XRK footer generation

This repository also ships small CLI wrappers built on top of that library:
`aim.py`, `xrk2csv.py`, and `xrz2xrk.py`.

Reverse-engineered from network captures of an AiM SOLO2DL. No vendor SDK required.

## Requirements

Python 3.10+, no third-party dependencies.

## Repository Layout

| Path | Purpose |
|---|---|
| `libaim/` | Shared library code |
| `aim.py` | Wi-Fi CLI for discover/list/download/delete/info |
| `xrk2csv.py` | Convert `.xrk` / `.xrz` to CSV |
| `xrz2xrk.py` | Add an export footer to `.xrz` / raw telemetry |
| `docs/wifi_protocol.md` | AiM Wi-Fi protocol notes |
| `docs/xrk_format.md` | XRK/XRZ format notes |
| `docs/libaim.md` | Library-oriented API notes and examples |

## Using `libaim`

There is no packaging metadata yet. Import it from a repository checkout by
running Python from the repo root or by adding the repo root to `PYTHONPATH`.

### Public API

| Module | Main entry points |
|---|---|
| `libaim` | Re-exports the most useful library symbols |
| `libaim.wifi` | `discover`, `AimSession`, `parse_session_list`, `Session` |
| `libaim.telemetry` | `read_session_bytes`, `read_raw_bytes`, `build_session`, `SessionData` |
| `libaim.export` | `build_export_footer` |

### Example: list sessions over Wi-Fi

```python
from libaim import AimSession, parse_session_list

with AimSession(host=None, timeout=15.0) as sess:
    csv_text = sess.fetch_list_csv()

sessions = parse_session_list(csv_text)
for item in sessions:
    print(item.name, item.size, item.date, item.hour)
```

`host=None` enables auto-discovery across the known AiM AP IPs.

### Example: download one session

```python
from pathlib import Path

from libaim import AimSession, parse_session_list

with AimSession(timeout=30.0) as sess:
    sessions = parse_session_list(sess.fetch_list_csv())
    target = sessions[0]
    result = sess.read_file_result(target.remote_path)

Path(target.name).write_bytes(result.data)
print(target.name, len(result.data), result.ready_size)
```

`result.ready_size` is the device-reported `READY size` from the download flow.

### Example: parse a session file

```python
from libaim import build_session, read_session_bytes

raw = read_session_bytes("session.xrz")
session = build_session(raw)

print(session.time_origin_ms)
print(len(session.channels), len(session.timeline), len(session.gps_frames))
```

`SessionData` includes decoded CHS metadata, channel samples, GPS frames, LAP
records, track info, parser warnings, and GPS timing-fix status.

### Example: build an XRK export footer

```python
from libaim import build_export_footer

footer = build_export_footer(
    racer="Driver",
    vehicle="SOLO2DL",
    vehicle_type="GT3",
    note="Qualifying",
)
```

This returns the export footer bytes that can be appended to a raw XRK body.

## CLI Tools

The CLI scripts are thin wrappers around `libaim`. Run each with `-h` for the
full option list.

### `aim.py`

Connect your PC to the logger's Wi-Fi AP, then run:

```bash
python aim.py discover
python aim.py list
python aim.py download a_7064.xrz
python aim.py download --all -o ./sessions
python aim.py delete a_7064.xrz
python aim.py info
```

Notes:

- The logger AP IP varies by device (`10.0.0.1`, `11.0.0.1`, `12.0.0.1`, `14.0.0.1`).
- Omitting `--host` enables UDP auto-discovery.
- `download` writes via a `.part` temp file and skips existing same-size files.
- `delete` verifies the post-delete list before reporting success.

### `xrk2csv.py`

Convert downloaded telemetry into a practical CSV subset:

```bash
python xrk2csv.py session.xrz
python xrk2csv.py session.xrz -o output.csv
python xrk2csv.py session.xrk
```

The CSV is anchored to session-relative time and includes GPS, IMU, drivetrain,
engine, chassis, fuel, electrical, and status channels.

### `xrz2xrk.py`

Append an export-style footer so the output can be consumed as `.xrk`:

```bash
python xrz2xrk.py session.xrz
python xrz2xrk.py session.xrz -o session.xrk
python xrz2xrk.py session.xrz --racer "Driver" --vehicle "Car" --vehicle-type "GT3"
```

Both `xrk2csv.py` and `xrz2xrk.py` accept truncated `.xrz` input as long as
zlib can still recover a structurally valid partial session.

## Full Workflow Example

```bash
python aim.py discover
python aim.py list
python aim.py download --all -o ./sessions
python xrk2csv.py ./sessions/a_7064.xrz
python xrz2xrk.py ./sessions/a_7064.xrz --racer "Driver" --vehicle "SOLO2DL"
```

## Documentation

- [`docs/libaim.md`](docs/libaim.md) — library-facing API notes and examples
- [`docs/wifi_protocol.md`](docs/wifi_protocol.md) — AiM Wi-Fi protocol notes
- [`docs/xrk_format.md`](docs/xrk_format.md) — XRK/XRZ binary format notes

## Known Limitations

- Tested against AiM SOLO2DL firmware only. Other AiM models likely work but are unverified.
- IMU channels are still decoded as raw counts. Full engineering scaling and calibration matrices are unresolved.
- Download resume from an arbitrary offset is not implemented.
