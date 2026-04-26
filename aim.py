#!/usr/bin/env python3
"""aim — CLI for AiM data logger over Wi-Fi.

Subcommands:
  discover                         UDP probe on :36002 to find loggers.
  list      [--host IP]            Show recorded sessions (from dev.ria / 0x24-02).
  download  NAME... [-o DIR]       Download one or more sessions by name.
  download  --all   [-o DIR]       Download every session in the list.
  delete    NAME...                Delete one or more sessions by name.
  delete    --all                  Delete every session in the list.
  info      [--host IP]            Dump device info block (cmd 0x10/01).

See docs/wifi_protocol.md for the protocol spec this implements.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
from typing import Optional

from libaim.telemetry import build_session, decode_session_bytes, looks_like_zlib
from libaim.wifi import (
    AimSession,
    DEFAULT_DISCOVERY_HOSTS,
    ProtocolError,
    Session,
    STATUS_EMPTY,
    discover,
    parse_session_list,
)


def _find_session_by_name(sessions: list[Session], name: str) -> Optional[Session]:
    for session in sessions:
        if session.name == name:
            return session
    return None


def _session_sort_key(session: Session) -> Optional[tuple[int, int, int, int, int, int, str]]:
    try:
        day_s, month_s, year_s = session.date.split("/")
        hour_parts = session.hour.split(":")
        if len(hour_parts) not in (2, 3):
            return None
        hour_s, minute_s = hour_parts[:2]
        second_s = hour_parts[2] if len(hour_parts) == 3 else "0"
        return (
            int(year_s),
            int(month_s),
            int(day_s),
            int(hour_s),
            int(minute_s),
            int(second_s),
            session.name,
        )
    except ValueError:
        return None


def _find_latest_session(sessions: list[Session]) -> Optional[Session]:
    latest: Optional[tuple[tuple[int, int, int, int, int, int, str], Session]] = None
    for session in sessions:
        key = _session_sort_key(session)
        if key is None:
            continue
        if latest is None or key > latest[0]:
            latest = (key, session)
    return None if latest is None else latest[1]


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _safe_output_name(name: str) -> str:
    """Reject logger-provided names that would escape the output directory."""
    if not name or name in (".", ".."):
        raise ValueError("invalid empty or dot-only session name")
    if "/" in name or "\\" in name or name != os.path.basename(name):
        raise ValueError(f"unsafe session name {name!r}")
    return name


def render_session_table(sessions: list[Session]) -> str:
    if not sessions:
        return "(no sessions on device)"
    cols = [
        ("#", lambda i, session: str(i)),
        ("name", lambda i, session: session.name),
        ("size", lambda i, session: _fmt_size(session.size)),
        ("date", lambda i, session: session.date),
        ("hour", lambda i, session: session.hour),
        ("laps", lambda i, session: session.nlap),
        ("best(ms)", lambda i, session: session.best),
        ("track", lambda i, session: session.track_name),
    ]
    rows = [[name for name, _ in cols]]
    for idx, session in enumerate(sessions, 1):
        rows.append([fn(idx, session) for _, fn in cols])
    widths = [max(len(row[col]) for row in rows) for col in range(len(cols))]
    lines = []
    for idx, row in enumerate(rows):
        lines.append("  ".join(cell.ljust(width) for cell, width in zip(row, widths)))
        if idx == 0:
            lines.append("  ".join("-" * width for width in widths))
    return "\n".join(lines)


def _confirm(question: str, *, default: bool = False) -> bool:
    # Prompts are only safe in an interactive terminal; in batch mode, fall
    # back to the caller-provided default instead of blocking on stdin.
    if not sys.stdin.isatty():
        print(f"warn  {question} (stdin is not a TTY; treating as 'no')", file=sys.stderr)
        return default
    suffix = " [Y/n] " if default else " [y/N] "
    while True:
        sys.stderr.write(question + suffix)
        sys.stderr.flush()
        answer = sys.stdin.readline()
        if answer == "":
            return default
        answer = answer.strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("please answer yes or no", file=sys.stderr)


def _validate_downloaded_session(name: str, data: bytes) -> None:
    # Reuse the telemetry parser as a structural integrity check rather than
    # inventing a second "is this log valid?" implementation in aim.py.
    raw = data
    if name.lower().endswith(".xrz") or looks_like_zlib(data):
        raw = decode_session_bytes(data, source=f"downloaded {name}", compressed=True)
    build_session(raw)


class _ProgressBar:
    def __init__(self, label: str, total: int, enabled: bool = True):
        self.label = label
        self.total = total
        self.enabled = enabled and sys.stderr.isatty()
        self._last = 0.0
        self._start = time.monotonic()

    def __call__(self, got: int, total: int) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if got < total and now - self._last < 0.1:
            return
        self._last = now
        pct = got / total * 100 if total else 100.0
        elapsed = now - self._start
        rate = got / elapsed if elapsed > 0 else 0
        bar_w = 30
        filled = int(bar_w * (got / total)) if total else bar_w
        bar = "#" * filled + "-" * (bar_w - filled)
        sys.stderr.write(
            f"\r{self.label} [{bar}] {pct:5.1f}%  "
            f"{_fmt_size(got)}/{_fmt_size(total)}  "
            f"{_fmt_size(int(rate))}/s"
        )
        sys.stderr.flush()
        if got >= total:
            sys.stderr.write("\n")
            sys.stderr.flush()


def cmd_discover(args: argparse.Namespace) -> int:
    hosts = [args.host] if args.host else None
    devices = discover(timeout=args.timeout, hosts=hosts, verbose=args.verbose)
    if not devices:
        print(
            "no AiM device found (probed aim-ka to "
            f"{hosts or list(DEFAULT_DISCOVERY_HOSTS)} for {args.timeout}s)",
            file=sys.stderr,
        )
        return 1
    for device in devices:
        print(device.short())
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    with AimSession(host=args.host, timeout=args.timeout, verbose=args.verbose) as session:
        csv_text = session.fetch_list_csv()
    sessions = parse_session_list(csv_text)

    if args.raw_csv:
        sys.stdout.write(csv_text)
        if not csv_text.endswith("\n"):
            sys.stdout.write("\n")
        return 0

    if args.json:
        import json

        json.dump([item.raw for item in sessions], sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0

    print(render_session_table(sessions))
    return 0


def _resolve_targets(sessions: list[Session], names: list[str], all_flag: bool) -> list[Session]:
    if all_flag:
        return sessions
    if not names:
        return []
    by_name = {session.name: session for session in sessions}
    resolved: list[Session] = []
    for name in names:
        if name in by_name:
            resolved.append(by_name[name])
            continue
        for ext in (".xrz", ".hrz"):
            if name + ext in by_name:
                resolved.append(by_name[name + ext])
                break
        else:
            if name.isdigit():
                idx = int(name)
                if 1 <= idx <= len(sessions):
                    resolved.append(sessions[idx - 1])
                    continue
            print(f"error: no session matches {name!r}", file=sys.stderr)
            sys.exit(2)
    return resolved


def cmd_download(args: argparse.Namespace) -> int:
    out_dir = args.out or "."
    os.makedirs(out_dir, exist_ok=True)

    with AimSession(host=args.host, timeout=args.timeout, verbose=args.verbose) as session:
        csv_text = session.fetch_list_csv()
        sessions = parse_session_list(csv_text)

        if not sessions:
            print("no sessions on device", file=sys.stderr)
            return 1

        targets = _resolve_targets(sessions, args.names, args.all)
        if not targets:
            print("error: specify session name(s) or --all", file=sys.stderr)
            return 2

        active_target = _find_latest_session(sessions)
        total_ok = 0
        for target in targets:
            try:
                local_name = _safe_output_name(target.name)
            except ValueError as exc:
                print(f"fail  {target.name}: {exc}", file=sys.stderr)
                continue
            previous_size = target.size
            if active_target is not None and target.name == active_target.name:
                try:
                    fresh = _find_session_by_name(
                        parse_session_list(session.fetch_list_csv()),
                        target.name,
                    )
                except (ProtocolError, ConnectionError, socket.timeout, OSError, ValueError) as exc:
                    print(
                        f"fail  {target.name}: could not refresh list before download: {exc}",
                        file=sys.stderr,
                    )
                    try:
                        session.reset()
                    except (ProtocolError, ConnectionError, socket.timeout, OSError, ValueError) as reset_exc:
                        print(
                            f"error: could not recover TCP session after failure: {reset_exc}",
                            file=sys.stderr,
                        )
                        return 1
                    continue
                if fresh is None:
                    print(
                        f"fail  {target.name}: session no longer present in refreshed list",
                        file=sys.stderr,
                    )
                    continue
                target = fresh
            expected_size = target.size
            size_changed = expected_size != previous_size
            dst = os.path.join(out_dir, local_name)
            if os.path.exists(dst) and not args.force:
                st = os.stat(dst)
                if st.st_size == expected_size:
                    print(f"skip  {target.name}  (already exists, size matches)")
                    total_ok += 1
                    continue
                print(
                    f"warn  {target.name}  exists with different size "
                    f"({st.st_size} vs {expected_size}); use --force to overwrite",
                    file=sys.stderr,
                )
                continue
            if size_changed:
                print(
                    f"warn  {target.name}: list size changed {previous_size} -> {expected_size}; "
                    "session appears to still be recording",
                    file=sys.stderr,
                )
                if not _confirm(f"download {target.name} anyway?"):
                    print(
                        f"skip  {target.name}  (user declined download while session is changing)",
                        file=sys.stderr,
                    )
                    continue

            progress = _ProgressBar(f"  {target.name}", expected_size, enabled=not args.quiet)
            try:
                read = session.read_file_result(target.remote_path, progress=progress)
                data = read.data
            except (ProtocolError, ConnectionError, socket.timeout, OSError, ValueError) as exc:
                print(f"fail  {target.name}: {exc}", file=sys.stderr)
                try:
                    session.reset()
                except (ProtocolError, ConnectionError, socket.timeout, OSError, ValueError) as reset_exc:
                    print(
                        f"error: could not recover TCP session after failure: {reset_exc}",
                        file=sys.stderr,
                    )
                    return 1
                continue
            if len(data) != expected_size:
                try:
                    # If parsing still succeeds, the most likely explanation is
                    # that the logger appended/finalized the file mid-download.
                    _validate_downloaded_session(target.name, data)
                except (OSError, ValueError, struct.error) as parse_exc:
                    print(
                        f"fail  {target.name}: size mismatch "
                        f"(got {len(data)}, list {expected_size}, ready {read.ready_size}); "
                        f"parse failed: {parse_exc}",
                        file=sys.stderr,
                    )
                    continue
                print(
                    f"warn  {target.name}: size mismatch "
                    f"(got {len(data)}, list {expected_size}, ready {read.ready_size}); "
                    "logger file changed during download",
                    file=sys.stderr,
                )
                if not _confirm(f"save {target.name} anyway?"):
                    print(
                        f"skip  {target.name}  (user declined saving log captured while session changed)",
                        file=sys.stderr,
                    )
                    continue
            if args.verbose:
                print(
                    f"  [aim] download result {target.name}: "
                    f"got={len(data)} list={expected_size} ready={read.ready_size}",
                    file=sys.stderr,
                )
            tmp = dst + ".part"
            with open(tmp, "wb") as handle:
                handle.write(data)
            os.replace(tmp, dst)
            print(f"ok    {target.name}  →  {dst}  ({_fmt_size(len(data))})")
            total_ok += 1

        return 0 if total_ok == len(targets) else 1


def cmd_delete(args: argparse.Namespace) -> int:
    with AimSession(host=args.host, timeout=args.timeout, verbose=args.verbose) as session:
        csv_text = session.fetch_list_csv()
        sessions = parse_session_list(csv_text)
        host = session.host

    if not sessions:
        print("no sessions on device", file=sys.stderr)
        return 1

    targets = _resolve_targets(sessions, args.names, args.all)
    if not targets:
        print("error: specify session name(s) or --all", file=sys.stderr)
        return 2

    if not args.yes:
        if len(targets) == 1:
            prompt = f"delete {targets[0].name} from device?"
        else:
            prompt = f"delete {len(targets)} sessions from device?"
        if not _confirm(prompt):
            print("cancelled", file=sys.stderr)
            return 0

    deleted_names: list[str] = []
    total_ok = 0
    with AimSession(host=host, timeout=args.timeout, verbose=args.verbose, bootstrap=False) as session:
        for target in targets:
            try:
                status = session.delete_file(target.remote_path)
            except (ProtocolError, ConnectionError, socket.timeout, OSError, ValueError) as exc:
                print(f"fail  {target.name}: {exc}", file=sys.stderr)
                try:
                    session.reset()
                except (ProtocolError, ConnectionError, socket.timeout, OSError, ValueError) as reset_exc:
                    print(
                        f"error: could not recover TCP session after failure: {reset_exc}",
                        file=sys.stderr,
                    )
                    return 1
                continue
            if status == STATUS_EMPTY:
                print(f"fail  {target.name}: device reported file missing", file=sys.stderr)
                continue
            if args.verbose:
                print(f"  [aim] delete result {target.name}: status={status:#010x}", file=sys.stderr)
            print(f"ok    {target.name}  deleted")
            deleted_names.append(target.name)
            total_ok += 1

        if deleted_names:
            try:
                remaining = parse_session_list(session.fetch_plain_list_csv())
            except (ProtocolError, ConnectionError, socket.timeout, OSError, ValueError) as exc:
                print(f"error: could not verify deleted sessions: {exc}", file=sys.stderr)
                return 1
            remaining_names = {item.name for item in remaining}
            for name in deleted_names:
                if name in remaining_names:
                    print(f"fail  {name}: still present after delete verification", file=sys.stderr)
                    total_ok -= 1

    return 0 if total_ok == len(targets) else 1


def cmd_info(args: argparse.Namespace) -> int:
    with AimSession(host=args.host, timeout=args.timeout, verbose=args.verbose) as session:
        blob = session.fetch_device_info()
    if not blob:
        print("no device info returned", file=sys.stderr)
        return 1

    i = 0
    n = len(blob)
    printed = 0
    while i + 12 <= n:
        if blob[i:i + 2] != b"<h":
            i += 1
            continue
        tag = blob[i + 2:i + 6]
        plen = int.from_bytes(blob[i + 6:i + 10], "little")
        term = blob[i + 10:i + 12]
        if term not in (b"a>", b"\x00>"):
            i += 1
            continue
        body_start = i + 12
        body_end = body_start + plen
        if body_end + 8 > n:
            break
        body = blob[body_start:body_end]
        tag_txt = tag.decode("ascii", errors="replace")
        print(f"--- {tag_txt}  ({plen}B) ---")
        printable = sum(1 for byte in body if 32 <= byte < 127 or byte in (9, 10, 13))
        if plen > 0 and printable / plen > 0.8:
            sys.stdout.write(body.decode("ascii", errors="replace"))
            if not body.endswith(b"\n"):
                sys.stdout.write("\n")
        else:
            preview = body[:128]
            print(preview.hex(" "))
            if len(body) > 128:
                print(f"... ({len(body) - 128} more bytes)")
        printed += 1
        i = body_end + 8
    if printed == 0:
        print(f"(could not parse inner blocks; raw {len(blob)}B)")
        print(blob[:256].hex(" "))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aim",
        description="List, download, and delete driving records from an AiM data logger over Wi-Fi.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    discover_parser = sub.add_parser("discover", help="UDP probe for AiM loggers on the network.")
    discover_parser.add_argument(
        "--host",
        default=None,
        help="Probe a single host/broadcast (default: 10/11/12/14.0.0.1 + 255.255.255.255)",
    )
    discover_parser.add_argument("--timeout", type=float, default=2.0, help="Seconds to listen.")
    discover_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print every received UDP datagram.",
    )
    discover_parser.set_defaults(func=cmd_discover)

    list_parser = sub.add_parser("list", help="List recorded sessions.")
    list_parser.add_argument(
        "--host",
        default=None,
        help="Logger IP. If omitted, auto-discover among known AP IPs.",
    )
    list_parser.add_argument("--timeout", type=float, default=15.0)
    list_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Trace every TCP frame (tx/rx) with decoded cmd/status.",
    )
    list_format = list_parser.add_mutually_exclusive_group()
    list_format.add_argument(
        "--raw-csv",
        action="store_true",
        help="Print the raw CSV exactly as the device returned it.",
    )
    list_format.add_argument(
        "--json",
        action="store_true",
        help="Print JSON array of row dicts.",
    )
    list_parser.set_defaults(func=cmd_list)

    download_parser = sub.add_parser("download", help="Download session file(s).")
    download_parser.add_argument(
        "--host",
        default=None,
        help="Logger IP. If omitted, auto-discover among known AP IPs.",
    )
    download_parser.add_argument("--timeout", type=float, default=30.0)
    download_parser.add_argument("-o", "--out", default=".", help="Output directory.")
    download_parser.add_argument("--all", action="store_true", help="Download every session.")
    download_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing files even if size matches.",
    )
    download_parser.add_argument("--quiet", action="store_true", help="Suppress progress bar.")
    download_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Trace every TCP frame (tx/rx) with decoded cmd/status.",
    )
    download_parser.add_argument(
        "names",
        nargs="*",
        help="Session names (a_7064.xrz), short names (a_7064), or 1-based indices.",
    )
    download_parser.set_defaults(func=cmd_download)

    delete_parser = sub.add_parser("delete", help="Delete session file(s) from the device.")
    delete_parser.add_argument(
        "--host",
        default=None,
        help="Logger IP. If omitted, auto-discover among known AP IPs.",
    )
    delete_parser.add_argument("--timeout", type=float, default=30.0)
    delete_parser.add_argument("--all", action="store_true", help="Delete every session.")
    delete_parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Delete without confirmation.",
    )
    delete_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Trace every TCP frame (tx/rx) with decoded cmd/status.",
    )
    delete_parser.add_argument(
        "names",
        nargs="*",
        help="Session names (a_7064.xrz), short names (a_7064), or 1-based indices.",
    )
    delete_parser.set_defaults(func=cmd_delete)

    info_parser = sub.add_parser("info", help="Dump device info block.")
    info_parser.add_argument(
        "--host",
        default=None,
        help="Logger IP. If omitted, auto-discover among known AP IPs.",
    )
    info_parser.add_argument("--timeout", type=float, default=15.0)
    info_parser.add_argument("-v", "--verbose", action="store_true", help="Trace every TCP frame.")
    info_parser.set_defaults(func=cmd_info)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except ProtocolError as exc:
        print(f"protocol error: {exc}", file=sys.stderr)
        return 1
    except (ConnectionError, socket.timeout, OSError) as exc:
        print(f"network error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
