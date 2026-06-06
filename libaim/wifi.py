from __future__ import annotations

import csv
import io
import re
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional


# IMPORTANT: AiM AP IP is configurable on-device; do not hardcode 10.0.0.1.
KNOWN_AP_HOSTS = ("10.0.0.1", "11.0.0.1", "12.0.0.1", "14.0.0.1")
DISCOVERY_BROADCAST = "255.255.255.255"
DEFAULT_DISCOVERY_HOSTS = KNOWN_AP_HOSTS + (DISCOVERY_BROADCAST,)
AUTO_DISCOVERY_TIMEOUT = 2.0
TCP_PORT = 2000
UDP_PORT = 36002
DISCOVERY_PROBE = b"aim-ka"

HDR_SIZE = 64
CMD_OFFSET = 8
SIZE_OFFSET = 16
STATUS_OFFSET = 24
ARG_OFFSET = 32

STATUS_REQUEST = 0x00000001
STATUS_RECEIVED = 0x00000A01
STATUS_PENDING = 0x00000A09
STATUS_READY = 0x00000A11
STATUS_EMPTY = 0x00000A1D

CHUNK_DATA_MAX = 32704
OPEN_RETRIES = 3
OPEN_RETRY_DELAY = 1.0
CLOSE_DRAIN_TIMEOUT = 1.0
CLOSE_COOLDOWN = 0.3
# Match the vendor app's steady "aim-ka" rhythm during active TCP sessions.
KEEPALIVE_INTERVAL = 0.8
KEEPALIVE_PRIME_DELAY = 0.1
# IMPORTANT: some loggers return only a broken 20B pseudo-frame if hello is
# sent immediately after TCP connect. A short post-connect settle delay makes
# the bootstrap reliable and matches the vendor capture timing.
CONNECT_SETTLE_DELAY = 0.4
HELLO_REPLY_CODES = (b"\x06\x09", b"\x06\x19")

CMD_DEVINFO = (0x10, 0x01)
CMD_SYNC_PING = (0x06, 0x01)
CMD_FILE_DELETE = (0x06, 0x04)
CMD_FILE_READ = (0x02, 0x04)
CMD_LIST = (0x24, 0x02)
CMD_LIST_PREP = (0x51, 0x02)
DEVINFO_REQ_SIZE = HDR_SIZE

RECORDED_DIR = "1:/mem"
LIST_CACHE_PATH = "0:/tkk/dev.ria"
SESSION_LIST_COLUMNS = [
    "name",
    "size",
    "date",
    "hour",
    "nlap",
    "nbest",
    "best",
    "pilota",
    "track_name",
    "veicolo",
    "campionato",
    "venue_type",
    "mode",
    "trk_type",
    "motivolap",
    "maxvel",
    "device",
    "track_lat",
    "track_lon",
    "test_dur",
    "pname",
    "ptype",
    "ptime",
    "pdist",
    "pmaxv",
]
SESSION_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
TraceCallback = Callable[[str], None]


class ProtocolError(Exception):
    """Application-level framing/protocol error."""


def _abortive_close(sock: socket.socket) -> None:
    """Close with TCP RST to clear stuck logger-side sessions promptly."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def wrap_frame(tag: bytes, payload: bytes) -> bytes:
    if len(tag) != 4:
        raise ValueError("tag must be 4 bytes")
    hdr = b"<h" + tag + len(payload).to_bytes(4, "little") + b"\x00>"
    chk = (sum(payload) & 0xFFFF).to_bytes(2, "little")
    return hdr + payload + b"<" + tag + chk + b">"


class FrameReader:
    """Reads STCP/STNC frames from a TCP stream, handling segment/frame mismatch."""

    def __init__(self, sock: socket.socket, on_recv=None, trace: Optional[TraceCallback] = None):
        self.sock = sock
        self.buf = bytearray()
        # optional callback(chunk: bytes) invoked for every raw recv()
        self.on_recv = on_recv
        self.trace = trace

    def _trace(self, msg: str) -> None:
        if self.trace is not None:
            self.trace(msg)

    def _recv_more(self, n: int = 65536) -> None:
        chunk = self.sock.recv(n)
        if not chunk:
            raise ConnectionError("connection closed by peer")
        if self.on_recv is not None:
            self.on_recv(chunk)
        self.buf.extend(chunk)

    def _need(self, size: int) -> None:
        while len(self.buf) < size:
            try:
                self._recv_more()
            except socket.timeout:
                if self.buf:
                    msg = (
                        f"timed out with {len(self.buf)}B partial data "
                        f"in buffer: {bytes(self.buf).hex()}"
                    )
                    self._trace(msg)
                    if self.trace is None:
                        sys.stderr.write(f"  [aim] {msg}\n")
                raise

    def _seek_frame_start(self) -> None:
        """Discard leading garbage until buffer starts with '<h'."""
        while True:
            idx = self.buf.find(b"<h")
            if idx == 0:
                return
            if idx > 0:
                self._trace(
                    f"discarding {idx}B before frame start: {bytes(self.buf[:idx]).hex()}"
                )
                del self.buf[:idx]
                return
            if self.buf[-1:] == b"<":
                if len(self.buf) > 1:
                    self._trace(
                        f"discarding {len(self.buf) - 1}B garbage before trailing '<': "
                        f"{bytes(self.buf[:-1]).hex()}"
                    )
                del self.buf[:-1]
            else:
                self._trace(f"discarding {len(self.buf)}B garbage: {bytes(self.buf).hex()}")
                del self.buf[:]
            self._recv_more()

    def read(self) -> tuple[bytes, bytes]:
        while True:
            self._need(12)
            self._seek_frame_start()
            self._need(12)
            tag = bytes(self.buf[2:6])
            plen = int.from_bytes(self.buf[6:10], "little")
            if self.buf[10:12] != b"\x00>":
                self._trace(
                    f"bad frame header terminator tag={tag!r} plen={plen} "
                    f"term={bytes(self.buf[10:12]).hex()}; shifting by 1B"
                )
                del self.buf[:1]
                continue

            total = 12 + plen + 8
            self._need(total)

            payload = bytes(self.buf[12:12 + plen])
            off = 12 + plen
            if self.buf[off:off + 1] != b"<" or self.buf[off + 1:off + 5] != tag:
                self._trace(
                    f"bad frame trailer tag={tag!r} plen={plen} "
                    f"trailer={bytes(self.buf[off:off + 8]).hex()}; shifting by 1B"
                )
                del self.buf[:1]
                continue
            chk = int.from_bytes(self.buf[off + 5:off + 7], "little")
            if self.buf[off + 7:off + 8] != b">":
                self._trace(
                    f"bad frame checksum terminator tag={tag!r} plen={plen} "
                    f"term={bytes(self.buf[off + 7:off + 8]).hex()}; shifting by 1B"
                )
                del self.buf[:1]
                continue
            expected = sum(payload) & 0xFFFF
            if chk != expected:
                self._trace(
                    f"checksum mismatch tag={tag!r} plen={plen}: "
                    f"got {chk:#06x}, want {expected:#06x}"
                )
                raise ProtocolError(f"checksum mismatch: got {chk:#06x}, want {expected:#06x}")

            del self.buf[:total]
            return tag, payload


def make_cmd(
    cmd: int,
    sub: int,
    *,
    path: str = "",
    arg_tail: bytes = b"",
    status: int = STATUS_REQUEST,
    size: int = 0,
) -> bytes:
    hdr = bytearray(HDR_SIZE)
    struct.pack_into("<HH", hdr, CMD_OFFSET, cmd, sub)
    struct.pack_into("<I", hdr, SIZE_OFFSET, size)
    struct.pack_into("<I", hdr, STATUS_OFFSET, status)
    if path:
        encoded = path.encode("ascii") + b"\x00"
        if len(encoded) > 32:
            raise ValueError(f"path too long: {path!r}")
        hdr[ARG_OFFSET:ARG_OFFSET + len(encoded)] = encoded
    elif arg_tail:
        if len(arg_tail) > 32:
            raise ValueError("arg_tail too long")
        hdr[ARG_OFFSET:ARG_OFFSET + len(arg_tail)] = arg_tail
    return bytes(hdr)


def parse_status(payload: bytes) -> tuple[int, int, int, int]:
    """Returns (cmd, sub, size, status) from a 64B command header response."""
    cmd, sub = struct.unpack_from("<HH", payload, CMD_OFFSET)
    size = struct.unpack_from("<I", payload, SIZE_OFFSET)[0]
    status = struct.unpack_from("<I", payload, STATUS_OFFSET)[0]
    return cmd, sub, size, status


def _make_timesync_payload(now: Optional[time.struct_time] = None) -> bytes:
    """68B STCP payload per spec §9: UTC block then local block."""
    epoch = time.time() if now is None else time.mktime(now)
    utc = time.gmtime(epoch)
    loc = time.localtime(epoch)
    pl = bytearray(68)

    def put(off: int, val: int) -> None:
        struct.pack_into("<I", pl, off, val)

    put(12, utc.tm_year)
    put(16, utc.tm_mon)
    put(20, utc.tm_mday)
    put(24, utc.tm_hour)
    put(28, utc.tm_min)
    put(44, loc.tm_year)
    put(48, loc.tm_mon)
    put(52, loc.tm_mday)
    put(56, loc.tm_hour)
    put(60, loc.tm_min)
    return bytes(pl)


class _UdpKeepalive:
    """Periodic UDP `aim-ka` sender for the lifetime of a TCP session."""

    def __init__(self, host: str, trace: TraceCallback) -> None:
        self.host = host
        self._trace = trace
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", UDP_PORT))
        except OSError as e:
            self._trace(f"udp keepalive bind :{UDP_PORT} failed ({e}); using ephemeral port")
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="aim-keepalive", daemon=True)
        self._thread.start()
        self._trace(f"udp keepalive started -> {self.host}:{UDP_PORT}")

    def stop(self) -> None:
        thread = self._thread
        sock = self._sock
        self._thread = None
        self._sock = None
        if thread is None:
            return
        self._stop.set()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        thread.join(timeout=1.0)
        self._stop.clear()
        self._trace("udp keepalive stopped")

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                self._sock.sendto(DISCOVERY_PROBE, (self.host, UDP_PORT))
                self._trace(f"udp keepalive tx aim-ka -> {self.host}:{UDP_PORT}")
            except OSError as e:
                if not self._stop.is_set():
                    self._trace(f"udp keepalive send failed: {e}")
            if self._stop.wait(KEEPALIVE_INTERVAL):
                break


@dataclass
class DiscoveredDevice:
    addr: str
    reply_len: int
    declared_len: Optional[int]
    version: Optional[int]
    raw: bytes

    def short(self) -> str:
        parts = [self.addr]
        extras = []
        if self.reply_len:
            extras.append(f"{self.reply_len}B reply")
        if self.version is not None:
            extras.append(f"version={self.version}")
        if extras:
            return f"{self.addr}  ({', '.join(extras)})"
        return parts[0]


@dataclass
class FileReadResult:
    data: bytes
    ready_size: int


def parse_discovery(data: bytes, addr: str) -> DiscoveredDevice:
    """Best-effort parse. Never rejects — firmware byte layouts vary by model."""
    declared = None
    version = None
    if len(data) >= 4:
        d = int.from_bytes(data[0:4], "little")
        if d == len(data):
            declared = d
    if len(data) >= 8:
        version = int.from_bytes(data[4:8], "little")
    return DiscoveredDevice(
        addr=addr,
        reply_len=len(data),
        declared_len=declared,
        version=version,
        raw=data,
    )


def _emit_trace(verbose: bool, trace: Optional[TraceCallback], msg: str) -> None:
    if trace is not None:
        trace(msg)
    if verbose:
        sys.stderr.write(f"  [aim] {msg}\n")
        sys.stderr.flush()


def discover(
    timeout: float = 2.0,
    hosts: Optional[Iterable[str]] = None,
    verbose: bool = False,
    trace: Optional[TraceCallback] = None,
) -> list[DiscoveredDevice]:
    """Broadcast + unicast `aim-ka` probe, collect replies from UDP :36002."""
    hosts = list(dict.fromkeys(hosts if hosts else DEFAULT_DISCOVERY_HOSTS))
    _emit_trace(verbose, trace, f"udp discover start hosts={hosts!r} timeout={timeout}s")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", UDP_PORT))
        _emit_trace(verbose, trace, f"udp discover bound 0.0.0.0:{UDP_PORT}")
    except OSError as e:
        _emit_trace(
            verbose,
            trace,
            f"warning: udp discover bind :{UDP_PORT} failed ({e}); using ephemeral port",
        )
    sock.settimeout(0.4)

    found: dict[str, DiscoveredDevice] = {}
    deadline = time.monotonic() + timeout
    next_probe = 0.0
    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_probe:
                for host in hosts:
                    try:
                        sock.sendto(DISCOVERY_PROBE, (host, UDP_PORT))
                        _emit_trace(verbose, trace, f"udp discover tx aim-ka -> {host}:{UDP_PORT}")
                    except OSError as e:
                        _emit_trace(verbose, trace, f"udp discover send to {host}:{UDP_PORT} failed: {e}")
                next_probe = now + 0.8
            try:
                data, (addr, src_port) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            _emit_trace(
                verbose,
                trace,
                f"udp discover rx {len(data)}B from {addr}:{src_port}: "
                f"{data[:32].hex()}{'...' if len(data) > 32 else ''}",
            )
            if src_port != UDP_PORT or data == DISCOVERY_PROBE:
                _emit_trace(
                    verbose,
                    trace,
                    f"udp discover ignored reply from {addr}:{src_port} "
                    f"(src_port={src_port}, echo={data == DISCOVERY_PROBE})",
                )
                continue
            found[addr] = parse_discovery(data, addr)
    finally:
        sock.close()
        _emit_trace(verbose, trace, f"udp discover closed; found={sorted(found)}")
    return list(found.values())


def auto_discover_host(
    timeout: float = AUTO_DISCOVERY_TIMEOUT,
    verbose: bool = False,
    trace: Optional[TraceCallback] = None,
) -> str:
    """Resolve the active logger IP without assuming 10.0.0.1 is fixed."""
    devices = discover(
        timeout=timeout,
        hosts=DEFAULT_DISCOVERY_HOSTS,
        verbose=verbose,
        trace=trace,
    )
    addrs = sorted({d.addr for d in devices})
    if not addrs:
        known = ", ".join(KNOWN_AP_HOSTS)
        raise ConnectionError(
            "no AiM device found via auto-discovery "
            f"(known AP IPs: {known}); pass --host explicitly or run `discover`"
        )
    if len(addrs) > 1:
        raise ConnectionError(
            "multiple AiM devices found via auto-discovery: "
            + ", ".join(addrs)
            + "; pass --host explicitly"
        )
    return addrs[0]


_STATUS_NAMES = {
    STATUS_REQUEST: "req",
    STATUS_RECEIVED: "recv",
    STATUS_PENDING: "pending",
    STATUS_READY: "ready",
    STATUS_EMPTY: "empty",
}


def _summarize_frame(tag: bytes, payload: bytes) -> str:
    n = len(payload)
    tag_txt = tag.decode("ascii", errors="replace")
    if (
        tag == b"STCP"
        and n == 68
        and payload[:12] == b"\x00" * 12
        and payload[36:44] == b"\x00" * 8
    ):
        return "STCP 68B  time-sync"
    if n >= HDR_SIZE and tag in (b"STCP", b"STNC") and payload[:8] == b"\x00" * 8:
        cmd, sub, size, status = parse_status(payload)
        st = _STATUS_NAMES.get(status, f"{status:#010x}")
        summary = f"{tag_txt} {n}B  cmd=0x{cmd:02x}/0x{sub:02x} size={size} status={st}"
        arg = payload[ARG_OFFSET:].rstrip(b"\x00")
        if arg:
            try:
                summary += f" arg={arg.decode('ascii')!r}"
            except UnicodeDecodeError:
                summary += f" arg=hex:{payload[ARG_OFFSET:ARG_OFFSET+8].hex()}"
        return summary
    if n == 4:
        return f"{tag_txt} 4B  offset/ack={int.from_bytes(payload, 'little')}"
    if n == 8:
        return f"{tag_txt} 8B  hex={payload.hex()}"
    preview = payload[:16].hex()
    more = "..." if n > 16 else ""
    if n >= 4 and tag == b"STCP":
        return f"{tag_txt} {n}B  data_offset={int.from_bytes(payload[:4], 'little')} body[{min(12, n-4)}]={payload[4:16].hex()}{more}"
    return f"{tag_txt} {n}B  hex={preview}{more}"


def _preview_text(text: str, limit: int = 512) -> str:
    preview = text[:limit]
    if len(text) > limit:
        preview += "..."
    return preview.encode("unicode_escape", errors="backslashreplace").decode("ascii")


class AimSession:
    """One TCP connection to the logger. Designed for short-lived per-task use."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: int = TCP_PORT,
        timeout: float = 15.0,
        verbose: bool = False,
        bootstrap: bool = True,
        trace: Optional[TraceCallback] = None,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.bootstrap = bootstrap
        self.trace = trace
        self.sock: Optional[socket.socket] = None
        self.reader: Optional[FrameReader] = None
        self.device_info: bytes = b""
        self.keepalive: Optional[_UdpKeepalive] = None

    def __enter__(self) -> "AimSession":
        self.open()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def open(self) -> None:
        last_exc: Optional[BaseException] = None
        if self.host is None:
            self.host = auto_discover_host(
                timeout=min(self.timeout, AUTO_DISCOVERY_TIMEOUT),
                verbose=self.verbose,
                trace=self.trace,
            )
            self._trace(f"auto-discovered host {self.host}")
        plans = ("none",) if not self.bootstrap else ("direct", "ping_then_init", "vendor_full")
        for attempt in range(1, OPEN_RETRIES + 1):
            try:
                plan = plans[min(attempt - 1, len(plans) - 1)]
                self._trace(
                    f"connect tcp {self.host}:{self.port} "
                    f"(timeout {self.timeout}s, attempt {attempt}/{OPEN_RETRIES}, "
                    f"bootstrap={plan})"
                )
                self._start_keepalive()
                if KEEPALIVE_PRIME_DELAY > 0:
                    time.sleep(KEEPALIVE_PRIME_DELAY)
                self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                self.sock.settimeout(self.timeout)
                self._trace(
                    f"tcp connected local={self.sock.getsockname()} "
                    f"peer={self.sock.getpeername()}"
                )
                try:
                    self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self._trace("tcp nodelay enabled")
                except OSError:
                    pass
                if CONNECT_SETTLE_DELAY > 0:
                    self._trace(f"post-connect settle {CONNECT_SETTLE_DELAY:.1f}s")
                    time.sleep(CONNECT_SETTLE_DELAY)
                on_recv = None
                if self.verbose or self.trace is not None:
                    def on_recv(chunk: bytes) -> None:
                        self._trace(
                            f"raw recv {len(chunk)}B: {chunk[:64].hex()}"
                            f"{'...' if len(chunk) > 64 else ''}"
                        )
                self.reader = FrameReader(self.sock, on_recv=on_recv, trace=self._trace)
                self._hello()
                if self.bootstrap:
                    self._bootstrap(plan)
                return
            except (ProtocolError, ConnectionError, socket.timeout, OSError) as e:
                last_exc = e
                self._trace(f"bootstrap failed: {type(e).__name__}: {e}")
                self.close(abort=True)
                if attempt >= OPEN_RETRIES:
                    raise
                time.sleep(OPEN_RETRY_DELAY)
        if last_exc is not None:
            raise last_exc

    def close(self, *, abort: bool = False) -> None:
        keepalive = self.keepalive
        self.keepalive = None
        if self.sock is not None:
            sock = self.sock
            self.sock = None
            self.reader = None
            peer_closed = False
            if not abort:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    abort = True
                else:
                    prev_timeout = sock.gettimeout()
                    try:
                        sock.settimeout(CLOSE_DRAIN_TIMEOUT)
                        while True:
                            chunk = sock.recv(65536)
                            if not chunk:
                                peer_closed = True
                                break
                            if self.verbose or self.trace is not None:
                                self._trace(
                                    f"close drain {len(chunk)}B: {chunk[:64].hex()}"
                                    f"{'...' if len(chunk) > 64 else ''}"
                                )
                    except (socket.timeout, OSError):
                        pass
                    finally:
                        try:
                            sock.settimeout(prev_timeout)
                        except OSError:
                            pass
                    if not peer_closed:
                        abort = True
            if abort:
                _abortive_close(sock)
                self._trace("tcp closed (rst)")
            else:
                try:
                    sock.close()
                except OSError:
                    pass
                self._trace("tcp closed")
            if keepalive is not None:
                keepalive.stop()
                keepalive = None
            if CLOSE_COOLDOWN > 0:
                time.sleep(CLOSE_COOLDOWN)
        if keepalive is not None:
            keepalive.stop()

    def reset(self, delay: float = 0.2) -> None:
        """Close and reopen the TCP session to recover from a bad protocol state."""
        self._trace("reset tcp session")
        self.close(abort=True)
        if delay > 0:
            time.sleep(delay)
        self.open()

    def _trace(self, msg: str) -> None:
        if self.trace is not None:
            self.trace(msg)
        if self.verbose:
            sys.stderr.write(f"  [aim] {msg}\n")
            sys.stderr.flush()

    def _start_keepalive(self) -> None:
        if self.keepalive is None:
            self.keepalive = _UdpKeepalive(self.host, self._trace)
            self.keepalive.start()

    def _send(self, tag: bytes, payload: bytes) -> None:
        assert self.sock is not None
        self._trace(f"tx {_summarize_frame(tag, payload)}")
        self.sock.sendall(wrap_frame(tag, payload))

    def _recv_frame(self) -> tuple[bytes, bytes]:
        assert self.reader is not None
        tag, pl = self.reader.read()
        self._trace(f"rx {_summarize_frame(tag, pl)}")
        return tag, pl

    def _hello(self) -> None:
        self._send(b"STCP", bytes.fromhex("0000000006080000"))
        try:
            tag, pl = self._recv_frame()
        except socket.timeout:
            raise ConnectionError(
                "no hello reply from logger — the device is likely in a stuck "
                "state from a previous session. Power-cycle the logger and retry."
            )
        if tag != b"STCP" or len(pl) != 8 or pl[4:6] not in HELLO_REPLY_CODES:
            msg = f"warning: unexpected hello reply tag={tag!r} payload={pl.hex()}"
            self._trace(msg)
            sys.stderr.write(msg + "\n")

    def _init(self) -> None:
        """Device-info request + time-sync."""
        size, status = self._run_init_handshake(
            *CMD_DEVINFO,
            arg_tail=b"\x01",
            size=DEVINFO_REQ_SIZE,
        )
        if status == STATUS_READY and size > 0:
            self.device_info = self._read_stream(size)

    def send_time_sync(self) -> None:
        """Public alias if caller wants to explicitly re-sync time mid-session."""
        self._send(b"STCP", _make_timesync_payload())

    def _sync_ping(self) -> None:
        """Lightweight state ping seen in vendor bootstrap before list activity."""
        self._send_stnc_cmd(*CMD_SYNC_PING, size=HDR_SIZE)
        self._wait_ready(expected_cmd=CMD_SYNC_PING)

    def _bootstrap(self, plan: str) -> None:
        if plan == "direct":
            self._init()
            return
        if plan == "ping_then_init":
            self._sync_ping()
            self._init()
            return
        if plan == "vendor_full":
            self._init()
            self._sync_ping()
            self._init()
            return
        raise ValueError(f"unknown bootstrap plan {plan!r}")

    def _send_stnc_cmd(
        self,
        cmd: int,
        sub: int,
        *,
        path: str = "",
        arg_tail: bytes = b"",
        size: int = 0,
    ) -> None:
        self._send(b"STNC", make_cmd(cmd, sub, path=path, arg_tail=arg_tail, size=size))

    def _run_init_handshake(
        self,
        cmd: int,
        sub: int,
        *,
        arg_tail: bytes = b"",
        size: int = 0,
    ) -> tuple[int, int]:
        expected = (cmd, sub)
        self._send_stnc_cmd(cmd, sub, arg_tail=arg_tail, size=size)
        size, status = self._wait_status(
            accept={STATUS_RECEIVED, STATUS_READY, STATUS_EMPTY},
            expected_cmd=expected,
        )
        if status == STATUS_RECEIVED:
            self._send(b"STCP", _make_timesync_payload())
            size, status = self._wait_ready(expected_cmd=expected)
        return size, status

    def _wait_status(
        self,
        *,
        accept: set[int],
        expected_cmd: Optional[tuple[int, int]] = None,
    ) -> tuple[int, int]:
        accept_txt = ",".join(_STATUS_NAMES.get(item, f"{item:#010x}") for item in sorted(accept))
        self._trace(f"wait_status expected_cmd={expected_cmd} accept={accept_txt}")
        exp_cmd = exp_sub = None
        if expected_cmd is not None:
            exp_cmd, exp_sub = expected_cmd
        while True:
            tag, pl = self._recv_frame()
            if tag != b"STCP":
                self._trace(f"wait_status unexpected tag={tag!r}")
                raise ProtocolError(f"unexpected non-STCP frame: tag={tag!r}")
            if len(pl) < HDR_SIZE:
                self._trace(f"wait_status ignoring short STCP payload len={len(pl)}")
                continue
            cmd, sub, size, status = parse_status(pl)
            if expected_cmd is not None and (cmd, sub) != (exp_cmd, exp_sub):
                self._trace(
                    f"wait_status unexpected cmd=0x{cmd:02x}/0x{sub:02x} "
                    f"want=0x{exp_cmd:02x}/0x{exp_sub:02x}"
                )
                raise ProtocolError(
                    f"unexpected status for cmd=0x{cmd:02x}/0x{sub:02x}; "
                    f"want 0x{exp_cmd:02x}/0x{exp_sub:02x}"
                )
            if status in accept:
                self._trace(
                    f"wait_status accepted cmd=0x{cmd:02x}/0x{sub:02x} "
                    f"size={size} status={status:#010x}"
                )
                return size, status
            if status in (STATUS_RECEIVED, STATUS_PENDING):
                self._trace(
                    f"wait_status continuing cmd=0x{cmd:02x}/0x{sub:02x} "
                    f"size={size} status={status:#010x}"
                )
                continue
            self._trace(
                f"wait_status unexpected status cmd=0x{cmd:02x}/0x{sub:02x} "
                f"size={size} status={status:#010x}"
            )
            raise ProtocolError(f"unexpected status {status:#010x}")

    def _wait_ready(
        self,
        *,
        expected_cmd: Optional[tuple[int, int]] = None,
    ) -> tuple[int, int]:
        return self._wait_status(
            accept={STATUS_READY, STATUS_EMPTY},
            expected_cmd=expected_cmd,
        )

    def _read_stream(self, total: int, progress=None) -> bytes:
        self._trace(f"stream read start total={total}")
        out = bytearray()
        while len(out) < total:
            self._send(b"STCP", len(out).to_bytes(4, "little"))
            tag, pl = self._recv_frame()
            if tag != b"STCP" or len(pl) < 4:
                raise ProtocolError(f"bad data frame tag={tag!r} len={len(pl)}")
            offset = int.from_bytes(pl[:4], "little")
            data = pl[4:]
            if offset != len(out):
                raise ProtocolError(f"offset mismatch: got {offset} want {len(out)}")
            out.extend(data)
            self._trace(
                f"stream chunk offset={offset} data={len(data)} got={len(out)}/{total}"
            )
            if progress is not None:
                progress(len(out), total)
        if len(out) > total:
            self._trace(f"stream read overrun got={len(out)} total={total}")
        self._trace(f"stream read complete got={len(out)} total={total}")
        return bytes(out)

    def read_file(self, path: str, *, progress=None) -> bytes:
        return self.read_file_result(path, progress=progress).data

    def read_file_result(self, path: str, *, progress=None) -> FileReadResult:
        self._trace(f"read_file start path={path!r}")
        self._send_stnc_cmd(*CMD_FILE_READ, path=path)
        size, status = self._wait_ready(expected_cmd=CMD_FILE_READ)
        self._trace(f"read_file ready path={path!r} size={size} status={status:#010x}")
        if status == STATUS_EMPTY or size == 0:
            return FileReadResult(b"", size)
        data = self._read_stream(size, progress=progress)
        self._trace(f"read_file complete path={path!r} got={len(data)} ready_size={size}")
        return FileReadResult(data, size)

    def fetch_list_csv(self) -> str:
        """Reproduce the vendor-app list flow: prep x2 → dev.ria probe → 0x24/02."""
        self._trace("fetch_list_csv start")
        prep_arg = b"\xff\xff\xff\xff"
        for idx in range(2):
            self._trace(f"fetch_list_csv prep {idx + 1}/2")
            self._send_stnc_cmd(*CMD_LIST_PREP, arg_tail=prep_arg)
            self._wait_ready(expected_cmd=CMD_LIST_PREP)
        cached = self.read_file(LIST_CACHE_PATH)
        if cached:
            self._trace(f"fetch_list_csv dev.ria cache bytes={len(cached)}")
            cached_text = cached.decode("utf-8-sig", errors="replace")
            cached_sessions = parse_session_list(cached_text)
            self._trace(
                f"fetch_list_csv dev.ria parsed_sessions={len(cached_sessions)} "
                f"preview={_preview_text(cached_text)}"
            )
            if _looks_like_session_list(cached_sessions):
                self._trace("fetch_list_csv using dev.ria cache")
                return cached_text
            self._trace(
                "dev.ria cache did not look like a session list; "
                "falling back to 0x24/0x02"
            )
        return self.fetch_plain_list_csv()

    def fetch_plain_list_csv(self) -> str:
        self._trace("fetch_plain_list_csv start")
        self._send_stnc_cmd(*CMD_LIST)
        size, status = self._wait_ready(expected_cmd=CMD_LIST)
        self._trace(f"fetch_plain_list_csv ready size={size} status={status:#010x}")
        if status == STATUS_EMPTY or size == 0:
            return ""
        text = self._read_stream(size).decode("ascii", errors="replace")
        self._trace(
            f"fetch_plain_list_csv complete chars={len(text)} preview={_preview_text(text)}"
        )
        return text

    def delete_file(self, path: str) -> int:
        self._trace(f"delete_file start path={path!r}")
        self._send_stnc_cmd(*CMD_FILE_DELETE, path=path)
        expected_path = path.encode("ascii")
        while True:
            tag, pl = self._recv_frame()
            if tag != b"STCP":
                raise ProtocolError(f"unexpected non-STCP frame: tag={tag!r}")
            if len(pl) < HDR_SIZE:
                continue
            cmd, sub, size, status = parse_status(pl)
            if (cmd, sub) != CMD_FILE_DELETE:
                raise ProtocolError(
                    f"unexpected status for cmd=0x{cmd:02x}/0x{sub:02x}; "
                    f"want 0x{CMD_FILE_DELETE[0]:02x}/0x{CMD_FILE_DELETE[1]:02x}"
                )
            echoed = pl[ARG_OFFSET:].split(b"\x00", 1)[0]
            if echoed != expected_path and not (status == STATUS_EMPTY and echoed == b""):
                raise ProtocolError(
                    f"delete path echo mismatch: got {echoed!r} want {expected_path!r}"
                )
            if status in (STATUS_RECEIVED, STATUS_PENDING):
                continue
            if status in (STATUS_READY, STATUS_EMPTY):
                if size != 0:
                    raise ProtocolError(f"unexpected delete completion size {size}")
                self._trace(f"delete_file complete path={path!r} status={status:#010x}")
                return status
            raise ProtocolError(f"unexpected delete status {status:#010x}")

    def fetch_device_info(self) -> bytes:
        if self.device_info:
            self._trace(f"fetch_device_info using cached bytes={len(self.device_info)}")
            return self.device_info
        self._trace("fetch_device_info start")
        self._send_stnc_cmd(*CMD_DEVINFO, arg_tail=b"\x01", size=DEVINFO_REQ_SIZE)
        size, status = self._wait_ready(expected_cmd=CMD_DEVINFO)
        self._trace(f"fetch_device_info ready size={size} status={status:#010x}")
        if status == STATUS_EMPTY or size == 0:
            return b""
        self.device_info = self._read_stream(size)
        self._trace(f"fetch_device_info complete bytes={len(self.device_info)}")
        return self.device_info


@dataclass
class Session:
    name: str
    size: int
    date: str
    hour: str
    nlap: str
    nbest: str
    best: str
    pilota: str
    track_name: str
    raw: dict[str, str]

    @property
    def remote_path(self) -> str:
        return f"{RECORDED_DIR}/{self.name}"


def parse_session_list(csv_text: str) -> list[Session]:
    """Parse the CSV returned by fetch_list_csv()."""
    if not csv_text.strip():
        return []
    if csv_text.startswith("\ufeff"):
        csv_text = csv_text.lstrip("\ufeff")
    delimiter = _detect_csv_delimiter(csv_text)
    reader = csv.reader(io.StringIO(csv_text), delimiter=delimiter)
    try:
        header = next(reader)
    except StopIteration:
        return []
    header = [h.strip().lstrip("\ufeff") for h in header]
    has_header = len(header) >= 2 and header[0].lower() == "name" and header[1].lower() == "size"
    if has_header:
        columns = header
    else:
        columns = SESSION_LIST_COLUMNS[:len(header)]
        reader = csv.reader(io.StringIO(csv_text), delimiter=delimiter)
    out: list[Session] = []
    for row in reader:
        if not row or not row[0]:
            continue
        if len(row) < len(columns):
            row = row + [""] * (len(columns) - len(row))
        values = dict(zip(columns, row))
        try:
            size = int(values.get("size", "0") or "0")
        except ValueError:
            size = 0
        out.append(
            Session(
                name=values.get("name", ""),
                size=size,
                date=values.get("date", ""),
                hour=values.get("hour", ""),
                nlap=values.get("nlap", ""),
                nbest=values.get("nbest", ""),
                best=values.get("best", ""),
                pilota=values.get("pilota", ""),
                track_name=values.get("track_name", ""),
                raw=values,
            )
        )
    return out


def _detect_csv_delimiter(csv_text: str) -> str:
    """Pick the delimiter used by the device's list output."""
    sample_lines = [line for line in csv_text.splitlines() if line.strip()][:5]
    sample = "\n".join(sample_lines)
    if not sample:
        return ","
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        return dialect.delimiter
    except csv.Error:
        pass
    counts = {
        delim: sum(line.count(delim) for line in sample_lines)
        for delim in (",", ";", "\t", "|")
    }
    best_delim, best_count = max(counts.items(), key=lambda item: item[1])
    return best_delim if best_count > 0 else ","


def _looks_like_session_list(sessions: list[Session]) -> bool:
    """Reject cache blobs or garbage that happen to parse as rows."""
    if not sessions:
        return False
    for session in sessions:
        if session.size <= 0:
            continue
        if not session.name:
            continue
        if "/" in session.name or "\\" in session.name or ";" in session.name or "," in session.name:
            continue
        if not SESSION_NAME_RE.fullmatch(session.name):
            continue
        return True
    return False


__all__ = [
    "AimSession",
    "DEFAULT_DISCOVERY_HOSTS",
    "DiscoveredDevice",
    "FileReadResult",
    "ProtocolError",
    "Session",
    "STATUS_EMPTY",
    "STATUS_READY",
    "discover",
    "parse_session_list",
    "parse_status",
    "wrap_frame",
]
