from __future__ import annotations

import csv
import io
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Iterable, Optional


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

CMD_DEVINFO = (0x10, 0x01)
CMD_SYNC_PING = (0x06, 0x01)
CMD_FILE_DELETE = (0x06, 0x04)
CMD_FILE_READ = (0x02, 0x04)
CMD_LIST = (0x24, 0x02)
CMD_LIST_PREP = (0x51, 0x02)
DEVINFO_REQ_SIZE = HDR_SIZE

RECORDED_DIR = "1:/mem"
LIST_CACHE_PATH = "0:/tkk/dev.ria"


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

    def __init__(self, sock: socket.socket, on_recv=None):
        self.sock = sock
        self.buf = bytearray()
        # optional callback(chunk: bytes) invoked for every raw recv()
        self.on_recv = on_recv

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
                    sys.stderr.write(
                        f"  [aim] timed out with {len(self.buf)}B partial data "
                        f"in buffer: {bytes(self.buf).hex()}\n"
                    )
                raise

    def _seek_frame_start(self) -> None:
        """Discard leading garbage until buffer starts with '<h'."""
        while True:
            idx = self.buf.find(b"<h")
            if idx == 0:
                return
            if idx > 0:
                del self.buf[:idx]
                return
            if self.buf[-1:] == b"<":
                del self.buf[:-1]
            else:
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
                del self.buf[:1]
                continue

            total = 12 + plen + 8
            self._need(total)

            payload = bytes(self.buf[12:12 + plen])
            off = 12 + plen
            if self.buf[off:off + 1] != b"<" or self.buf[off + 1:off + 5] != tag:
                del self.buf[:1]
                continue
            chk = int.from_bytes(self.buf[off + 5:off + 7], "little")
            if self.buf[off + 7:off + 8] != b">":
                del self.buf[:1]
                continue
            expected = sum(payload) & 0xFFFF
            if chk != expected:
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

    def __init__(self, host: str, trace) -> None:
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


def discover(
    timeout: float = 2.0,
    hosts: Optional[Iterable[str]] = None,
    verbose: bool = False,
) -> list[DiscoveredDevice]:
    """Broadcast + unicast `aim-ka` probe, collect replies from UDP :36002."""
    hosts = list(dict.fromkeys(hosts if hosts else DEFAULT_DISCOVERY_HOSTS))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", UDP_PORT))
    except OSError as e:
        if verbose:
            sys.stderr.write(f"warning: bind to :{UDP_PORT} failed ({e}); using ephemeral port\n")
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
                    except OSError as e:
                        if verbose:
                            sys.stderr.write(f"send to {host}: {e}\n")
                next_probe = now + 0.8
            try:
                data, (addr, src_port) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if verbose:
                sys.stderr.write(f"rx {len(data)}B from {addr}:{src_port}: {data[:32].hex()}\n")
            if src_port != UDP_PORT or data == DISCOVERY_PROBE:
                continue
            found[addr] = parse_discovery(data, addr)
    finally:
        sock.close()
    return list(found.values())


def auto_discover_host(
    timeout: float = AUTO_DISCOVERY_TIMEOUT,
    verbose: bool = False,
) -> str:
    """Resolve the active logger IP without assuming 10.0.0.1 is fixed."""
    devices = discover(timeout=timeout, hosts=DEFAULT_DISCOVERY_HOSTS, verbose=verbose)
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


class AimSession:
    """One TCP connection to the logger. Designed for short-lived per-task use."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: int = TCP_PORT,
        timeout: float = 15.0,
        verbose: bool = False,
        bootstrap: bool = True,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.bootstrap = bootstrap
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
                try:
                    self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                if CONNECT_SETTLE_DELAY > 0:
                    self._trace(f"post-connect settle {CONNECT_SETTLE_DELAY:.1f}s")
                    time.sleep(CONNECT_SETTLE_DELAY)
                on_recv = None
                if self.verbose:
                    def on_recv(chunk: bytes) -> None:
                        self._trace(
                            f"raw recv {len(chunk)}B: {chunk[:64].hex()}"
                            f"{'...' if len(chunk) > 64 else ''}"
                        )
                self.reader = FrameReader(self.sock, on_recv=on_recv)
                self._hello()
                if self.bootstrap:
                    self._bootstrap(plan)
                return
            except (ProtocolError, ConnectionError, socket.timeout, OSError) as e:
                last_exc = e
                self._trace(f"bootstrap failed: {e}")
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
                            if self.verbose:
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
        if self.verbose:
            sys.stderr.write(f"  [aim] {msg}\n")
            sys.stderr.flush()

    def _start_keepalive(self) -> None:
        if self.keepalive is None:
            self.keepalive = _UdpKeepalive(self.host, self._trace)
            self.keepalive.start()

    def _send(self, tag: bytes, payload: bytes) -> None:
        assert self.sock is not None
        if self.verbose:
            self._trace(f"tx {_summarize_frame(tag, payload)}")
        self.sock.sendall(wrap_frame(tag, payload))

    def _recv_frame(self) -> tuple[bytes, bytes]:
        assert self.reader is not None
        tag, pl = self.reader.read()
        if self.verbose:
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
        if tag != b"STCP" or len(pl) != 8 or pl[4:6] != b"\x06\x09":
            sys.stderr.write(f"warning: unexpected hello reply tag={tag!r} payload={pl.hex()}\n")

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
        exp_cmd = exp_sub = None
        if expected_cmd is not None:
            exp_cmd, exp_sub = expected_cmd
        while True:
            tag, pl = self._recv_frame()
            if tag != b"STCP":
                raise ProtocolError(f"unexpected non-STCP frame: tag={tag!r}")
            if len(pl) < HDR_SIZE:
                continue
            cmd, sub, size, status = parse_status(pl)
            if expected_cmd is not None and (cmd, sub) != (exp_cmd, exp_sub):
                raise ProtocolError(
                    f"unexpected status for cmd=0x{cmd:02x}/0x{sub:02x}; "
                    f"want 0x{exp_cmd:02x}/0x{exp_sub:02x}"
                )
            if status in accept:
                return size, status
            if status in (STATUS_RECEIVED, STATUS_PENDING):
                continue
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
            if progress is not None:
                progress(len(out), total)
        return bytes(out)

    def read_file(self, path: str, *, progress=None) -> bytes:
        return self.read_file_result(path, progress=progress).data

    def read_file_result(self, path: str, *, progress=None) -> FileReadResult:
        self._send_stnc_cmd(*CMD_FILE_READ, path=path)
        size, status = self._wait_ready(expected_cmd=CMD_FILE_READ)
        if status == STATUS_EMPTY or size == 0:
            return FileReadResult(b"", size)
        return FileReadResult(self._read_stream(size, progress=progress), size)

    def fetch_list_csv(self) -> str:
        """Reproduce the vendor-app list flow: prep x2 → dev.ria probe → 0x24/02."""
        prep_arg = b"\xff\xff\xff\xff"
        for _ in range(2):
            self._send_stnc_cmd(*CMD_LIST_PREP, arg_tail=prep_arg)
            self._wait_ready(expected_cmd=CMD_LIST_PREP)
        cached = self.read_file(LIST_CACHE_PATH)
        if cached:
            return cached.decode("ascii", errors="replace")
        return self.fetch_plain_list_csv()

    def fetch_plain_list_csv(self) -> str:
        self._send_stnc_cmd(*CMD_LIST)
        size, status = self._wait_ready(expected_cmd=CMD_LIST)
        if status == STATUS_EMPTY or size == 0:
            return ""
        return self._read_stream(size).decode("ascii", errors="replace")

    def delete_file(self, path: str) -> int:
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
                return status
            raise ProtocolError(f"unexpected delete status {status:#010x}")

    def fetch_device_info(self) -> bytes:
        if self.device_info:
            return self.device_info
        self._send_stnc_cmd(*CMD_DEVINFO, arg_tail=b"\x01", size=DEVINFO_REQ_SIZE)
        size, status = self._wait_ready(expected_cmd=CMD_DEVINFO)
        if status == STATUS_EMPTY or size == 0:
            return b""
        self.device_info = self._read_stream(size)
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
    reader = csv.reader(io.StringIO(csv_text))
    try:
        header = next(reader)
    except StopIteration:
        return []
    header = [h.strip() for h in header]
    out: list[Session] = []
    for row in reader:
        if not row or not row[0]:
            continue
        if len(row) < len(header):
            row = row + [""] * (len(header) - len(row))
        values = dict(zip(header, row))
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

