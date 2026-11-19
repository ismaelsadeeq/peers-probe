"""peer_probe — polite Bitcoin P2P prober.

Connects to a peer, completes a v1 version/verack handshake, records the
peer's user agent + service flags (and optionally times a getheaders response),
then disconnects cleanly. Designed to be well-behaved: honest user agent,
NODE_NONE services, no retries/churn, bounded concurrency.

The module is split into PURE functions (serialization/parsing — unit testable
with no network) and the network layer (handshake/runner).
"""
from __future__ import annotations
import socket, struct, hashlib, time, io, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
MAINNET_MAGIC = bytes.fromhex("f9beb4d9")
PROTOCOL_VERSION = 70016
NODE_NONE = 0
NODE_NETWORK = 1 << 0
NODE_WITNESS = 1 << 3
NODE_NETWORK_LIMITED = 1 << 10
# look like a normal pruned Core node: NETWORK_LIMITED | WITNESS
DEFAULT_SERVICES = NODE_NETWORK_LIMITED | NODE_WITNESS
PROBE_USER_AGENT = "/Satoshi:28.1.0/"  # blend in with common version
# mainnet genesis block hash, internal (little-endian) byte order for locators
GENESIS_HASH_LE = bytes.fromhex(
    "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")

# service flags: Core + widely-used non-core (Knots/utreexod/libre-relay/BU)
SERVICE_BITS = [
    (1 << 0, "NETWORK"), (1 << 1, "GETUTXO"), (1 << 2, "BLOOM"),
    (1 << 3, "WITNESS"), (1 << 6, "COMPACT_FILTERS"),
    (1 << 10, "NETWORK_LIMITED"), (1 << 11, "P2P_V2"),
    (1 << 4, "XTHIN"), (1 << 12, "UTREEXO"), (1 << 13, "UTREEXO_ARCHIVE"),
    (1 << 24, "UTREEXO_TMP"), (1 << 26, "REPLACE_BY_FEE"),
    (1 << 27, "REDUCED_DATA"), (1 << 28, "BLAKE2B"), (1 << 29, "LIBRE_RELAY"),
]


# ---------------------------------------------------------------------------
# pure serialization helpers
# ---------------------------------------------------------------------------
def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def ser_compactsize(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack("<B", n)
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def deser_compactsize(f: io.BufferedIOBase) -> int:
    c = f.read(1)[0]
    if c < 0xFD:
        return c
    if c == 0xFD:
        return struct.unpack("<H", f.read(2))[0]
    if c == 0xFE:
        return struct.unpack("<I", f.read(4))[0]
    return struct.unpack("<Q", f.read(8))[0]


def ser_varstr(s: bytes) -> bytes:
    return ser_compactsize(len(s)) + s


def deser_varstr(f: io.BufferedIOBase) -> bytes:
    n = deser_compactsize(f)
    return f.read(n)


def ser_netaddr(services: int, ip: str | None, port: int) -> bytes:
    """26-byte network address as used inside the version message (no time)."""
    if ip is None:
        ip_bytes = b"\x00" * 16
    else:
        a = ipaddress.ip_address(ip)
        if a.version == 4:
            ip_bytes = b"\x00" * 10 + b"\xff\xff" + a.packed  # IPv4-mapped
        else:
            ip_bytes = a.packed
    return struct.pack("<Q", services) + ip_bytes + struct.pack(">H", port)


def decode_services(n: int) -> list[str]:
    names = [name for bit, name in SERVICE_BITS if n & bit]
    other = n & ~sum(bit for bit, _ in SERVICE_BITS)
    if other:
        names.append(f"other(0x{other:x})")
    return names or ["NONE"]


# ---------------------------------------------------------------------------
# message framing
# ---------------------------------------------------------------------------
def make_message(command: str, payload: bytes, magic: bytes = MAINNET_MAGIC) -> bytes:
    cmd = command.encode().ljust(12, b"\x00")
    return magic + cmd + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload


def parse_message(read_exactly, magic: bytes = MAINNET_MAGIC):
    """Read one message using read_exactly(n)->bytes. Returns (command, payload).
    Raises ValueError on magic/checksum mismatch."""
    hdr = read_exactly(24)
    if hdr[:4] != magic:
        raise ValueError(f"bad magic {hdr[:4].hex()}")
    command = hdr[4:16].rstrip(b"\x00").decode("ascii", "replace")
    length = struct.unpack("<I", hdr[16:20])[0]
    checksum = hdr[20:24]
    payload = read_exactly(length) if length else b""
    if sha256d(payload)[:4] != checksum:
        raise ValueError("checksum mismatch")
    return command, payload


def build_version_payload(*, services=NODE_NONE, recv_ip=None, recv_port=0,
                          nonce=0, user_agent=PROBE_USER_AGENT, start_height=0,
                          relay=False, timestamp=0,
                          protocol_version=PROTOCOL_VERSION) -> bytes:
    p = struct.pack("<i", protocol_version)
    p += struct.pack("<Q", services)
    p += struct.pack("<q", timestamp)
    p += ser_netaddr(0, recv_ip, recv_port)          # addr_recv
    p += ser_netaddr(services, None, 0)              # addr_from (dummy)
    p += struct.pack("<Q", nonce)
    p += ser_varstr(user_agent.encode())
    p += struct.pack("<i", start_height)
    p += struct.pack("<?", relay)
    return p


def parse_version_payload(payload: bytes) -> dict:
    f = io.BytesIO(payload)
    version = struct.unpack("<i", f.read(4))[0]
    services = struct.unpack("<Q", f.read(8))[0]
    timestamp = struct.unpack("<q", f.read(8))[0]
    f.read(26)  # addr_recv
    f.read(26)  # addr_from
    nonce = struct.unpack("<Q", f.read(8))[0]
    user_agent = deser_varstr(f).decode("utf-8", "replace")
    start_height = struct.unpack("<i", f.read(4))[0]
    rest = f.read(1)
    relay = bool(rest[0]) if rest else True
    return dict(version=version, services=services,
                service_names=decode_services(services), timestamp=timestamp,
                nonce=nonce, user_agent=user_agent, start_height=start_height,
                relay=relay)


def build_getheaders_payload(locator_hashes, hash_stop=b"\x00" * 32,
                             protocol_version=PROTOCOL_VERSION) -> bytes:
    p = struct.pack("<I", protocol_version)
    p += ser_compactsize(len(locator_hashes))
    for h in locator_hashes:
        p += h
    p += hash_stop
    return p


# inv/getdata object types
MSG_BLOCK = 2
MSG_WITNESS_BLOCK = 0x40000002  # MSG_BLOCK | MSG_WITNESS_FLAG


def build_getdata_payload(invs) -> bytes:
    """invs: list of (type:int, hash:bytes32-little-endian)."""
    p = ser_compactsize(len(invs))
    for typ, h in invs:
        p += struct.pack("<I", typ) + h
    return p


# ping/pong carry an 8-byte nonce the peer echoes back; timing the round trip is
# the canonical application-layer latency (what Core itself records as min-ping).
PING_NONCE = 0x50656572_50726f62  # "PeerProb", any nonzero uint64 we can recognise


def build_ping_payload(nonce: int = PING_NONCE) -> bytes:
    return struct.pack("<Q", nonce)


def parse_pong_nonce(payload: bytes) -> int | None:
    return struct.unpack("<Q", payload[:8])[0] if len(payload) >= 8 else None


# ---------------------------------------------------------------------------
# network layer
# ---------------------------------------------------------------------------
def _reader(sock):
    def read_exactly(n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed connection")
            buf += chunk
        return buf
    return read_exactly


def _socks5_connect(proxy_host, proxy_port, target_host, target_port, timeout):
    """Connect to target through a SOCKS5 proxy (for Tor .onion routing)."""
    import struct as _st
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((proxy_host, proxy_port))
    s.sendall(b'\x05\x01\x00')  # greeting: 1 method, no-auth
    if s.recv(2) != b'\x05\x00':
        raise ConnectionError("SOCKS5 auth rejected")
    host = target_host.encode()
    s.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + _st.pack('>H', target_port))
    resp = s.recv(10)
    if len(resp) < 2 or resp[1] != 0:
        raise ConnectionError(f"SOCKS5 connect failed (status {resp[1] if len(resp)>1 else '?'})")
    return s


def handshake(ip: str, port: int, *, timeout: float = 8.0,
              user_agent: str = PROBE_USER_AGENT, do_headers: bool = False,
              do_ping: bool = False, block_hash: bytes | None = None,
              witness: bool = True, services: int = DEFAULT_SERVICES,
              block_timeout: float = 30.0,
              socks_proxy: tuple | None = None) -> dict:
    """Connect, complete a v1 handshake, record UA + service flags, disconnect.
    Returns a result dict; never raises (errors captured in result['error']).
    If socks_proxy=(host, port) is given, routes through SOCKS5 (for Tor)."""
    result = {"ip": ip, "port": port, "ok": False, "error": None}
    t0 = time.monotonic()
    sock = None

    def wait_for(sock, read_exactly, wanted, deadline):
        """Read messages until one in `wanted` arrives or the deadline passes.
        Answers pings (so the peer doesn't drop us) and ignores everything else."""
        while time.monotonic() < deadline:
            command, payload = parse_message(read_exactly)
            if command == "ping":
                sock.sendall(make_message("pong", payload))  # keep-alive
                continue
            if command in wanted:
                return command, payload
        return None, None

    try:
        if socks_proxy:
            sock = _socks5_connect(socks_proxy[0], socks_proxy[1], ip, port, timeout)
        else:
            sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        read_exactly = _reader(sock)
        import os, random
        nonce = int.from_bytes(os.urandom(8), "little")
        ver = build_version_payload(services=services, user_agent=user_agent,
                                    timestamp=int(time.time()), nonce=nonce,
                                    start_height=975000 + random.randint(0, 300),
                                    relay=True)
        sock.sendall(make_message("version", ver))
        # 1) receive their version
        cmd, payload = wait_for(sock, read_exactly, {"version"}, time.monotonic()+timeout)
        if cmd != "version":
            raise ValueError("no version received")
        result.update(parse_version_payload(payload), ok=True,
                      connect_ms=round((time.monotonic() - t0) * 1000, 1))
        # 2) send feature-negotiation messages (look like a normal v0.21+ node),
        #    then verack, then wait for theirs.
        sock.sendall(make_message("wtxidrelay", b""))
        sock.sendall(make_message("sendaddrv2", b""))
        sock.sendall(make_message("verack", b""))
        wait_for(sock, read_exactly, {"verack"}, time.monotonic()+timeout)
        # 3) burst all requests at once — race the eviction timer.
        #    send everything, then collect whatever comes back.
        sock.sendall(make_message("sendheaders", b""))
        sock.sendall(make_message("sendcmpct", b"\x00\x02\x00\x00\x00\x00\x00\x00\x00"))
        tp = t1 = t2 = time.monotonic()
        if do_ping:
            sock.sendall(make_message("ping", build_ping_payload()))
        if do_headers:
            sock.sendall(make_message("getheaders", build_getheaders_payload([GENESIS_HASH_LE])))
        if block_hash is not None:
            typ = MSG_WITNESS_BLOCK if witness else MSG_BLOCK
            sock.sendall(make_message("getdata", build_getdata_payload([(typ, block_hash)])))

        # collect responses — whatever arrives before disconnect or deadline
        want = set()
        if do_ping:     want.add("pong")
        if do_headers:  want.add("headers")
        if block_hash:  want |= {"block", "notfound"}
        deadline = time.monotonic() + (block_timeout if block_hash else timeout)
        if block_hash:
            sock.settimeout(block_timeout)
        while want and time.monotonic() < deadline:
            try:
                command, payload = parse_message(read_exactly)
            except (ConnectionError, TimeoutError, ValueError):
                break
            if command == "ping":
                sock.sendall(make_message("pong", payload))
                continue
            if command == "pong" and "pong" in want:
                if parse_pong_nonce(payload) == PING_NONCE:
                    result["ping_ms"] = round((time.monotonic() - tp) * 1000, 1)
                want.discard("pong")
            elif command == "headers" and "headers" in want:
                result["headers_count"] = deser_compactsize(io.BytesIO(payload))
                result["headers_ms"] = round((time.monotonic() - t1) * 1000, 1)
                result["headers_bytes"] = len(payload)
                want.discard("headers")
            elif command == "block" and "block" in want:
                dt = time.monotonic() - t2
                result["block_bytes"] = len(payload)
                result["block_ms"] = round(dt * 1000, 1)
                result["block_mbps"] = round(len(payload) * 8 / 1e6 / dt, 2) if dt > 0 else None
                result["block_status"] = "served"
                want -= {"block", "notfound"}
            elif command == "notfound" and "notfound" in want:
                result["block_status"] = "notfound"
                want -= {"block", "notfound"}
        if block_hash and "block_status" not in result:
            result["block_status"] = "no_response"
    except Exception as e:  # noqa: BLE001 — capture everything per-host
        if block_hash is not None and "block_status" not in result:
            result["block_status"] = "disconnected" if result.get("ok") else "handshake_fail"
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
    return result


def run_harvest(targets, *, concurrency: int = 8, timeout: float = 8.0,
                do_headers: bool = False, do_ping: bool = False,
                block_hash: bytes | None = None, witness: bool = True,
                user_agent: str = PROBE_USER_AGENT, on_result=None,
                socks_proxy: tuple | None = None) -> list[dict]:
    """Harvest a list of (ip, port) politely: bounded concurrency, one attempt
    per host (no retries/churn), clean disconnects."""
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = {ex.submit(handshake, ip, int(port), timeout=timeout,
                          user_agent=user_agent, do_headers=do_headers,
                          do_ping=do_ping, block_hash=block_hash, witness=witness,
                          socks_proxy=socks_proxy): (ip, port)
                for ip, port in targets}
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            if on_result:
                on_result(r)
    return results
