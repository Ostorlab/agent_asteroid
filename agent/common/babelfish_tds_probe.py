"""Read-only TDS prelogin fingerprint for Babelfish for PostgreSQL exposure.

Babelfish for PostgreSQL implements the Microsoft SQL Server wire protocol
(TDS) so that SQL Server clients can connect to PostgreSQL unchanged. Its
prelogin response advertises a constant emulated server version of
12.0.2000.8 (SQL Server 2014 RTM), identical across Babelfish releases -
including the releases fixed for CVE-2026-119923 / CVE-2026-119924 - so this
probe is an exposure fingerprint, not a fix-state check. The running Babelfish
release cannot be observed without credentials (verified in a lab against
Babelfish 5.4.0 and 6.1.0, which answer identically); findings are therefore
reported as potential exposure.

The probe sends a single, standards-compliant TDS PRELOGIN packet - the same
packet any SQL Server client sends when opening a connection - and parses the
response. It never sends malformed or oversized packets, never attempts a
login, and never exercises the prelogin-parser memory corruption. It has no
dependency on the ostorlab agent framework so it can be exercised directly
against a lab server.
"""

from __future__ import annotations

import dataclasses
import logging
import socket
import struct

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 4096
PRELOGIN_PACKET_TYPE = 0x12
TDS_RESPONSE_PACKET_TYPE = 0x04
VERSION_OPTION_TYPE = 0x00
# The emulated SQL Server version Babelfish advertises in its prelogin
# response; constant across releases, including the fixed ones.
BABELFISH_EMULATED_VERSION = (12, 0, 2000)


@dataclasses.dataclass
class ProbeResult:
    """Outcome of the TDS prelogin fingerprint against a single target."""

    tds: bool = False
    babelfish: bool = False
    version: str | None = None
    detail: str | None = None


def build_prelogin() -> bytes:
    """A standards-compliant TDS PRELOGIN packet (client 10.0.4000.0, no TLS)."""
    version = b"\x0a\x00\x0f\xe0\x00\x00"
    encryption = b"\x02"  # ENCRYPT_NOT_SUP
    instopt = b"\x00"
    threadid = b"\x00\x00\x00\x00"
    mars = b"\x00"
    parts = (version, encryption, instopt, threadid, mars)
    option_types = (0x00, 0x01, 0x02, 0x03, 0x04)
    header_size = len(option_types) * 5 + 5
    option_header = b""
    offset = 0
    for option_type, part in zip(option_types, parts):
        option_header += struct.pack(
            ">BHH", option_type, header_size + offset, len(part)
        )
        offset += len(part)
    option_header += b"\xff\x00\x00\x00\x00"
    payload = option_header + b"".join(parts)
    return (
        struct.pack(">BBHHBB", PRELOGIN_PACKET_TYPE, 0x01, len(payload) + 8, 0, 1, 0)
        + payload
    )


def parse_prelogin_version(response: bytes) -> str | None:
    """Return the 'major.minor.build' version from a prelogin response, if any."""
    if len(response) < 8 or response[0] != TDS_RESPONSE_PACKET_TYPE:
        return None
    payload = response[8:]
    pos = 0
    while pos + 5 <= len(payload):
        option_type = payload[pos]
        if option_type == 0xFF:
            break
        option_offset = struct.unpack(">H", payload[pos + 1 : pos + 3])[0]
        option_length = struct.unpack(">H", payload[pos + 3 : pos + 5])[0]
        if (
            option_type == VERSION_OPTION_TYPE
            and option_length >= 4
            and option_offset + option_length <= len(payload)
        ):
            version = payload[option_offset : option_offset + option_length]
            build = struct.unpack(">H", version[2:4])[0]
            return f"{version[0]}.{version[1]}.{build}"
        pos += 5
    return None


def _read_response(sock: socket.socket) -> bytes:
    """Read one TDS response packet, bounded by MAX_RESPONSE_BYTES."""
    buffer = bytearray()
    while len(buffer) < MAX_RESPONSE_BYTES:
        chunk = sock.recv(min(4096, MAX_RESPONSE_BYTES - len(buffer)))
        if len(chunk) == 0:
            break
        buffer.extend(chunk)
        if (
            len(buffer) >= 4
            and len(buffer) >= struct.unpack(">H", bytes(buffer[2:4]))[0]
        ):
            break
    return bytes(buffer)


def probe_tds(
    host: str, port: int, *, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> ProbeResult:
    """Fingerprint a TDS endpoint and check the Babelfish emulated version.

    `tds` is set when the endpoint answered a TDS prelogin; `babelfish` is set
    when the advertised emulated version matches the constant Babelfish
    signature. Every failure mode is inconclusive and reported as no match.
    """
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as error:
        logger.debug("TDS probe to %s:%s failed to connect: %s", host, port, error)
        return ProbeResult(detail=f"Connection error: {error}")
    try:
        sock.settimeout(timeout)
        sock.sendall(build_prelogin())
        response = _read_response(sock)
    except OSError as error:
        logger.debug("TDS probe to %s:%s failed during exchange: %s", host, port, error)
        return ProbeResult(detail=f"Connection error: {error}")
    finally:
        sock.close()

    if len(response) < 8 or response[0] != TDS_RESPONSE_PACKET_TYPE:
        return ProbeResult(detail="No TDS prelogin response")

    version = parse_prelogin_version(response)
    if version is None:
        return ProbeResult(
            tds=True, detail="TDS prelogin answered without a parseable version"
        )

    major, minor, build = (int(part) for part in version.split("."))
    if (major, minor, build) == BABELFISH_EMULATED_VERSION:
        return ProbeResult(
            tds=True,
            babelfish=True,
            version=version,
            detail=(
                f"TDS prelogin advertises emulated SQL Server version {version} "
                "(SQL Server 2014 RTM), the constant Babelfish signature"
            ),
        )
    return ProbeResult(
        tds=True,
        version=version,
        detail=(
            f"TDS service advertises server version {version}, which is not the "
            "Babelfish signature"
        ),
    )
