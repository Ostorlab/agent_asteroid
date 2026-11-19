"""Unit tests for the Babelfish for PostgreSQL TDS prelogin probe."""

from __future__ import annotations

import socket

import pytest

from agent.common import babelfish_tds_probe

# Real prelogin responses captured from a lab (see docs/cve-2026-119923.md):
# Babelfish 5.4.0 and 6.1.0 answer identically; MSSQL 2022 differs.
BABELFISH_RESPONSE = bytes.fromhex(
    "0401002b0000000000001a00060100200001020021000103002200000400220001ff"
    "0c0007d00000020000"
)
MSSQL_RESPONSE = bytes.fromhex(
    "0401002b0000010000001a00060100200001020021000103002200000400220001ff"
    "100010d10000020000"
)
HTTP_RESPONSE = bytes.fromhex("485454502f312e3120343030200d0a")


class _FakeSocket:
    """Serves a canned response and records what the probe sends."""

    def __init__(self, response: bytes, *, chunk_size: int | None = None) -> None:
        self._response = response
        self._chunk_size = chunk_size
        self._offset = 0
        self.sent = b""
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        del timeout

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, size: int) -> bytes:
        if self._offset >= len(self._response):
            return b""
        if self._chunk_size is None:
            chunk = self._response[self._offset :]
            self._offset = len(self._response)
        else:
            chunk = self._response[self._offset : self._offset + self._chunk_size]
            self._offset += len(chunk)
        return chunk[:size]

    def close(self) -> None:
        self.closed = True


class _FailingSendSocket(_FakeSocket):
    def sendall(self, data: bytes) -> None:
        del data
        raise ConnectionResetError("reset")


def _install(monkeypatch: pytest.MonkeyPatch, fake: _FakeSocket) -> _FakeSocket:
    def create_connection(address: tuple[str, int], timeout: float) -> _FakeSocket:
        del address, timeout
        return fake

    monkeypatch.setattr(socket, "create_connection", create_connection)
    return fake


def _install_connect_error(monkeypatch: pytest.MonkeyPatch, error: OSError) -> None:
    def create_connection(address: tuple[str, int], timeout: float) -> _FakeSocket:
        del address, timeout
        raise error

    monkeypatch.setattr(socket, "create_connection", create_connection)


def testProbeTds_whenBabelfishResponse_shouldDetectBabelfish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The constant Babelfish prelogin version is fingerprinted."""
    fake = _install(monkeypatch, _FakeSocket(BABELFISH_RESPONSE))

    result = babelfish_tds_probe.probe_tds("babelfish.host", 1433)

    assert result.tds is True
    assert result.babelfish is True
    assert result.version == "12.0.2000"
    assert result.detail is not None and "Babelfish signature" in result.detail
    assert fake.sent[0] == babelfish_tds_probe.PRELOGIN_PACKET_TYPE
    assert int.from_bytes(fake.sent[2:4], "big") == len(fake.sent)


def testProbeTds_whenMSSQLResponse_shouldNotFlagBabelfish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real MSSQL version differs from the Babelfish signature."""
    _install(monkeypatch, _FakeSocket(MSSQL_RESPONSE))

    result = babelfish_tds_probe.probe_tds("mssql.host", 1433)

    assert result.tds is True
    assert result.babelfish is False
    assert result.version == "16.0.4305"


def testProbeTds_whenNonTdsResponse_shouldNotDetect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An HTTP response is not a TDS prelogin."""
    _install(monkeypatch, _FakeSocket(HTTP_RESPONSE))

    result = babelfish_tds_probe.probe_tds("web.host", 443)

    assert result.tds is False
    assert result.babelfish is False


def testProbeTds_whenResponseIsChunked_shouldParse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The read loop reassembles a response delivered in chunks."""
    _install(monkeypatch, _FakeSocket(BABELFISH_RESPONSE, chunk_size=7))

    result = babelfish_tds_probe.probe_tds("babelfish.host", 1433)

    assert result.babelfish is True


def testProbeTds_whenTdsWithoutVersionOption_shouldReportNoBabelfish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A TDS prelogin without a version option is inconclusive, not a match."""
    empty_prelogin = (
        bytes([0x04, 0x01, 0x00, 0x0D, 0, 0, 0, 0]) + b"\xff\x00\x00\x00\x00"
    )
    _install(monkeypatch, _FakeSocket(empty_prelogin))

    result = babelfish_tds_probe.probe_tds("mssql.host", 1433)

    assert result.tds is True
    assert result.babelfish is False
    assert result.version is None


def testProbeTds_whenConnectionRefused_shouldReturnNoMatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Transport errors surface as no match, never as exceptions."""
    _install_connect_error(monkeypatch, ConnectionRefusedError("refused"))

    result = babelfish_tds_probe.probe_tds("closed.host", 1433)

    assert result.tds is False
    assert result.babelfish is False
    assert result.detail is not None and "Connection error" in result.detail


def testProbeTds_whenExchangeFails_shouldCloseSocketAndReturnNoMatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure during the exchange still closes the socket."""
    fake = _FailingSendSocket(b"")
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: fake)

    result = babelfish_tds_probe.probe_tds("reset.host", 1433)

    assert result.babelfish is False
    assert fake.closed is True


def testBuildPrelogin_shouldProduceWellFormedPacket() -> None:
    """The prelogin packet carries the TDS header and a matching length field."""
    packet = babelfish_tds_probe.build_prelogin()

    assert packet[0] == babelfish_tds_probe.PRELOGIN_PACKET_TYPE
    assert int.from_bytes(packet[2:4], "big") == len(packet)
    assert b"\xff\x00\x00\x00\x00" in packet


@pytest.mark.parametrize(
    "response",
    (b"", b"\x04\x01\x00\x08\x00\x00\x00\x00", b"\x04\x01"),
)
def testParsePreloginVersion_whenNoVersion_shouldReturnNone(response: bytes) -> None:
    """Short or version-less prelogin responses yield no version."""
    assert babelfish_tds_probe.parse_prelogin_version(response) is None


def testParsePreloginVersion_whenRealBabelfishResponse_shouldReturnVersion() -> None:
    """The parser reads the emulated version from the captured response."""
    assert babelfish_tds_probe.parse_prelogin_version(BABELFISH_RESPONSE) == "12.0.2000"
