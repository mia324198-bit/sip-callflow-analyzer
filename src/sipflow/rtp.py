"""RTP header parsing and stream quality metrics (RFC 3550)."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Static payload types -> clock rate (RFC 3551)
CLOCK_RATES = {0: 8000, 8: 8000, 9: 8000, 18: 8000}
DEFAULT_CLOCK = 8000


@dataclass
class RtpPacket:
    payload_type: int
    seq: int
    timestamp: int
    ssrc: int


def parse(payload: bytes) -> RtpPacket | None:
    """Parse a fixed 12-byte RTP header. Returns None if it isn't RTP version 2."""
    if len(payload) < 12:
        return None
    b0, b1, seq, ts, ssrc = struct.unpack("!BBHII", payload[:12])
    if b0 >> 6 != 2:
        return None
    return RtpPacket(payload_type=b1 & 0x7F, seq=seq, timestamp=ts, ssrc=ssrc)


@dataclass
class RtpStream:
    """Accumulates one RTP stream (one SSRC in one direction) and computes quality metrics."""

    src: str
    dst: str
    ssrc: int
    payload_type: int
    packets: int = 0
    first_time: float | None = None
    last_time: float | None = None
    _base_seq: int | None = None
    _max_ext_seq: int = 0
    _cycles: int = 0
    _last_seq: int | None = None
    _prev_transit: float | None = None
    _jitter: float = 0.0  # in timestamp units
    _seen: set[int] = field(default_factory=set)

    @property
    def clock_rate(self) -> int:
        return CLOCK_RATES.get(self.payload_type, DEFAULT_CLOCK)

    def add(self, pkt: RtpPacket, arrival: float) -> None:
        self.packets += 1
        if self.first_time is None:
            self.first_time = arrival
        self.last_time = arrival

        # Extended sequence number, handling 16-bit wraparound
        if self._last_seq is not None and pkt.seq < 0x1000 and self._last_seq > 0xF000:
            self._cycles += 1 << 16
        ext = self._cycles + pkt.seq
        if self._base_seq is None:
            self._base_seq = ext
        self._max_ext_seq = max(self._max_ext_seq, ext)
        self._last_seq = pkt.seq
        self._seen.add(ext)

        # Interarrival jitter, RFC 3550 section 6.4.1
        transit = arrival * self.clock_rate - pkt.timestamp
        if self._prev_transit is not None:
            d = abs(transit - self._prev_transit)
            self._jitter += (d - self._jitter) / 16
        self._prev_transit = transit

    @property
    def expected(self) -> int:
        if self._base_seq is None:
            return 0
        return self._max_ext_seq - self._base_seq + 1

    @property
    def lost(self) -> int:
        return max(self.expected - len(self._seen), 0)

    @property
    def loss_pct(self) -> float:
        return 100.0 * self.lost / self.expected if self.expected else 0.0

    @property
    def jitter_ms(self) -> float:
        return 1000.0 * self._jitter / self.clock_rate

    @property
    def duration(self) -> float:
        if self.first_time is None or self.last_time is None:
            return 0.0
        return self.last_time - self.first_time
