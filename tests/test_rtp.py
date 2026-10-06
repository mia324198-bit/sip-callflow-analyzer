import pytest

from sipflow import rtp
from sipflow.synth import rtp_bytes


def test_parse_header():
    pkt = rtp.parse(rtp_bytes(seq=42, ts=6720, ssrc=0xABCD))
    assert (pkt.seq, pkt.timestamp, pkt.ssrc, pkt.payload_type) == (42, 6720, 0xABCD, 0)


def test_rejects_short_or_wrong_version():
    assert rtp.parse(b"\x80\x00") is None
    assert rtp.parse(b"\x40" + b"\x00" * 11) is None  # version 1


def _stream(seqs, jitter=None):
    s = rtp.RtpStream(src="a", dst="b", ssrc=1, payload_type=0)
    for i in seqs:
        arrival = i * 0.02 + (jitter(i) if jitter else 0.0)
        s.add(rtp.RtpPacket(payload_type=0, seq=i, timestamp=160 * i, ssrc=1), arrival)
    return s


def test_perfect_stream_has_no_loss_or_jitter():
    s = _stream(range(100))
    assert s.lost == 0
    assert s.jitter_ms == pytest.approx(0.0, abs=1e-6)


def test_counts_lost_packets():
    seqs = [i for i in range(100) if i not in (10, 11, 50)]
    s = _stream(seqs)
    assert s.expected == 100
    assert s.lost == 3
    assert s.loss_pct == pytest.approx(3.0)


def test_jitter_increases_with_variable_delay():
    s = _stream(range(200), jitter=lambda i: 0.03 if i % 2 else 0.0)
    assert s.jitter_ms > 20


def test_sequence_wraparound_is_not_loss():
    s = rtp.RtpStream(src="a", dst="b", ssrc=1, payload_type=0)
    for n, seq in enumerate([65533, 65534, 65535, 0, 1, 2]):
        s.add(rtp.RtpPacket(0, seq, 160 * n, 1), n * 0.02)
    assert s.expected == 6
    assert s.lost == 0
