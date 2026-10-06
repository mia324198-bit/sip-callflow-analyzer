"""Generate synthetic SIP/RTP captures for demos and tests.

No real call data is used anywhere in this project: every sample is built here.
"""

from __future__ import annotations

import random
import struct

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

PROXY = "10.0.0.1"


def _seed(text: str) -> int:
    """Deterministic seed (built-in hash() is randomized per process)."""
    return sum(text.encode()) % 1000


def sip_msg(start: str, call_id: str, cseq: str, frm: str, to: str, sdp: tuple[str, int] | None = None) -> bytes:
    body = ""
    if sdp:
        ip, port = sdp
        body = (
            "v=0\r\n"
            f"o=- 1 1 IN IP4 {ip}\r\n"
            "s=call\r\n"
            f"c=IN IP4 {ip}\r\n"
            "t=0 0\r\n"
            f"m=audio {port} RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )
    headers = [
        start,
        "Via: SIP/2.0/UDP host;branch=z9hG4bK" + call_id[:6],
        f"From: <sip:{frm}>;tag=a1",
        f"To: <sip:{to}>",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq}",
        "Content-Type: application/sdp" if sdp else "Content-Length: 0",
    ]
    if sdp:
        headers.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode()


def rtp_bytes(seq: int, ts: int, ssrc: int) -> bytes:
    return struct.pack("!BBHII", 0x80, 0, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc) + b"\xff" * 160


class CaptureBuilder:
    def __init__(self) -> None:
        self.pkts = []

    def udp(self, t: float, src: str, sport: int, dst: str, dport: int, payload: bytes) -> None:
        p = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload
        p.time = t
        self.pkts.append(p)

    def sip(self, t: float, src: str, dst: str, payload: bytes) -> None:
        self.udp(t, src, 5060, dst, 5060, payload)

    def rtp_stream(
        self,
        t0: float,
        seconds: float,
        src: tuple[str, int],
        dst: tuple[str, int],
        ssrc: int,
        loss: float = 0.0,
        jitter_s: float = 0.0,
        seed: int = 1,
    ) -> None:
        rng = random.Random(seed)
        n = int(seconds * 50)  # 20 ms packets
        for i in range(n):
            if loss and rng.random() < loss:
                continue
            arrival = t0 + i * 0.02 + (rng.uniform(0, jitter_s) if jitter_s else 0.0)
            self.udp(arrival, src[0], src[1], dst[0], dst[1], rtp_bytes(1000 + i, 160 * i, ssrc))

    def save(self, path: str) -> None:
        wrpcap(path, sorted(self.pkts, key=lambda p: float(p.time)))


def answered_call(cb: CaptureBuilder, t: float, cid: str, a: str, b: str, talk: float = 2.0, **media) -> None:
    caller, callee = f"{cid}-caller@example.net", "911@psap.example.net"
    a_media, b_media = (a, 40000), (b, 50000)
    cb.sip(t, a, PROXY, sip_msg("INVITE sip:911@psap.example.net SIP/2.0", cid, "1 INVITE", caller, callee, a_media))
    cb.sip(t + 0.05, PROXY, a, sip_msg("SIP/2.0 100 Trying", cid, "1 INVITE", caller, callee))
    cb.sip(t + 0.30, PROXY, a, sip_msg("SIP/2.0 180 Ringing", cid, "1 INVITE", caller, callee))
    cb.sip(t + 1.20, PROXY, a, sip_msg("SIP/2.0 200 OK", cid, "1 INVITE", caller, callee, b_media))
    cb.sip(t + 1.25, a, PROXY, sip_msg("ACK sip:911@psap.example.net SIP/2.0", cid, "1 ACK", caller, callee))
    start = t + 1.3
    cb.rtp_stream(start, talk, a_media, b_media, ssrc=0x1111, seed=_seed(cid))
    cb.rtp_stream(start, talk, b_media, a_media, ssrc=0x2222, seed=_seed(cid) + 1, **media)
    end = start + talk + 0.1
    cb.sip(end, a, PROXY, sip_msg("BYE sip:911@psap.example.net SIP/2.0", cid, "2 BYE", caller, callee))
    cb.sip(end + 0.05, PROXY, a, sip_msg("SIP/2.0 200 OK", cid, "2 BYE", caller, callee))


def failed_call(cb: CaptureBuilder, t: float, cid: str, a: str, code: str = "486 Busy Here") -> None:
    caller, callee = f"{cid}-caller@example.net", "dispatch@psap.example.net"
    cb.sip(t, a, PROXY, sip_msg("INVITE sip:dispatch@psap.example.net SIP/2.0", cid, "1 INVITE", caller, callee, (a, 40002)))
    cb.sip(t + 0.05, PROXY, a, sip_msg("SIP/2.0 100 Trying", cid, "1 INVITE", caller, callee))
    cb.sip(t + 0.40, PROXY, a, sip_msg(f"SIP/2.0 {code}", cid, "1 INVITE", caller, callee))
    cb.sip(t + 0.45, a, PROXY, sip_msg("ACK sip:dispatch@psap.example.net SIP/2.0", cid, "1 ACK", caller, callee))


def cancelled_call(cb: CaptureBuilder, t: float, cid: str, a: str) -> None:
    caller, callee = f"{cid}-caller@example.net", "911@psap.example.net"
    cb.sip(t, a, PROXY, sip_msg("INVITE sip:911@psap.example.net SIP/2.0", cid, "1 INVITE", caller, callee, (a, 40004)))
    cb.sip(t + 0.30, PROXY, a, sip_msg("SIP/2.0 180 Ringing", cid, "1 INVITE", caller, callee))
    cb.sip(t + 2.00, a, PROXY, sip_msg("CANCEL sip:911@psap.example.net SIP/2.0", cid, "1 CANCEL", caller, callee))
    cb.sip(t + 2.05, PROXY, a, sip_msg("SIP/2.0 200 OK", cid, "1 CANCEL", caller, callee))
    cb.sip(t + 2.10, PROXY, a, sip_msg("SIP/2.0 487 Request Terminated", cid, "1 INVITE", caller, callee))


def slow_call(cb: CaptureBuilder, t: float, cid: str, a: str, b: str) -> None:
    """INVITE is retransmitted and the answer takes over 4 seconds."""
    caller, callee = f"{cid}-caller@example.net", "911@psap.example.net"
    a_media, b_media = (a, 40006), (b, 50006)
    invite = sip_msg("INVITE sip:911@psap.example.net SIP/2.0", cid, "1 INVITE", caller, callee, a_media)
    cb.sip(t, a, PROXY, invite)
    cb.sip(t + 0.5, a, PROXY, invite)  # T1 retransmission
    cb.sip(t + 1.0, PROXY, a, sip_msg("SIP/2.0 180 Ringing", cid, "1 INVITE", caller, callee))
    cb.sip(t + 4.2, PROXY, a, sip_msg("SIP/2.0 200 OK", cid, "1 INVITE", caller, callee, b_media))
    cb.sip(t + 4.25, a, PROXY, sip_msg("ACK sip:911@psap.example.net SIP/2.0", cid, "1 ACK", caller, callee))
    cb.rtp_stream(t + 4.3, 1.0, a_media, b_media, ssrc=0x3333)
    cb.rtp_stream(t + 4.3, 1.0, b_media, a_media, ssrc=0x4444)
    cb.sip(t + 5.5, PROXY, a, sip_msg("BYE sip:caller SIP/2.0", cid, "1 BYE", callee, caller))


def build_demo(path: str) -> None:
    cb = CaptureBuilder()
    answered_call(cb, 0.0, "call-clean", "192.168.1.10", "192.168.2.20")
    answered_call(cb, 1.0, "call-lossy", "192.168.1.11", "192.168.2.21", loss=0.05, jitter_s=0.10)
    failed_call(cb, 2.0, "call-busy", "192.168.1.12")
    cancelled_call(cb, 3.0, "call-abandoned", "192.168.1.13")
    slow_call(cb, 4.0, "call-slow", "192.168.1.14", "192.168.2.24")
    cb.save(path)
