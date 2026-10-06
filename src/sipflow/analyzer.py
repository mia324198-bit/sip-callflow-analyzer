"""Rebuild SIP call flows and RTP media quality from a packet capture."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from scapy.layers.inet import IP, UDP
from scapy.utils import PcapReader

from . import rtp, sip


@dataclass
class Event:
    time: float
    src: str
    dst: str
    label: str  # e.g. "INVITE" or "200 OK"


@dataclass
class Call:
    call_id: str
    caller: str | None = None
    callee: str | None = None
    invite_time: float | None = None
    ringing_time: float | None = None
    answer_time: float | None = None
    end_time: float | None = None
    final_code: int | None = None
    cancelled: bool = False
    invite_count: int = 0
    events: list[Event] = field(default_factory=list)
    media_endpoints: set[tuple[str, int]] = field(default_factory=set)
    streams: list[rtp.RtpStream] = field(default_factory=list)

    @property
    def outcome(self) -> str:
        if self.cancelled:
            return "cancelled"
        if self.final_code is None:
            return "incomplete"
        if 200 <= self.final_code < 300:
            return "answered"
        return "failed"

    @property
    def post_dial_delay(self) -> float | None:
        """Seconds from INVITE to first ringing (180/183)."""
        if self.invite_time is None or self.ringing_time is None:
            return None
        return self.ringing_time - self.invite_time

    @property
    def setup_time(self) -> float | None:
        """Seconds from INVITE to 200 OK."""
        if self.invite_time is None or self.answer_time is None:
            return None
        return self.answer_time - self.invite_time

    @property
    def talk_time(self) -> float | None:
        if self.answer_time is None or self.end_time is None:
            return None
        return self.end_time - self.answer_time

    @property
    def retransmissions(self) -> int:
        return max(self.invite_count - 1, 0)

    def to_dict(self) -> dict:
        def r(x):
            return None if x is None else round(x, 3)

        return {
            "call_id": self.call_id,
            "caller": self.caller,
            "callee": self.callee,
            "outcome": self.outcome,
            "final_code": self.final_code,
            "post_dial_delay_s": r(self.post_dial_delay),
            "setup_time_s": r(self.setup_time),
            "talk_time_s": r(self.talk_time),
            "invite_retransmissions": self.retransmissions,
            "streams": [
                {
                    "src": s.src,
                    "dst": s.dst,
                    "ssrc": f"0x{s.ssrc:08x}",
                    "payload_type": s.payload_type,
                    "packets": s.packets,
                    "lost": s.lost,
                    "loss_pct": round(s.loss_pct, 2),
                    "jitter_ms": round(s.jitter_ms, 2),
                }
                for s in self.streams
            ],
            "ladder": [
                {"t": round(e.time - (self.invite_time or e.time), 3), "src": e.src, "dst": e.dst, "msg": e.label}
                for e in self.events
            ],
        }


class Analyzer:
    def __init__(self) -> None:
        self.calls: dict[str, Call] = {}
        self._rtp_candidates: list[tuple[float, str, int, str, int, rtp.RtpPacket]] = []

    def feed(self, time: float, src_ip: str, sport: int, dst_ip: str, dport: int, payload: bytes) -> None:
        msg = sip.parse(payload)
        if msg is not None and msg.call_id:
            self._handle_sip(time, f"{src_ip}:{sport}", f"{dst_ip}:{dport}", msg)
            return
        pkt = rtp.parse(payload)
        if pkt is not None:
            self._rtp_candidates.append((time, src_ip, sport, dst_ip, dport, pkt))

    def _handle_sip(self, time: float, src: str, dst: str, msg: sip.SipMessage) -> None:
        call = self.calls.setdefault(msg.call_id, Call(call_id=msg.call_id))
        label = msg.method if msg.is_request else f"{msg.status_code} {msg.reason}".strip()
        call.events.append(Event(time, src, dst, label))

        media = msg.sdp_audio()
        if media:
            call.media_endpoints.add(media)

        if msg.is_request:
            if msg.method == "INVITE":
                call.invite_count += 1
                if call.invite_time is None:
                    call.invite_time = time
                    call.caller = msg.from_uri
                    call.callee = msg.to_uri
            elif msg.method == "CANCEL":
                call.cancelled = True
            elif msg.method == "BYE" and call.end_time is None:
                call.end_time = time
            return

        # Responses: only INVITE transactions drive call state
        if msg.cseq_method != "INVITE":
            return
        code = msg.status_code
        if code in (180, 183) and call.ringing_time is None:
            call.ringing_time = time
        elif code >= 200 and call.final_code is None:
            call.final_code = code
            if 200 <= code < 300:
                call.answer_time = time

    def finish(self) -> list[Call]:
        """Attach buffered RTP packets to calls by SDP media endpoint, then return calls in time order."""
        owner: dict[tuple[str, int], Call] = {}
        for call in self.calls.values():
            for ep in call.media_endpoints:
                owner[ep] = call

        streams: dict[tuple[str, str, int], rtp.RtpStream] = {}
        for time, sip_, sport, dip, dport, pkt in sorted(self._rtp_candidates, key=lambda c: c[0]):
            call = owner.get((dip, dport)) or owner.get((sip_, sport))
            if call is None:
                continue
            key = (f"{sip_}:{sport}", f"{dip}:{dport}", pkt.ssrc)
            stream = streams.get(key)
            if stream is None:
                stream = rtp.RtpStream(src=key[0], dst=key[1], ssrc=pkt.ssrc, payload_type=pkt.payload_type)
                streams[key] = stream
                call.streams.append(stream)
            stream.add(pkt, time)

        return sorted(self.calls.values(), key=lambda c: c.invite_time or 0.0)


def analyze_pcap(path: str | Path) -> list[Call]:
    analyzer = Analyzer()
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if IP in pkt and UDP in pkt:
                udp = pkt[UDP]
                analyzer.feed(float(pkt.time), pkt[IP].src, udp.sport, pkt[IP].dst, udp.dport, bytes(udp.payload))
    return analyzer.finish()
