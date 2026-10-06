"""Minimal SIP message parser.

Parses just enough of a SIP request or response (RFC 3261) to rebuild call flows:
the start line, the headers we care about, and the audio port from an SDP body.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SIP_METHODS = {"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "PRACK", "UPDATE", "INFO"}

# Compact header forms (RFC 3261 section 7.3.3)
COMPACT = {"i": "call-id", "f": "from", "t": "to", "v": "via", "m": "contact", "l": "content-length", "c": "content-type"}


@dataclass
class SipMessage:
    is_request: bool
    method: str | None = None  # for requests, e.g. "INVITE"
    uri: str | None = None
    status_code: int | None = None  # for responses, e.g. 200
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    @property
    def call_id(self) -> str | None:
        return self.headers.get("call-id")

    @property
    def cseq_method(self) -> str | None:
        cseq = self.headers.get("cseq")
        if not cseq:
            return None
        parts = cseq.split()
        return parts[1].upper() if len(parts) == 2 else None

    @property
    def from_uri(self) -> str | None:
        return _extract_uri(self.headers.get("from"))

    @property
    def to_uri(self) -> str | None:
        return _extract_uri(self.headers.get("to"))

    def sdp_audio(self) -> tuple[str, int] | None:
        """Return (connection IP, audio port) from an SDP body, if present."""
        if not self.body:
            return None
        ip, port = None, None
        for line in self.body.splitlines():
            line = line.strip()
            if line.startswith("c=IN IP4 "):
                ip = line.split()[-1]
            elif line.startswith("m=audio "):
                try:
                    port = int(line.split()[1])
                except (IndexError, ValueError):
                    return None
        if ip and port:
            return ip, port
        return None


def _extract_uri(value: str | None) -> str | None:
    if not value:
        return None
    if "<" in value and ">" in value:
        return value[value.index("<") + 1 : value.index(">")]
    return value.split(";")[0].strip()


def looks_like_sip(payload: bytes) -> bool:
    head = payload[:16]
    if head.startswith(b"SIP/2.0 "):
        return True
    word = head.split(b" ", 1)[0]
    return word.decode("ascii", "ignore") in SIP_METHODS


def parse(payload: bytes) -> SipMessage | None:
    """Parse a UDP payload into a SipMessage, or return None if it isn't SIP."""
    if not looks_like_sip(payload):
        return None
    text = payload.decode("utf-8", "replace")
    head, _, body = text.replace("\r\n", "\n").partition("\n\n")
    lines = head.split("\n")
    start = lines[0].strip()

    if start.startswith("SIP/2.0 "):
        parts = start.split(" ", 2)
        try:
            code = int(parts[1])
        except (IndexError, ValueError):
            return None
        msg = SipMessage(is_request=False, status_code=code, reason=parts[2] if len(parts) > 2 else "")
    else:
        parts = start.split(" ")
        if len(parts) < 3:
            return None
        msg = SipMessage(is_request=True, method=parts[0].upper(), uri=parts[1])

    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        name = COMPACT.get(name, name)
        msg.headers.setdefault(name, value.strip())

    msg.body = body
    return msg
