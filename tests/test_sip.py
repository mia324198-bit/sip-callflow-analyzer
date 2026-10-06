from sipflow import sip
from sipflow.synth import sip_msg


def test_parses_invite_with_sdp():
    raw = sip_msg(
        "INVITE sip:911@psap.example.net SIP/2.0", "abc", "1 INVITE", "a@x", "911@psap.example.net", ("10.1.1.1", 40000)
    )
    msg = sip.parse(raw)
    assert msg.is_request and msg.method == "INVITE"
    assert msg.call_id == "abc"
    assert msg.cseq_method == "INVITE"
    assert msg.from_uri == "sip:a@x"
    assert msg.to_uri == "sip:911@psap.example.net"
    assert msg.sdp_audio() == ("10.1.1.1", 40000)


def test_parses_response():
    msg = sip.parse(sip_msg("SIP/2.0 486 Busy Here", "abc", "1 INVITE", "a@x", "b@y"))
    assert not msg.is_request
    assert msg.status_code == 486
    assert msg.reason == "Busy Here"
    assert msg.sdp_audio() is None


def test_compact_headers():
    raw = b"BYE sip:b@y SIP/2.0\r\ni: short-id\r\nf: <sip:a@x>\r\nCSeq: 2 BYE\r\n\r\n"
    msg = sip.parse(raw)
    assert msg.call_id == "short-id"
    assert msg.from_uri == "sip:a@x"


def test_rejects_non_sip():
    assert sip.parse(b"\x80\x00\x00\x01binary rtp") is None
    assert sip.parse(b"GET / HTTP/1.1\r\n\r\n") is None
    assert sip.parse(b"SIP/2.0 notanumber\r\n\r\n") is None
