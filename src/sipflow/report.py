"""Human-readable and JSON reports, plus quality checks."""

from __future__ import annotations

import json

from .analyzer import Call

# Thresholds based on common VoIP quality guidance (ITU-T G.114 / typical carrier SLAs)
MAX_SETUP_S = 3.0
MAX_LOSS_PCT = 1.0
MAX_JITTER_MS = 30.0


def issues(call: Call) -> list[str]:
    found = []
    if call.outcome == "failed":
        found.append(f"call failed with {call.final_code}")
    if call.outcome == "cancelled":
        found.append("abandoned: caller hung up before answer (a 911 center would normally call back)")
    if call.outcome == "incomplete":
        found.append("no final response to INVITE")
    if call.setup_time is not None and call.setup_time > MAX_SETUP_S:
        found.append(f"slow setup {call.setup_time:.2f}s (> {MAX_SETUP_S}s)")
    if call.retransmissions:
        found.append(f"{call.retransmissions} INVITE retransmission(s)")
    if call.outcome == "answered" and not call.streams:
        found.append("answered but no RTP media seen (possible one-way/no audio)")
    for s in call.streams:
        if s.loss_pct > MAX_LOSS_PCT:
            found.append(f"packet loss {s.loss_pct:.1f}% on {s.src} -> {s.dst}")
        if s.jitter_ms > MAX_JITTER_MS:
            found.append(f"jitter {s.jitter_ms:.1f}ms on {s.src} -> {s.dst}")
    return found


def _fmt(x: float | None, unit: str = "s") -> str:
    return "-" if x is None else f"{x:.2f}{unit}"


def text_report(calls: list[Call], ladder: bool = False) -> str:
    out = [f"SIP call flow report: {len(calls)} call(s)", ""]
    header = f"{'#':<3}{'Caller':<26}{'Callee':<26}{'Outcome':<11}{'Code':<6}{'PDD':<8}{'Setup':<8}{'Talk':<8}"
    out += [header, "-" * len(header)]
    for i, c in enumerate(calls, 1):
        out.append(
            f"{i:<3}{(c.caller or '?')[:25]:<26}{(c.callee or '?')[:25]:<26}{c.outcome:<11}"
            f"{str(c.final_code or '-'):<6}{_fmt(c.post_dial_delay):<8}{_fmt(c.setup_time):<8}{_fmt(c.talk_time):<8}"
        )

    for i, c in enumerate(calls, 1):
        out += ["", f"[{i}] Call-ID {c.call_id}"]
        for s in c.streams:
            out.append(
                f"    RTP {s.src} -> {s.dst}  pkts={s.packets} lost={s.lost} ({s.loss_pct:.1f}%) jitter={s.jitter_ms:.1f}ms"
            )
        problems = issues(c)
        out.append("    Issues: " + ("; ".join(problems) if problems else "none"))
        if ladder:
            t0 = c.invite_time or (c.events[0].time if c.events else 0.0)
            for e in c.events:
                out.append(f"    +{e.time - t0:7.3f}s  {e.src:>21} -> {e.dst:<21} {e.label}")
    return "\n".join(out)


def json_report(calls: list[Call]) -> str:
    return json.dumps(
        {"calls": [dict(c.to_dict(), issues=issues(c)) for c in calls]},
        indent=2,
    )
