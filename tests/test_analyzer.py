import json

import pytest

from sipflow import analyze_pcap
from sipflow.cli import main
from sipflow.report import issues
from sipflow.synth import build_demo


@pytest.fixture(scope="module")
def demo_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("pcap") / "demo.pcap"
    build_demo(str(path))
    return path


@pytest.fixture(scope="module")
def calls(demo_pcap):
    return {c.call_id: c for c in analyze_pcap(demo_pcap)}


def test_finds_every_call(calls):
    assert set(calls) == {"call-clean", "call-lossy", "call-busy", "call-abandoned", "call-slow"}


def test_outcomes(calls):
    assert calls["call-clean"].outcome == "answered"
    assert calls["call-busy"].outcome == "failed"
    assert calls["call-busy"].final_code == 486
    assert calls["call-abandoned"].outcome == "cancelled"


def test_timing(calls):
    clean = calls["call-clean"]
    assert clean.post_dial_delay == pytest.approx(0.30, abs=0.01)
    assert clean.setup_time == pytest.approx(1.20, abs=0.01)
    assert clean.talk_time > 2.0


def test_clean_call_media(calls):
    clean = calls["call-clean"]
    assert len(clean.streams) == 2
    assert all(s.lost == 0 for s in clean.streams)
    assert issues(clean) == []


def test_lossy_call_flagged(calls):
    problems = " ".join(issues(calls["call-lossy"]))
    assert "packet loss" in problems
    assert "jitter" in problems


def test_slow_call_flagged(calls):
    slow = calls["call-slow"]
    assert slow.retransmissions == 1
    problems = " ".join(issues(slow))
    assert "slow setup" in problems
    assert "retransmission" in problems


def test_cli_json(demo_pcap, capsys):
    assert main([str(demo_pcap), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["calls"]) == 5


def test_cli_fail_on_issues(demo_pcap, capsys):
    assert main([str(demo_pcap), "--fail-on-issues"]) == 2


def test_cli_missing_file(capsys):
    assert main(["does-not-exist.pcap"]) == 1


def test_abandoned_call_flagged(calls):
    assert "abandoned" in " ".join(issues(calls["call-abandoned"]))
