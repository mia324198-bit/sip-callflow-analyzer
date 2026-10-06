"""Regenerate samples/demo_calls.pcap (synthetic data only)."""

import sys
from pathlib import Path

from sipflow.synth import build_demo

out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "samples" / "demo_calls.pcap"
out.parent.mkdir(parents=True, exist_ok=True)
build_demo(str(out))
print(f"wrote {out}")
