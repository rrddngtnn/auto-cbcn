"""fingerprint.py — Recycled number detection, IoT/virtual prefix blocklists, and attempt ledger."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

LEDGER_PATH = Path(os.environ.get("CBCN_LEDGER", str(Path(__file__).resolve().parents[2] / "var" / "ledger.json")))

# Prefix virtual / IoT that are hard-blocked by Tencent OneID isVirtualMobile
VIRTUAL_PREFIXES = tuple(f"1{d}" for d in ("45", "46", "47", "48", "49", "62", "65", "67", "70", "71", "72")) + ("192",)
BAD_CN_PREFIXES = ("145", "146", "147", "148", "149", "162", "165", "167", "170", "171", "172", "192")


def _load(path: Path = LEDGER_PATH) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_file():
        return {"seen": {}, "good": {}, "bad": {}, "runs": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"seen": {}, "good": {}, "bad": {}, "runs": []}


def _save(data: dict, path: Path = LEDGER_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def prefix_of(phone: str) -> str:
    """Normalize phone prefix: HK (8 digits or +852) -> 'hk'; CN (11 digits) -> first 7 digits."""
    p = "".join(ch for ch in phone if ch.isdigit())
    if p.startswith("852") and len(p) == 11:
        return "hk"
    if len(p) == 8:
        return "hk"
    return p[:7] if len(p) >= 7 else p


def is_recycled_suspect(phone: str, ledger_path: Path = LEDGER_PATH) -> tuple[bool, str]:
    """Offline heuristic check to determine if a rented number is suspect or recycled."""
    d = _load(ledger_path)
    pre = prefix_of(phone)
    if pre in d.get("bad", {}):
        return True, f"prefix {pre} previously flagged with 11140"
    if phone in d.get("seen", {}):
        return True, "phone already tested this session"
    digits = "".join(c for c in phone if c.isdigit())
    if len(digits) == 11 and digits.startswith(VIRTUAL_PREFIXES):
        return True, "virtual/IoT prefix rejected by isVirtualMobile"
    if len(digits) == 11 and digits.startswith(BAD_CN_PREFIXES):
        return True, "prefix in default blocklist"
    return False, "ok"


def record_attempt(
    phone: str,
    provider: str,
    outcome: str,
    detail: str = "",
    ledger_path: Path = LEDGER_PATH,
) -> None:
    """Record an attempt outcome: sms_bisu | no_otp | empty_quota | banned | ok | error."""
    d = _load(ledger_path)
    pre = prefix_of(phone)
    d.setdefault("seen", {})[phone] = {
        "provider": provider,
        "outcome": outcome,
        "ts": int(time.time()),
    }
    if outcome in ("banned",):
        b = d.setdefault("bad", {}).setdefault(pre, {"count": 0})
        b["count"] += 1
        b["last"] = detail[:160]
    elif outcome == "ok":
        g = d.setdefault("good", {}).setdefault(pre, {"count": 0})
        g["count"] += 1
    d.setdefault("runs", []).append({
        "phone": phone,
        "prefix": pre,
        "outcome": outcome,
        "ts": int(time.time()),
    })
    d["runs"] = d["runs"][-500:]
    _save(d, ledger_path)


def summarize(ledger_path: Path = LEDGER_PATH) -> dict:
    d = _load(ledger_path)
    return {
        "ledger": str(ledger_path),
        "seen_numbers": len(d.get("seen", {})),
        "good_prefixes": sorted(d.get("good", {}).items(), key=lambda kv: -kv[1].get("count", 0))[:10],
        "bad_prefixes": sorted(d.get("bad", {}).items(), key=lambda kv: -kv[1].get("count", 0))[:10],
        "runs": len(d.get("runs", [])),
    }
