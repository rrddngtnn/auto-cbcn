"""harvester.py — CodeBuddy China (CBCN) CLI authentication, task completion, and resource auditing."""
from __future__ import annotations

import datetime
import hashlib
import json
import time
import urllib.parse
import uuid
from pathlib import Path

import requests

from .store import (
    DEFAULT_DB_PATH,
    DEFAULT_ROUTER_URL,
    CredentialBundle,
    decrypt_field,
    dispatch_credential_sink,
    encrypt_field,
    install_cbcn_sqlite,
    load_dotenv_file,
)

load_dotenv_file()

CHAT_BASE_CN = "https://copilot.tencent.com"
BILLING_BASE_CN = "https://www.codebuddy.cn"
WEB_BASE_CN = "https://www.workbuddy.cn"

DESKTOP_VER = "5.9.3"
CLI_VER = "2.165.0"
BILLING_UA = f"WorkBuddy/{DESKTOP_VER}"
DESKTOP_UA = f"WorkBuddy/{DESKTOP_VER} WorkBuddy/{DESKTOP_VER} CLI/{CLI_VER}"
WEB_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"

MP_TASK_CODES = {
    "school_season",
    "Sequential_Tasks_1",
    "Sequential_Tasks_2",
    "Sequential_Tasks_3",
    "Sequential_Tasks_4",
    "Sequential_Tasks_5",
    "Sequential_Tasks_6",
    "Sequential_Tasks_7",
}


def _derive_id(uid: str, salt: str) -> str:
    raw = bytearray(hashlib.md5(f"{salt}:{uid}".encode("utf-8")).digest())
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    h = bytes(raw).hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def create_cbcn_cli_state(timeout: int = 15) -> dict:
    """Create a fresh CBCN CLI device-flow state and return state + login URL."""
    r = requests.post(
        f"{CHAT_BASE_CN}/v2/plugin/auth/state?platform=CLI",
        json={"platform": "CLI"},
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"CLI/{CLI_VER} CodeBuddy/{CLI_VER}",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": BILLING_BASE_CN,
            "Referer": f"{BILLING_BASE_CN}/",
            "X-Domain": "copilot.tencent.com",
            "X-No-Authorization": "true",
            "X-No-User-Id": "true",
            "X-Product": "SaaS",
        },
        timeout=timeout,
    )
    r.raise_for_status()
    body = r.json()
    data = body.get("data") or {}
    state = str(data.get("state") or "")
    if body.get("code") != 0 or not state:
        raise RuntimeError(f"Failed to create CBCN state: {body}")
    return {
        "state": state,
        "auth_url": f"{BILLING_BASE_CN}/login/?platform=CLI&state={state}",
        "raw_auth_url": data.get("authUrl") or "",
    }


def poll_cbcn_cli_token(state: str, timeout: int = 15) -> dict:
    """Poll CBCN CLI state once; if authorized, also fetch uid/nickname from /v2/plugin/login/account."""
    r = requests.get(
        f"{CHAT_BASE_CN}/v2/plugin/auth/token",
        params={"state": state},
        headers={
            "Accept": "application/json",
            "User-Agent": f"CLI/{CLI_VER} CodeBuddy/{CLI_VER}",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": BILLING_BASE_CN,
            "Referer": f"{BILLING_BASE_CN}/",
            "X-Domain": "copilot.tencent.com",
            "X-No-Authorization": "true",
            "X-No-User-Id": "true",
            "X-Product": "SaaS",
        },
        timeout=timeout,
    )
    if not r.ok:
        return {"ok": False, "status": r.status_code}
    body = r.json()
    data = body.get("data") or {}
    if body.get("code") != 0 or not data.get("accessToken"):
        return {"ok": False, "code": body.get("code"), "msg": body.get("msg")}

    access_token = data["accessToken"]
    refresh_token = data.get("refreshToken") or ""
    expires_in = int(data.get("expiresIn") or 5184000)

    uid = ""
    nickname = ""
    enterprise_id = ""
    try:
        ra = requests.get(
            f"{CHAT_BASE_CN}/v2/plugin/login/account",
            params={"state": state},
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "User-Agent": f"CLI/{CLI_VER} CodeBuddy/{CLI_VER}",
                "Origin": BILLING_BASE_CN,
                "Referer": f"{BILLING_BASE_CN}/",
            },
            timeout=timeout,
        )
        if ra.ok:
            adata = ra.json().get("data") or {}
            uid = str(adata.get("uid") or "")
            nickname = str(adata.get("nickname") or "")
            enterprise_id = str(adata.get("enterpriseId") or "")
    except Exception:
        pass

    return {
        "ok": True,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "uid": uid,
        "nickname": nickname,
        "enterprise_id": enterprise_id,
    }


def _billing_headers(access_token: str, uid: str = "", extra: dict | None = None) -> dict:
    h = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": DESKTOP_UA,
        "X-Product": "SaaS",
        "X-Domain": "copilot.tencent.com",
        "x-requested-with": "XMLHttpRequest",
        "x-codebuddy-request": "1",
        "X-Machine-ID": _derive_id(uid or "anon", "machine"),
        "X-Session-ID": _derive_id(uid or "anon", "session"),
    }
    if uid:
        h["X-User-Id"] = uid
    if extra:
        h.update(extra)
    return h


def get_cbcn_user_resource(access_token: str, uid: str = "") -> dict:
    """Fetch user active package summary from /v2/billing/meter/get-user-resource."""
    now = datetime.datetime.now()
    payload = {
        "PageNumber": 1,
        "PageSize": 100,
        "ProductCode": "p_tcaca",
        "Status": [0, 3],
        "PackageEndTimeRangeBegin": now.strftime("%Y-%m-%d %H:%M:%S"),
        "PackageEndTimeRangeEnd": (now + datetime.timedelta(days=3650)).strftime("%Y-%m-%d %H:%M:%S"),
    }
    r = requests.post(
        f"{CHAT_BASE_CN}/v2/billing/meter/get-user-resource",
        json=payload,
        headers=_billing_headers(access_token, uid),
        timeout=15,
    )
    if not r.ok:
        return {"ok": False, "status": r.status_code, "text": r.text[:200]}
    j = r.json()
    if j.get("code") != 0:
        return {"ok": False, "code": j.get("code"), "msg": j.get("msg")}

    accounts = (((j.get("data") or {}).get("Response") or {}).get("Data") or {}).get("Accounts") or []
    total_size = 0.0
    total_remain = 0.0
    packs = []
    for acc in accounts:
        size = float(acc.get("CycleCapacitySizePrecise") or acc.get("CycleCapacitySize") or acc.get("CapacitySizePrecise") or acc.get("CapacitySize") or 0)
        used = float(acc.get("CycleCapacityUsedPrecise") or acc.get("CycleCapacityUsed") or acc.get("CapacityUsedPrecise") or acc.get("CapacityUsed") or 0)
        rem = max(0.0, size - used)
        total_size += size
        total_remain += rem
        packs.append({
            "name": acc.get("PackageName") or acc.get("SubProductName") or "Pack",
            "size": size,
            "used": used,
            "remain": rem,
            "cycle_end": acc.get("CycleEndTime"),
        })
    return {
        "ok": True,
        "pack_count": len(packs),
        "total_credits": total_size,
        "remaining_credits": total_remain,
        "packs": packs,
    }


def harvest_cbcn_safe(access_token: str, uid: str = "") -> dict:
    """Safe non-/v2/report credit harvest (ide/trial, claim-gift, claim-compensation, daily-checkin) with human pacing."""
    log_steps = {}
    hdr = _billing_headers(access_token, uid)
    for label, url in [
        ("ide_trial", f"{BILLING_BASE_CN}/billing/ide/trial"),
        ("claim_gift", f"{BILLING_BASE_CN}/billing/meter/claim-gift"),
        ("claim_compensation", f"{BILLING_BASE_CN}/billing/meter/claim-compensation"),
        ("daily_checkin", f"{BILLING_BASE_CN}/v2/billing/meter/daily-checkin"),
    ]:
        try:
            r = requests.post(url, json={}, headers=hdr, timeout=12)
            log_steps[label] = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.status_code
        except Exception as e:
            log_steps[label] = str(e)
        time.sleep(1.5)
    resource = get_cbcn_user_resource(access_token, uid=uid)
    return {"steps": log_steps, "resource": resource}


def list_growth_tasks(access_token: str, uid: str = "", mp: bool = False) -> list[dict]:
    hdr = _billing_headers(access_token, uid)
    if mp:
        hdr["X-Client-Platform"] = "miniprogram"
    r = requests.get(f"{CHAT_BASE_CN}/v2/activity/growth/tasks", headers=hdr, timeout=12)
    if not r.ok:
        return []
    data = (r.json().get("data") or {}) if isinstance(r.json(), dict) else {}
    return data.get("tasks") or []


def accept_growth_tasks(access_token: str, task_codes: list[str], uid: str = "", mp: bool = False) -> dict:
    hdr = _billing_headers(access_token, uid)
    if mp:
        hdr["X-Client-Platform"] = "miniprogram"
    r = requests.post(f"{CHAT_BASE_CN}/v2/activity/growth/tasks/accept", json={"task_codes": task_codes}, headers=hdr, timeout=12)
    try:
        return r.json()
    except Exception:
        return {"status": r.status_code}


def claim_task_reward(access_token: str, task_code: str, uid: str = "", mp: bool = False) -> dict:
    escaped = urllib.parse.quote(task_code, safe="")
    if mp:
        hdr = _billing_headers(access_token, uid, extra={"X-Client-Platform": "miniprogram"})
        r = requests.post(f"{CHAT_BASE_CN}/activity/growth/tasks/{escaped}/claim", headers=hdr, timeout=12)
        if r.ok:
            try:
                return r.json()
            except Exception:
                pass
    hdr_web = _billing_headers(access_token, uid, extra={"x-client-platform": "web", "Origin": WEB_BASE_CN, "Referer": f"{WEB_BASE_CN}/"})
    r = requests.post(f"{WEB_BASE_CN}/activity/growth/tasks/{escaped}/claim", headers=hdr_web, timeout=12)
    try:
        return r.json()
    except Exception:
        return {"status": r.status_code}


def harvest_cbcn_all(access_token: str, uid: str = "", nickname: str = "User") -> dict:
    """Full 19-bonus-pack harvester across cloud tasks, desktop events, mini-program tasks, and cat travel."""
    safe_res = harvest_cbcn_safe(access_token, uid=uid)
    log_steps = safe_res.get("steps") or {}

    std_tasks = list_growth_tasks(access_token, uid, mp=False)
    mp_tasks = list_growth_tasks(access_token, uid, mp=True)
    std_codes = [t["task_code"] for t in std_tasks if t.get("task_code") and not t.get("locked") and t.get("accept_status") not in ("accepted", "completed", "claimed")]
    mp_codes = [t["task_code"] for t in mp_tasks if t.get("task_code") and not t.get("locked") and t.get("accept_status") not in ("accepted", "completed", "claimed")]
    if std_codes:
        log_steps["accept_std"] = accept_growth_tasks(access_token, std_codes, uid, mp=False)
    if mp_codes:
        log_steps["accept_mp"] = accept_growth_tasks(access_token, mp_codes, uid, mp=True)
    time.sleep(1.5)

    claimed_rewards = []
    all_after = list_growth_tasks(access_token, uid, mp=True) + list_growth_tasks(access_token, uid, mp=False)
    seen_codes = set()
    for t in all_after:
        tcode = t.get("task_code") or ""
        if not tcode or tcode in seen_codes:
            continue
        seen_codes.add(tcode)
        if t.get("accept_status") == "claimed":
            continue
        res = claim_task_reward(access_token, tcode, uid=uid, mp=(tcode in MP_TASK_CODES))
        if res.get("code") == 0 and (res.get("data") or {}):
            claimed_rewards.append({"task_code": tcode, "reward": res.get("data")})

    try:
        requests.post(f"{CHAT_BASE_CN}/activity/growth/buddy/travel/depart", json={"location_id": 1}, headers=_billing_headers(access_token, uid), timeout=10)
    except Exception:
        pass

    resource = get_cbcn_user_resource(access_token, uid=uid)
    return {
        "steps": log_steps,
        "claimed_rewards": claimed_rewards,
        "resource": resource,
    }


def export_bundle(
    access_token: str,
    refresh_token: str = "",
    name: str = "",
    phone: str = "",
    uid: str = "",
    nickname: str = "",
    expires_in: int = 5184000,
    remaining_credits: float = 0.0,
    pack_count: int = 0,
) -> CredentialBundle:
    """Build a portable CredentialBundle for routing to any sink or gateway."""
    return CredentialBundle(
        name=name or nickname or phone or "CBCN-Account",
        phone=phone,
        uid=uid,
        nickname=nickname,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        remaining_credits=remaining_credits,
        pack_count=pack_count,
    )


def install_cbcn_to_db(
    name: str,
    access_token: str,
    refresh_token: str = "",
    expires_in: int = 5184000,
    db_path: str | Path = DEFAULT_DB_PATH,
    secret: str | None = None,
) -> str:
    """Insert or update a CBCN connection into SQLite database via universal sink."""
    b = export_bundle(
        access_token=access_token,
        refresh_token=refresh_token,
        name=name,
        expires_in=expires_in,
    )
    res = dispatch_credential_sink(b, sink=f"sqlite:{db_path}", secret=secret)
    return str(res.get("connection_id") or "")
