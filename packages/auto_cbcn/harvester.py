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


def get_cbcn_user_resource(access_token: str, uid: str = "", session: requests.Session | None = None) -> dict:
    """Fetch user active package summary from /v2/billing/meter/get-user-resource."""
    req = session or requests
    now = datetime.datetime.now()
    payload = {
        "PageNumber": 1,
        "PageSize": 100,
        "ProductCode": "p_tcaca",
        "Status": [0, 3],
        "PackageEndTimeRangeBegin": now.strftime("%Y-%m-%d %H:%M:%S"),
        "PackageEndTimeRangeEnd": (now + datetime.timedelta(days=3650)).strftime("%Y-%m-%d %H:%M:%S"),
    }
    r = req.post(
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


def list_growth_tasks(access_token: str, uid: str = "", mp: bool = False, session: requests.Session | None = None) -> list[dict]:
    req = session or requests
    hdr = _billing_headers(access_token, uid)
    if mp:
        hdr["X-Client-Platform"] = "miniprogram"
    r = req.get(f"{CHAT_BASE_CN}/v2/activity/growth/tasks", headers=hdr, timeout=12)
    if not r.ok:
        return []
    data = (r.json().get("data") or {}) if isinstance(r.json(), dict) else {}
    return data.get("tasks") or []


def accept_growth_tasks(access_token: str, task_codes: list[str], uid: str = "", mp: bool = False, session: requests.Session | None = None) -> dict:
    req = session or requests
    hdr = _billing_headers(access_token, uid)
    if mp:
        hdr["X-Client-Platform"] = "miniprogram"
    r = req.post(f"{CHAT_BASE_CN}/v2/activity/growth/tasks/accept", json={"task_codes": task_codes}, headers=hdr, timeout=12)
    try:
        return r.json()
    except Exception:
        return {"status": r.status_code}


def claim_task_reward(access_token: str, task_code: str, uid: str = "", mp: bool = False, session: requests.Session | None = None) -> dict:
    req = session or requests
    escaped = urllib.parse.quote(task_code, safe="")
    if mp:
        hdr = _billing_headers(access_token, uid, extra={"X-Client-Platform": "miniprogram"})
        r = req.post(f"{CHAT_BASE_CN}/activity/growth/tasks/{escaped}/claim", headers=hdr, timeout=12)
        if r.ok:
            try:
                return r.json()
            except Exception:
                pass
    hdr_web = _billing_headers(access_token, uid, extra={"x-client-platform": "web", "Origin": WEB_BASE_CN, "Referer": f"{WEB_BASE_CN}/"})
    r = req.post(f"{WEB_BASE_CN}/activity/growth/tasks/{escaped}/claim", headers=hdr_web, timeout=12)
    try:
        return r.json()
    except Exception:
        return {"status": r.status_code}


def refresh_cbcn_token(refresh_token: str, access_token: str = "", uid: str = "", timeout: int = 20, session: requests.Session | None = None) -> dict:
    """Refresh CBCN OAuth credentials (single-use RT rotation!)."""
    req = session or requests
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": f"CLI/{CLI_VER} CodeBuddy/{CLI_VER}",
        "X-Refresh-Token": refresh_token,
        "X-Auth-Refresh-Source": "plugin",
        "X-Product": "SaaS",
        "X-Domain": "copilot.tencent.com",
    }
    if access_token:
        hdrs["Authorization"] = f"Bearer {access_token}"
    if uid:
        hdrs["X-User-Id"] = uid
    r = req.post(f"{CHAT_BASE_CN}/v2/plugin/auth/token/refresh", json={}, headers=hdrs, timeout=timeout)
    if not r.ok:
        return {"ok": False, "status": r.status_code, "text": r.text[:200]}
    body = r.json()
    data = body.get("data") or {}
    if body.get("code") != 0 or not data.get("accessToken"):
        return {"ok": False, "code": body.get("code"), "msg": body.get("msg")}
    return {
        "ok": True,
        "access_token": data["accessToken"],
        "refresh_token": data.get("refreshToken") or refresh_token,
        "expires_in": int(data.get("expiresIn") or 5184000),
    }


def _desktop_fingerprint(uid: str, nickname: str = "User") -> dict:
    now = int(time.time() * 1000)
    return {
        "timezone": "Asia/Shanghai",
        "reportDelay": 2000,
        "userId": uid,
        "username": nickname or uid,
        "userNickname": nickname or uid,
        "product": "SaaS",
        "releaseDate": 1789036585355,
        "commit": "5f9692923c93033111c51ad7b003eb80204a9b75",
        "ideName": "WorkBuddy",
        "ideType": "WorkBuddy",
        "ideVersion": DESKTOP_VER,
        "machineId": _derive_id(uid or "anon", "machine"),
        "sessionId": _derive_id(uid or "anon", "session"),
        "extName": "workbuddy-desktop",
        "extVersion": DESKTOP_VER,
        "os": "win32",
        "arch": "x64",
        "osVersion": "10.0.26220",
        "cpuCores": 20,
        "memorySize": 24,
        "timestamp": now,
        "presentAt": now,
    }


def harvest_cbcn_all(access_token: str, uid: str = "", nickname: str = "User") -> dict:
    """Full bonus-pack harvester across cloud tasks, desktop events, mini-program tasks, and cat travel."""
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

    hdr = _billing_headers(access_token, uid)
    fp = _desktop_fingerprint(uid, nickname)
    ms = int(time.time() * 1000)

    # Desktop chat_5 + first_buddy + template_5 + playbook + Buddy_App
    for i in range(5):
        cid = uuid.uuid4().hex
        rid = uuid.uuid4().hex
        ev = [{**fp, "eventCode": "chat_request_send", "mode": "craft", "conversationId": cid, "requestId": rid, "rootRequestId": rid, "parentConversationId": cid, "inputLength": 14, "agentName": "cli", "agentType": "main"}]
        try:
            requests.post(f"{CHAT_BASE_CN}/v2/report", json=ev, headers=hdr, timeout=10)
        except Exception:
            pass
        time.sleep(1.0)

    desktop_evs = [
        {**fp, "eventCode": "playbook_cta_click", "id": "worker-ledger-freedom-dashboard", "name": "打工人小账本", "type": "document", "source": "discover", "position": 0, "conversationId": uuid.uuid4().hex, "requestId": uuid.uuid4().hex},
        {**fp, "eventCode": "playbook_prompt_send", "id": "worker-ledger-freedom-dashboard", "name": "打工人小账本", "type": "document", "promptLength": 30, "isOfficial": 1, "source": "discover", "conversationId": uuid.uuid4().hex, "requestId": uuid.uuid4().hex},
        {**fp, "eventCode": "wbx_design_canvas_task_create", "conversationId": uuid.uuid4().hex, "requestId": uuid.uuid4().hex, "source": "summon_keyword", "isCustomModel": False, "name": "", "inputLength": 12, "id": f"wbx-canvas-{ms}", "cost": 0, "isSuccessful": True},
        {**fp, "eventCode": "skill_info", "skillId": "skill_2096525080079265792", "name": "pptx"},
        {**fp, "eventCode": "automated_task_create_suc", "name": "每周工作整理", "type": "cron", "source": "manually", "modelId": "deepseek-v4-flash", "modelIsThinking": False, "conversationId": uuid.uuid4().hex, "requestId": uuid.uuid4().hex, "schedule": {"type": "recurring", "rrule": "FREQ=WEEKLY;BYDAY=FR;BYHOUR=9;BYMINUTE=0"}, "prompt": "每周五自动整理本周工作"},
    ]
    for tidx in range(5):
        desktop_evs.append({**fp, "eventCode": "agent_task_created_with_template", "isCustomModel": True, "id": str(tidx), "name": "幻灯片", "requestId": uuid.uuid4().hex, "conversationId": uuid.uuid4().hex})
    for ex_id, ex_name in [
        ("ex_PZw8Gu81HfN4", "运维工程师"), ("ex_ROsDtJbzADFV", "产品经理"),
        ("ex_SMUnl0nJbPix", "UI设计师"), ("ex_ZTR062oVBOCW", "数据分析师"),
        ("ex_a3sSSFBy8qaC", "后端架构师"),
    ]:
        desktop_evs.append({**fp, "eventCode": "expert_actual_use", "mode": "CLOUD", "id": ex_id, "name": ex_name, "expertTitle": ex_name, "type": "02-Engineering", "expertType": "agent", "source": "builtin", "version": "1.0.2", "cost": 0, "characterCount": 12, "conversationId": uuid.uuid4().hex, "requestId": uuid.uuid4().hex, "requestModelId": "deepseek-v4-flash", "requestModelName": "DeepSeek V4 Flash"})
    for tm_id, tm_name in [("CloudOpsTeam", "运维专家团队"), ("CloudContentTeam", "内容专家团队"), ("CloudDevTeam", "研发专家团队")]:
        desktop_evs.append({**fp, "eventCode": "expert_actual_use", "mode": "CLOUD", "id": tm_id, "name": tm_name, "expertTitle": tm_name, "type": "02-Engineering", "expertType": "team", "source": "builtin", "version": "1.0.2", "cost": 0, "characterCount": 12, "conversationId": uuid.uuid4().hex, "requestId": uuid.uuid4().hex, "requestModelId": "deepseek-v4-flash", "requestModelName": "DeepSeek V4 Flash"})
    try:
        requests.post(f"{CHAT_BASE_CN}/v2/report", json=desktop_evs, headers=hdr, timeout=12)
    except Exception:
        pass

    # Adopt buddy & read library doc
    for b_url in (f"{CHAT_BASE_CN}/activity/growth/buddy/agreement", f"{CHAT_BASE_CN}/activity/growth/buddy/first"):
        try:
            requests.post(b_url, json={}, headers=hdr, timeout=10)
        except Exception:
            pass

    try:
        doc_url = "https://www.workbuddy.cn/space/d/o0KWYeynteVv06UnAZqIFm"
        web_ev = [{
            "eventCode": "web_element_click", "timestamp": ms, "reportDelay": 0, "pageURL": doc_url,
            "elementId": "library_doc_intro_click", "elementName": "WorkBuddy资料库介绍",
            "os": "Win32", "arch": "", "osVersion": "10.0", "userAgent": WEB_UA,
            "machineId": _derive_id(uid or "anon", "webmachine"), "userId": uid, "userNickname": nickname or uid, "enterpriseId": "",
        }]
        requests.post(f"{WEB_BASE_CN}/v2/report", json=web_ev, headers=_billing_headers(access_token, uid, {"x-client-platform": "web", "Origin": WEB_BASE_CN, "Referer": doc_url, "User-Agent": WEB_UA}), timeout=10)
    except Exception:
        pass

    # Mini-program event
    try:
        mp_ev = [{
            "eventCode": "chat_request_send", "timestamp": ms, "reportDelay": 0,
            "ideType": "WorkBuddy_MP", "extVersion": "2.2.8", "userId": uid,
            "userNickname": nickname or uid, "machineId": _derive_id(uid or "anon", "mpmachine"),
            "inputLength": 14, "conversationId": uuid.uuid4().hex, "rootRequestId": uuid.uuid4().hex,
            "parentConversationId": uuid.uuid4().hex, "agentName": "mp", "agentType": "main",
        }]
        requests.post(f"{BILLING_BASE_CN}/v2/report", json=mp_ev, headers=_billing_headers(access_token, uid, {"X-Client-Platform": "mp-weixin", "X-Client-Product": "workbuddy-mp", "Origin": BILLING_BASE_CN, "Referer": f"{BILLING_BASE_CN}/"}), timeout=10)
    except Exception:
        pass

    time.sleep(3.5)
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
        requests.post(f"{CHAT_BASE_CN}/activity/growth/buddy/travel/depart", json={"location_id": 1}, headers=hdr, timeout=10)
    except Exception:
        pass
    try:
        q = requests.get(f"{CHAT_BASE_CN}/v2/activity/growth/buddy/quota", headers=hdr, timeout=10).json().get("data") or {}
        aff = int(q.get("affordable") or 0)
        if aff > 0:
            cnt = min(aff, max(1, int(q.get("max_open_count") or 1)))
            requests.post(f"{CHAT_BASE_CN}/v2/activity/growth/buddy/open", json={"count": cnt, "client_token": str(uuid.uuid4())}, headers=hdr, timeout=10)
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
