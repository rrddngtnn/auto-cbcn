"""cron.py — Universal daily check-in, streak keeper, cat travel, and task drip scheduler.

Supports multiple account sources:
  - SQLite database (StyxRouter, OmniRoute, or custom schema with provider_connections)
  - Credential files (JSON list or JSONL)
  - Directory of account files (e.g. auths/workbuddy-*.json)
  - Environment variables (CBCN_TOKENS=phone:at:rt)

Works cross-platform without requiring StyxRouter or any specific daemon.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import random
import sqlite3
import sys
import time
import uuid
import requests

from .harvester import (
    BILLING_BASE_CN,
    CHAT_BASE_CN,
    MP_TASK_CODES,
    WEB_BASE_CN,
    _billing_headers,
    _derive_id,
    accept_growth_tasks,
    claim_task_reward,
    get_cbcn_user_resource,
    list_growth_tasks,
    refresh_cbcn_token,
)
from .store import (
    DEFAULT_DB_PATH,
    DEFAULT_SALT,
    decrypt_field,
    encrypt_field,
    load_dotenv_file,
    resolve_secret,
)

load_dotenv_file()

SAFE_DRIP_TASKS = [
    "first_buddy",
    "Library_read",
    "playbook_prompt",
    "skill_1",
    "automation_1",
    "template_5",
    "create_canvas",
    "RichMeow_Chat",
    "chat_5",
    "expert_5",
    "Expert_team_use_3",
    "Sequential_Tasks_1",
    "Sequential_Tasks_2",
    "Sequential_Tasks_3",
    "Sequential_Tasks_4",
    "Sequential_Tasks_5",
    "Sequential_Tasks_6",
    "Sequential_Tasks_7",
]


def _jwt_claims(tok: str) -> dict:
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


def _is_11140(code: int, body: dict | str | None) -> bool:
    if isinstance(body, dict):
        c = body.get("code")
        s = json.dumps(body, ensure_ascii=False)
        return c == 11140 or (code == 403 and "账号存在异常行为" in s)
    t = str(body or "")
    return code == 403 and ("11140" in t or "账号存在异常行为" in t)


def run_single_safe_task(
    at: str,
    uid: str,
    nick: str,
    tcode: str,
    is_mp: bool,
    session: requests.Session | None = None,
) -> str:
    """Execute 1 safe growth task using official bare-array payload structure."""
    req = session or requests
    accept_growth_tasks(at, [tcode], uid=uid, mp=is_mp, session=session)
    time.sleep(1.5)
    now_ms = int(time.time() * 1000)
    rid = uuid.uuid4().hex
    cid = uuid.uuid4().hex
    fp = {
        "timezone": "Asia/Shanghai",
        "reportDelay": 2000,
        "userId": uid,
        "username": nick or uid,
        "userNickname": nick or uid,
        "product": "SaaS",
        "releaseDate": 1789036585355,
        "commit": "5f9692923c93033111c51ad7b003eb80204a9b75",
        "ideName": "WorkBuddy",
        "ideType": "WorkBuddy",
        "ideVersion": "5.9.3",
        "machineId": _derive_id(uid or "anon", "machine"),
        "sessionId": _derive_id(uid or "anon", "session"),
        "extName": "workbuddy-desktop",
        "extVersion": "5.9.3",
        "os": "win32",
        "arch": "x64",
        "osVersion": "10.0.26220",
        "cpuCores": 20,
        "memorySize": 24,
        "timestamp": now_ms,
        "presentAt": now_ms,
    }

    if tcode == "first_buddy":
        ev = [{**fp, "eventCode": "chat_request_send", "conversationId": cid, "requestId": rid, "inputLength": 16, "mode": "craft", "agentName": "cli", "agentType": "main", "rootRequestId": rid, "parentConversationId": cid}]
        req.post(f"{CHAT_BASE_CN}/v2/report", json=ev, headers=_billing_headers(at, uid), timeout=15)
        time.sleep(2.0)
        req.post(f"{CHAT_BASE_CN}/activity/growth/buddy/agreement", json={}, headers=_billing_headers(at, uid), timeout=12)
        time.sleep(1.0)
        req.post(f"{CHAT_BASE_CN}/activity/growth/buddy/first", json={}, headers=_billing_headers(at, uid), timeout=12)
    elif tcode == "Library_read":
        doc_url = "https://www.workbuddy.cn/space/d/o0KWYeynteVv06UnAZqIFm"
        ev = [{
            "eventCode": "web_element_click", "timestamp": now_ms, "reportDelay": 0, "pageURL": doc_url,
            "elementId": "library_doc_intro_click", "elementName": "WorkBuddy资料库介绍",
            "os": "Win32", "arch": "", "osVersion": "10.0", "userAgent": "Mozilla/5.0",
            "machineId": _derive_id(uid or "anon", "webmachine"), "userId": uid, "userNickname": nick or uid, "enterpriseId": "",
        }]
        req.post(f"{WEB_BASE_CN}/v2/report", json=ev, headers=_billing_headers(at, uid, {"x-client-platform": "web", "Origin": WEB_BASE_CN, "Referer": doc_url}), timeout=15)
    elif tcode in ("playbook_prompt", "Sequential_Tasks_7"):
        evs = [
            {**fp, "eventCode": "playbook_cta_click", "id": "worker-ledger-freedom-dashboard", "name": "打工人小账本", "type": "document", "source": "discover", "position": 0, "conversationId": cid, "requestId": rid, "messageId": rid},
            {**fp, "eventCode": "playbook_prompt_send", "id": "worker-ledger-freedom-dashboard", "name": "打工人小账本", "type": "document", "promptLength": 30, "isOfficial": 1, "source": "discover", "conversationId": cid, "requestId": rid, "messageId": rid},
        ]
        req.post(f"{CHAT_BASE_CN}/v2/report", json=evs, headers=_billing_headers(at, uid), timeout=15)
    elif tcode == "skill_1":
        evs = [{**fp, "eventCode": "skill_info", "skillId": "skill_2096525080079265792", "name": "pptx"}]
        req.post(f"{CHAT_BASE_CN}/v2/report", json=evs, headers=_billing_headers(at, uid), timeout=15)
    elif tcode == "automation_1":
        evs = [{
            **fp, "eventCode": "automated_task_create_suc", "name": "每周工作整理", "type": "cron",
            "source": "manually", "modelId": "deepseek-v4-flash", "modelIsThinking": False,
            "conversationId": cid, "requestId": rid,
            "schedule": {"type": "recurring", "rrule": "FREQ=WEEKLY;BYDAY=FR;BYHOUR=9;BYMINUTE=0"},
            "prompt": "每周五自动整理本周工作",
        }]
        req.post(f"{CHAT_BASE_CN}/v2/report", json=evs, headers=_billing_headers(at, uid), timeout=15)
    elif tcode == "create_canvas":
        evs = [{
            **fp, "eventCode": "wbx_design_canvas_task_create", "conversationId": cid, "requestId": rid,
            "source": "summon_keyword", "isCustomModel": False, "name": "", "inputLength": 12,
            "id": f"wbx-canvas-{now_ms}", "cost": 0, "isSuccessful": True,
        }]
        req.post(f"{CHAT_BASE_CN}/v2/report", json=evs, headers=_billing_headers(at, uid), timeout=15)
    elif tcode == "template_5":
        for i in range(5):
            ev = [{
                **fp, "eventCode": "agent_task_created_with_template", "isCustomModel": True,
                "id": str(i), "name": "幻灯片", "requestId": f"{rid}{i}", "conversationId": f"{cid}{i}",
            }]
            req.post(f"{CHAT_BASE_CN}/v2/report", json=ev, headers=_billing_headers(at, uid), timeout=15)
            time.sleep(1.1)
    elif tcode == "expert_5":
        experts = [
            ("ex_PZw8Gu81HfN4", "运维工程师"), ("ex_ROsDtJbzADFV", "产品经理"),
            ("ex_SMUnl0nJbPix", "UI设计师"), ("ex_ZTR062oVBOCW", "数据分析师"),
            ("ex_a3sSSFBy8qaC", "后端架构师"),
        ]
        for i, (ex_id, ex_name) in enumerate(experts):
            ev = [{
                **fp, "eventCode": "expert_actual_use", "mode": "CLOUD", "id": ex_id, "name": ex_name,
                "expertTitle": ex_name, "type": "02-Engineering", "expertType": "agent", "source": "builtin",
                "version": "1.0.2", "cost": 0, "characterCount": 12, "conversationId": f"{cid}{i}",
                "requestId": f"{rid}{i}", "messageId": f"{rid}{i}",
                "requestModelId": "deepseek-v4-flash", "requestModelName": "DeepSeek V4 Flash",
            }]
            req.post(f"{CHAT_BASE_CN}/v2/report", json=ev, headers=_billing_headers(at, uid), timeout=15)
            time.sleep(1.1)
    elif tcode == "Expert_team_use_3":
        teams = [("CloudOpsTeam", "运维专家团队"), ("CloudContentTeam", "内容专家团队"), ("CloudDevTeam", "研发专家团队")]
        for i, (tm_id, tm_name) in enumerate(teams):
            ev = [{
                **fp, "eventCode": "expert_actual_use", "mode": "CLOUD", "id": tm_id, "name": tm_name,
                "expertTitle": tm_name, "type": "02-Engineering", "expertType": "team", "source": "builtin",
                "version": "1.0.2", "cost": 0, "characterCount": 12, "conversationId": f"{cid}{i}",
                "requestId": f"{rid}{i}", "messageId": f"{rid}{i}",
                "requestModelId": "deepseek-v4-flash", "requestModelName": "DeepSeek V4 Flash",
            }]
            req.post(f"{CHAT_BASE_CN}/v2/report", json=ev, headers=_billing_headers(at, uid), timeout=15)
            time.sleep(1.1)
    elif tcode in ("RichMeow_Chat", "chat_5"):
        n = 5 if tcode == "chat_5" else 1
        for i in range(n):
            ev = [{**fp, "eventCode": "chat_request_send", "conversationId": cid, "requestId": f"{rid}{i}", "inputLength": 18, "mode": "craft", "agentName": "cli", "agentType": "main", "rootRequestId": f"{rid}{i}", "parentConversationId": cid}]
            req.post(f"{CHAT_BASE_CN}/v2/report", json=ev, headers=_billing_headers(at, uid), timeout=15)
            time.sleep(2.0 if n > 1 else 0.5)
    elif tcode.startswith("Sequential_Tasks_") and tcode != "Sequential_Tasks_7":
        mp_hdr = _billing_headers(at, uid, {"X-Client-Platform": "mp-weixin", "X-Client-Product": "workbuddy-mp", "X-Client-Version": "2.4.0"})
        mp_base = {
            "timestamp": now_ms, "reportDelay": 0, "ideType": "WorkBuddy_MP", "extVersion": "2.2.8",
            "userId": uid, "userNickname": nick or uid, "machineId": _derive_id(uid or "anon", "mpmachine"),
        }
        if tcode == "Sequential_Tasks_2":
            ev = [{**mp_base, "eventCode": "expert_actual_use", "id": "WorkspaceBuilder", "name": "WorkspaceBuilder", "expertTitle": "工作台搭建师", "type": "send_message", "characterCount": 12, "expertType": "agent"}]
            req.post(f"{BILLING_BASE_CN}/v2/report", json=ev, headers=mp_hdr, timeout=15)
        elif tcode == "Sequential_Tasks_4":
            ev = [{**mp_base, "eventCode": "automated_task_create_suc", "mode": "CLOUD", "name": "每日任务提醒", "source": "manually", "skills": "", "skillCount": 0, "scheduleType": "daily"}]
            req.post(f"{BILLING_BASE_CN}/v2/report", json=ev, headers=mp_hdr, timeout=15)
        elif tcode == "Sequential_Tasks_5":
            ev = [{**mp_base, "eventCode": "chat_request_send", "mode": "chat", "inputLength": 14, "conversationId": cid, "rootRequestId": rid, "parentConversationId": cid, "agentName": "mp", "agentType": "main", "requestModelId": "glm-5.2", "requestModelName": "GLM-5.2"}]
            req.post(f"{BILLING_BASE_CN}/v2/report", json=ev, headers=mp_hdr, timeout=15)
        else:
            n = 5 if tcode == "Sequential_Tasks_3" else (10 if tcode == "Sequential_Tasks_6" else 1)
            for i in range(n):
                ev = [{**mp_base, "eventCode": "chat_request_send", "mode": "chat", "inputLength": 14, "conversationId": f"{cid}{i}", "requestId": f"{rid}{i}", "rootRequestId": f"{rid}{i}", "parentConversationId": f"{cid}{i}", "agentName": "mp", "agentType": "main"}]
                req.post(f"{BILLING_BASE_CN}/v2/report", json=ev, headers=mp_hdr, timeout=15)
                if n > 1:
                    time.sleep(1.5)

    time.sleep(3.0)
    after = list_growth_tasks(at, uid=uid, mp=is_mp, session=session)
    matched = [t for t in after if t.get("task_code") == tcode]
    if matched and matched[0].get("accept_status") == "completed":
        c = claim_task_reward(at, tcode, uid=uid, mp=is_mp, session=session)
        return f"claimed:{tcode}:{c.get('code')}"
    st_now = matched[0].get("accept_status") if matched else "missing"
    return f"pending:{tcode}:{st_now}"


def _http_proxies(proxy_url: str | None = None, session_key: str = "") -> dict[str, str] | None:
    raw = (proxy_url or os.environ.get("CBCN_CRON_PROXY") or os.environ.get("CBCN_PROXY_URL") or "").strip()
    if not raw:
        tpl = os.environ.get("PROXY_TEMPLATE", "").strip()
        host = os.environ.get("PROXY_HOST", "").strip()
        user = os.environ.get("PROXY_USER", "").strip()
        pwd = os.environ.get("PROXY_PASS", "").strip()
        if tpl and host and user:
            pmin = int(os.environ.get("PROXY_PORT_MIN", "10000"))
            pmax = int(os.environ.get("PROXY_PORT_MAX", "29999"))
            if session_key:
                h = int(hashlib.md5(session_key.encode("utf-8")).hexdigest()[:8], 16)
                port = pmin + (h % max(1, (pmax - pmin + 1)))
            else:
                port = random.randint(pmin, pmax)
            country = os.environ.get("CBCN_CRON_COUNTRY", "hk").strip() or "hk"
            base_u = user.split(";")[0].split("__")[0]
            raw = tpl.format(user=base_u, password=pwd, host=host, port=port, country=country, ttl=30)
    if not raw:
        return None
    if raw.lower() in ("none", "direct", "off", "false"):
        return None
    if "://" not in raw:
        raw = f"http://{raw}"
    if "{session}" in raw or "{port}" in raw:
        pmin = int(os.environ.get("PROXY_PORT_MIN", "10000"))
        pmax = int(os.environ.get("PROXY_PORT_MAX", "29999"))
        if session_key:
            h = int(hashlib.md5(session_key.encode("utf-8")).hexdigest()[:8], 16)
            port = pmin + (h % max(1, (pmax - pmin + 1)))
            sid = hashlib.md5(session_key.encode("utf-8")).hexdigest()[:10]
        else:
            port = random.randint(pmin, pmax)
            sid = uuid.uuid4().hex[:10]
        raw = raw.replace("{port}", str(port)).replace("{session}", sid)
    return {"http": raw, "https": raw}


def process_account_record(
    acc: dict,
    allow_drip: bool = True,
    allow_refresh: bool = False,
    proxy_url: str | None = None,
) -> dict:
    """Process daily actions for a single CBCN account (checkin, travel, lottery, safe-drip)."""
    at = acc.get("access_token", "")
    rt = acc.get("refresh_token", "")
    name = acc.get("name") or acc.get("phone") or "CBCN-Account"
    claims = _jwt_claims(at)
    uid = str(claims.get("sub") or claims.get("userId") or acc.get("uid") or "")
    nick = str(claims.get("preferred_username") or claims.get("nickname") or acc.get("nickname") or name)

    res: dict = {"name": name, "uid": uid[:8] if uid else "unknown"}
    if not at or not uid:
        res["status"] = "invalid_token_or_uid"
        return res

    sess = requests.Session()
    proxies = _http_proxies(proxy_url, session_key=uid)
    if proxies:
        sess.proxies.update(proxies)
        res["proxy"] = proxies["https"].split("@")[-1]

    # 1. Check resource snapshot & 11140 (optional refresh on 401 if allow_refresh=True)
    res_before = get_cbcn_user_resource(at, uid=uid, session=sess)
    if not res_before.get("ok") and res_before.get("status") == 401 and allow_refresh and rt:
        ref = refresh_cbcn_token(rt, access_token=at, uid=uid, session=sess)
        if ref.get("ok"):
            at = ref["access_token"]
            rt = ref["refresh_token"]
            acc["access_token"] = at
            acc["refresh_token"] = rt
            acc["_refreshed"] = True
            res["refreshed"] = True
            res_before = get_cbcn_user_resource(at, uid=uid, session=sess)

    if not res_before.get("ok"):
        if _is_11140(res_before.get("status", 0), res_before.get("msg") or res_before.get("text")):
            res["status"] = "restricted_11140"
            return res
        res["status"] = f"error_{res_before.get('status')}"
        return res

    res["credits_before"] = res_before.get("remaining_credits", 0.0)

    # 2. Daily checkin (+100 credits)
    try:
        r_chk = sess.post(f"{BILLING_BASE_CN}/v2/billing/meter/daily-checkin", json={}, headers=_billing_headers(at, uid), timeout=12)
        cj = r_chk.json() if r_chk.headers.get("content-type", "").startswith("application/json") else {}
        res["checkin"] = cj.get("msg") or cj.get("code") or r_chk.status_code
        if _is_11140(r_chk.status_code, cj):
            res["status"] = "restricted_11140"
            return res
    except Exception as e:
        res["checkin"] = str(e)[:60]
    time.sleep(1.5)

    # 3. Streak & Lottery
    try:
        rs = sess.get(f"{CHAT_BASE_CN}/activity/growth/streak", headers=_billing_headers(at, uid), timeout=12).json()
        rstat = (rs.get("data") or {}).get("redemption_status") or {}
        for tier in ("7d", "14d", "28d"):
            if rstat.get(f"tier_{tier}_status") == "unlocked":
                sess.post(f"{CHAT_BASE_CN}/activity/growth/redeem", json={"tier": tier, "client_token": str(uuid.uuid4())}, headers=_billing_headers(at, uid), timeout=12)
                res.setdefault("redeemed", []).append(tier)
                time.sleep(1.2)
    except Exception:
        pass

    try:
        rl = sess.get(f"{CHAT_BASE_CN}/activity/growth/lottery/summary", headers=_billing_headers(at, uid), timeout=12).json()
        chances = int((rl.get("data") or {}).get("chances") or 0)
        for _ in range(min(chances, 3)):
            sess.post(f"{CHAT_BASE_CN}/activity/growth/lottery/draw", json={"client_token": str(uuid.uuid4())}, headers=_billing_headers(at, uid), timeout=12)
            res["lottery_draws"] = res.get("lottery_draws", 0) + 1
            time.sleep(1.2)
    except Exception:
        pass

    # 4. Buddy Cat Travel
    try:
        bi = sess.get(f"{CHAT_BASE_CN}/activity/growth/buddy/info", headers=_billing_headers(at, uid), timeout=12).json()
        if (bi.get("data") or {}).get("buddy"):
            ts = sess.get(f"{CHAT_BASE_CN}/activity/growth/buddy/travel/status", headers=_billing_headers(at, uid), timeout=12).json().get("data") or {}
            if ts.get("state") == "arrived" and ts.get("record_id"):
                sess.post(f"{CHAT_BASE_CN}/activity/growth/buddy/travel/claim", json={"record_id": ts["record_id"]}, headers=_billing_headers(at, uid), timeout=12)
                res["travel"] = "claimed"
                time.sleep(1.5)
                ts = sess.get(f"{CHAT_BASE_CN}/activity/growth/buddy/travel/status", headers=_billing_headers(at, uid), timeout=12).json().get("data") or {}
            if ts.get("state") == "idle" and not ts.get("daily_limit_reached"):
                sess.post(f"{CHAT_BASE_CN}/activity/growth/buddy/travel/depart", json={"location_id": random.randint(1, 4)}, headers=_billing_headers(at, uid), timeout=12)
                res["travel"] = res.get("travel", "") + "+departed"
    except Exception:
        pass

    # 4b. Buddy Energy Blindbox
    try:
        q_res = sess.get(f"{CHAT_BASE_CN}/v2/activity/growth/buddy/quota", headers=_billing_headers(at, uid), timeout=10).json()
        q_data = (q_res.get("data") or {}) if q_res.get("code") == 0 else {}
        aff = int(q_data.get("affordable") or 0)
        if aff > 0:
            cnt = min(aff, max(1, int(q_data.get("max_open_count") or 1)))
            o_res = sess.post(f"{CHAT_BASE_CN}/v2/activity/growth/buddy/open", json={"count": cnt, "client_token": str(uuid.uuid4())}, headers=_billing_headers(at, uid), timeout=12).json()
            if o_res.get("code") == 0:
                res["blindbox_opened"] = cnt
    except Exception:
        pass

    # 5. Safe Drip Growth Task (if account age >= 24h)
    age_hours = 999.0
    if acc.get("created_at"):
        try:
            c_dt = datetime.datetime.fromisoformat(str(acc["created_at"]).replace("Z", "+00:00"))
            age_hours = (datetime.datetime.now(datetime.timezone.utc) - c_dt).total_seconds() / 3600.0
        except Exception:
            pass

    if allow_drip and age_hours >= 24.0:
        std = list_growth_tasks(at, uid=uid, mp=False, session=sess)
        mp = list_growth_tasks(at, uid=uid, mp=True, session=sess)
        by_code = {t["task_code"]: (t, False) for t in std if t.get("task_code")}
        for t in mp:
            tc = t.get("task_code")
            if tc and tc not in by_code:
                by_code[tc] = (t, tc in MP_TASK_CODES)

        for tc in SAFE_DRIP_TASKS:
            if tc not in by_code:
                continue
            t, is_mp = by_code[tc]
            if t.get("locked") or t.get("accept_status") == "claimed":
                continue
            if t.get("accept_status") == "completed":
                c = claim_task_reward(at, tc, uid=uid, mp=is_mp, session=sess)
                res["drip_task"] = f"claimed_existing:{tc}:{c.get('code')}"
            else:
                res["drip_task"] = run_single_safe_task(at, uid, nick, tc, is_mp, session=sess)
            break
    elif age_hours < 24.0:
        res["drip_task"] = f"quiet_period_skip({age_hours:.1f}h<24h)"

    res_after = get_cbcn_user_resource(at, uid=uid, session=sess)
    res["credits_after"] = res_after.get("remaining_credits", res.get("credits_before", 0.0))
    res["status"] = "ok"
    return res


def load_accounts_from_source(source: str, secret: str | None = None, salt: bytes = DEFAULT_SALT) -> list[dict]:
    """Universal account loader from SQLite, file (JSON/JSONL), directory, or env."""
    accounts = []
    if source.startswith("sqlite:") or (source == "sqlite") or Path(source).suffix in (".sqlite", ".db"):
        db_path = Path(source[len("sqlite:"):]) if source.startswith("sqlite:") else Path(source if source != "sqlite" else DEFAULT_DB_PATH)
        if not db_path.is_file():
            return []
        con = sqlite3.connect(str(db_path), timeout=30)
        con.row_factory = sqlite3.Row
        try:
            sec = resolve_secret(secret)
            rows = con.execute(
                "SELECT id, name, access_token, refresh_token, created_at, is_active, test_status, error_code, last_error "
                "FROM provider_connections WHERE provider='codebuddy-cn'"
            ).fetchall()
            for r in rows:
                if not r["is_active"]:
                    continue
                if str(r["error_code"] or "") == "403" or "11140" in str(r["last_error"] or ""):
                    continue
                at = decrypt_field(r["access_token"], secret=sec, salt=salt)
                rt = decrypt_field(r["refresh_token"], secret=sec, salt=salt)
                accounts.append({
                    "id": r["id"],
                    "name": r["name"],
                    "access_token": at,
                    "refresh_token": rt,
                    "created_at": r["created_at"],
                    "test_status": r["test_status"],
                    "error_code": r["error_code"],
                    "source": "sqlite",
                    "db_path": str(db_path),
                })
        finally:
            con.close()
        return accounts

    raw_path = source
    if source.startswith("file:"):
        raw_path = source[len("file:"):]
    elif source.startswith("dir:"):
        raw_path = source[len("dir:"):]

    p = Path(raw_path)
    if p.is_file():
        text = p.read_text(encoding="utf-8").strip()
        if text.startswith("["):
            data = json.loads(text)
            for item in data:
                if isinstance(item, dict) and item.get("access_token"):
                    accounts.append(item)
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("{"):
                    try:
                        accounts.append(json.loads(line))
                    except Exception:
                        pass
                elif ":" in line:
                    parts = line.split(":")
                    if len(parts) >= 3:
                        accounts.append({"phone": parts[0], "access_token": parts[1], "refresh_token": parts[2]})
                    elif len(parts) == 2:
                        accounts.append({"name": parts[0], "access_token": parts[1]})
        return accounts

    if p.is_dir():
        for fp_file in sorted(p.glob("*.json")):
            try:
                d = json.loads(fp_file.read_text(encoding="utf-8"))
                if isinstance(d, dict) and (d.get("access_token") or (d.get("auth") or {}).get("accessToken")):
                    at = d.get("access_token") or d["auth"]["accessToken"]
                    rt = d.get("refresh_token") or (d.get("auth") or {}).get("refreshToken") or ""
                    nick = d.get("nickname") or (d.get("account") or {}).get("nickname") or fp_file.stem
                    uid = d.get("uid") or (d.get("account") or {}).get("uid") or ""
                    accounts.append({"name": nick, "access_token": at, "refresh_token": rt, "uid": uid, "created_at": d.get("created_at")})
            except Exception:
                pass
        return accounts

    raw_env = os.environ.get("CBCN_TOKENS", "").strip()
    if raw_env:
        for line in raw_env.splitlines():
            line = line.strip()
            if ":" in line:
                parts = line.split(":")
                accounts.append({"phone": parts[0], "access_token": parts[1], "refresh_token": parts[2] if len(parts) > 2 else ""})
    return accounts


def execute_cron_pass(
    source: str = "sqlite",
    secret: str | None = None,
    salt: bytes = DEFAULT_SALT,
    allow_drip: bool = True,
    allow_refresh: bool = False,
    proxy_url: str | None = None,
) -> dict:
    """Run universal daily cron pass across all resolved CBCN accounts."""
    accounts = load_accounts_from_source(source, secret=secret, salt=salt)
    results = []
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for i, acc in enumerate(accounts):
        if i > 0:
            time.sleep(random.uniform(4.0, 9.0))
        r = process_account_record(acc, allow_drip=allow_drip, allow_refresh=allow_refresh, proxy_url=proxy_url)

        if acc.get("source") == "sqlite" and acc.get("id"):
            db_p = acc.get("db_path") or DEFAULT_DB_PATH
            con = sqlite3.connect(str(db_p), timeout=30)
            try:
                now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                if acc.get("_refreshed"):
                    enc_at = encrypt_field(acc["access_token"], secret=secret, salt=salt)
                    enc_rt = encrypt_field(acc["refresh_token"], secret=secret, salt=salt)
                    con.execute(
                        "UPDATE provider_connections SET access_token=?, refresh_token=?, updated_at=? WHERE id=?",
                        (enc_at, enc_rt, now_iso, acc["id"]),
                    )
                    con.commit()
                if r.get("status") == "restricted_11140":
                    con.execute(
                        "UPDATE provider_connections SET test_status='unavailable', error_code='403', last_error='11140 restricted', updated_at=? WHERE id=?",
                        (now_iso, acc["id"]),
                    )
                    con.commit()
                elif (
                    r.get("status") == "ok"
                    and float(r.get("credits_after", 0)) > 0
                    and acc.get("test_status") == "unavailable"
                    and str(acc.get("error_code") or "") == "429"
                ):
                    con.execute(
                        "UPDATE provider_connections SET test_status='active', error_code=NULL, last_error=NULL, rate_limited_until=NULL, updated_at=? WHERE id=?",
                        (now_iso, acc["id"]),
                    )
                    con.commit()
                    r["revived_in_db"] = True
            finally:
                con.close()

        results.append(r)

    return {
        "timestamp": ts,
        "source": source,
        "scanned": len(accounts),
        "results": results,
    }


def print_crontab_snippet(python_bin: str = sys.executable, source: str = "sqlite") -> None:
    print("# === auto-cbcn universal cronjob (run at 09:15 and 21:15 daily) ===")
    print(f"15 9,21 * * * {python_bin} -m auto_cbcn.cli cron --run --source {source} >> /var/log/auto-cbcn.log 2>&1")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="auto-cbcn cron", description="Universal CBCN Daily Maintenance Scheduler")
    ap.add_argument("--source", default="sqlite", help="Account source: sqlite, sqlite:<path>, file:<path>, or dir:<path>")
    ap.add_argument("--run", action="store_true", help="Execute single cron pass immediately")
    ap.add_argument("--daemon", action="store_true", help="Run indefinitely in background daemon mode")
    ap.add_argument("--interval", type=int, default=43200, help="Daemon sleep interval in seconds (default: 43200 = 12h)")
    ap.add_argument("--print-cron", action="store_true", help="Print crontab configuration line")
    ap.add_argument("--no-drip", action="store_true", help="Skip growth task dripping (run check-in and travel only)")
    ap.add_argument("--allow-refresh", action="store_true", help="Allow refreshing 401 tokens (only for standalone sources without router auto-refresh)")
    ap.add_argument("--proxy-url", default="", help="Optional HTTP/SOCKS proxy URL for cron requests (or set CBCN_CRON_PROXY / PROXY_TEMPLATE)")
    args = ap.parse_args(argv)

    if args.print_cron:
        print_crontab_snippet(source=args.source)
        return 0

    if args.daemon:
        print(f"[DAEMON] Starting universal auto-cbcn daemon (interval: {args.interval}s, source: {args.source})", flush=True)
        while True:
            try:
                res = execute_cron_pass(source=args.source, allow_drip=not args.no_drip, allow_refresh=args.allow_refresh, proxy_url=args.proxy_url or None)
                print(json.dumps(res, indent=2, ensure_ascii=False), flush=True)
            except Exception as e:
                print(f"[DAEMON ERROR] {e}", file=sys.stderr, flush=True)
            time.sleep(args.interval)

    res = execute_cron_pass(source=args.source, allow_drip=not args.no_drip, allow_refresh=args.allow_refresh, proxy_url=args.proxy_url or None)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
