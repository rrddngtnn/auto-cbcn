"""engine.py — Core browser automation engine for CBCN registration and verification."""
from __future__ import annotations

import json
import os
import re
import time

from .fingerprint import is_recycled_suspect, prefix_of, record_attempt
from .harvester import (
    create_cbcn_cli_state,
    export_bundle,
    harvest_cbcn_all,
    harvest_cbcn_safe,
    install_cbcn_to_db,
    poll_cbcn_cli_token,
)
from .solver import (
    RentedPhone,
    build_sms_client,
    human_drag,
    probe_cbcn_inference,
    resolve_proxy_playwright_cfg,
    solve_tcaptcha_dx,
)
from .store import DEFAULT_DB_PATH, dispatch_credential_sink, load_dotenv_file

load_dotenv_file()


def open_phone_tab(page, auth_url: str, tries: int = 4) -> bool:
    for _ in range(tries):
        try:
            page.goto(auth_url, wait_until="commit", timeout=35000)
        except Exception:
            pass
        try:
            page.get_by_text("手机号", exact=True).wait_for(state="visible", timeout=45000)
            page.get_by_text("手机号", exact=True).click()
            page.locator("input[placeholder='请输入手机号']").wait_for(state="visible", timeout=15000)
            page.wait_for_timeout(400)
            return True
        except Exception:
            page.wait_for_timeout(1500)
    return False


def solve_slider(page, cap_store: dict, verify_results: list[str], sms_results: list[tuple[int, str]]) -> tuple[bool, list[str]]:
    logs: list[str] = []
    page.locator("button.oneid-react-verify-code__code-btn").click()
    for t_idx in range(4):
        cap_frame = None
        for w_idx in range(60):
            page.wait_for_timeout(400)
            if any('"status":"unexpired"' in s[1] or '"status":"ok"' in s[1] for s in sms_results):
                return True, logs
            if any('"errCode"' in s[1] for s in sms_results):
                logs.append("sms_err:" + [s[1] for s in sms_results if '"errCode"' in s[1]][-1][:140])
                return False, logs
            for f in page.frames:
                if "drag_ele" in f.url or "captcha" in f.url:
                    cap_frame = f
                    break
            if cap_frame and all(k in cap_store for k in ("pre", "bg", "sp")):
                break
            if w_idx >= 25 and cap_frame and "pre" in cap_store and ("bg" not in cap_store or "sp" not in cap_store):
                try:
                    dyn = cap_store["pre"]["data"]["dyn_show_info"]
                    bgu = dyn["bg_elem_cfg"]["img_url"]
                    spu = dyn["sprite_url"]
                    if bgu.startswith("/"):
                        bgu = "https://t.captcha.qq.com" + bgu
                    if spu.startswith("/"):
                        spu = "https://t.captcha.qq.com" + spu
                    if "bg" not in cap_store and bgu:
                        cap_store["bg"] = page.request.get(bgu, timeout=12000).body()
                    if "sp" not in cap_store and spu:
                        cap_store["sp"] = page.request.get(spu, timeout=12000).body()
                    if all(k in cap_store for k in ("pre", "bg", "sp")):
                        break
                except Exception:
                    pass

        if not cap_frame or not all(k in cap_store for k in ("pre", "bg", "sp")):
            logs.append(f"t{t_idx}:missing(frame={bool(cap_frame)},keys={list(cap_store.keys())})")
            return False, logs

        page.wait_for_timeout(500)
        s = solve_tcaptcha_dx(cap_store["pre"], cap_store["bg"], cap_store["sp"])
        sb = cap_frame.locator("#slideBg").bounding_box()
        tb = cap_frame.locator(".tc-slider-normal").bounding_box()
        if not sb or not tb:
            logs.append(f"t{t_idx}:no_bbox")
            return False, logs

        dx_dom = s["delta_orig"] * (sb["width"] / s["bg_w"])
        prev_v = len(verify_results)
        human_drag(page, tb["x"] + tb["width"] / 2, tb["y"] + tb["height"] / 2, dx_dom)
        page.wait_for_timeout(4500)
        cap_store.pop("bg", None)
        cap_store.pop("sp", None)

        new_v = verify_results[prev_v:]
        if any('"errorCode":"0"' in v for v in new_v):
            page.wait_for_timeout(1800)
            if any('"status":"unexpired"' in s[1] or '"status":"ok"' in s[1] for s in sms_results):
                return True, logs
            if any('"errCode"' in s[1] for s in sms_results):
                logs.append("post_cap_sms_err:" + [s[1] for s in sms_results if '"errCode"' in s[1]][-1][:140])
                return False, logs
            page.wait_for_timeout(1500)
            return any('"status":"unexpired"' in s[1] or '"status":"ok"' in s[1] for s in sms_results), logs
    return False, logs


def register_cbcn(
    pid: int = 11751,
    mode: int | None = 2,
    area_code: str = "+86",
    isp: str | None = None,
    proxy_country: str = "hk",
    sms_provider: str = "feihu",
    sms_keyword: str = "腾讯科技",
    channel_uid: str = "21986-HBY3OAE45E",
    fresh_only: bool = False,
    block_bind: bool = False,
    precheck: bool = True,
    safe_harvest: bool = True,
    skip_harvest: bool = False,
    min_credits: float = 2000.0,
    otp_timeout: int = 60,
    max_attempts: int = 3,
    sink: str = "sqlite",
    proxy_url: str | None = None,
) -> dict:
    """Execute end-to-end automated CBCN account registration, captcha solving, and harvest."""
    from camoufox.sync_api import Camoufox

    deps_dir = os.path.expanduser("~/.local/lib/chromium-deps")
    if os.path.isdir(deps_dir):
        ld = os.environ.get("LD_LIBRARY_PATH", "")
        if deps_dir not in ld:
            os.environ["LD_LIBRARY_PATH"] = f"{deps_dir}:{ld}" if ld else deps_dir

    sms_client = build_sms_client(sms_provider)
    sms_client.login()
    st_info = create_cbcn_cli_state()

    out: dict = {
        "ok": False,
        "sms_provider": sms_provider,
        "pid": pid,
        "mode": mode,
        "area_code": area_code,
        "isp_filter": isp,
        "proxy_country": proxy_country,
        "fresh_only": fresh_only,
        "block_bind": block_bind,
        "safe_harvest": safe_harvest,
        "skip_harvest": skip_harvest,
        "min_credits": min_credits,
        "attempts": [],
    }

    active_order: dict[str, str | None] = {"id": None}
    try:
        for _proxy_try in range(3):
            proxy_cfg = resolve_proxy_playwright_cfg(proxy_url, country=proxy_country)
            with Camoufox(headless=True, proxy=proxy_cfg, geoip=False) as browser:
                page = browser.new_page()
                page.route("**/*.woa.com/**", lambda r: r.abort())
                cap_store, verify_results, sms_results = {}, [], []
                blocked_count = {"n": 0}

                def intercept_cap(route):
                    try:
                        resp = route.fetch()
                        body = resp.body()
                        url = route.request.url
                        if "cap_union_prehandle" in url:
                            m = re.search(r"(\{.*\})", body.decode("utf-8", "replace"), re.DOTALL)
                            if m:
                                cap_store["pre"] = json.loads(m.group(1))
                        elif "img_index=1" in url:
                            cap_store["bg"] = body
                        elif "img_index=0" in url:
                            cap_store["sp"] = body
                        elif "cap_union_new_verify" in url:
                            verify_results.append(body.decode("utf-8", "replace"))
                        route.fulfill(response=resp, body=body)
                    except Exception:
                        try:
                            route.abort()
                        except Exception:
                            pass

                for pat in ("**/cap_union_prehandle*", "**/cap_union_new_getcapbysig*", "**/cap_union_new_verify*", "**/*img_index=*"):
                    page.route(pat, intercept_cap)

                def on_resp(r):
                    if "sms/code/send" in r.url:
                        try:
                            sms_results.append((r.status, r.text()[:400]))
                        except Exception:
                            pass

                page.on("response", on_resp)

                if not open_phone_tab(page, st_info["auth_url"], tries=2):
                    print(f"[ENGINE] open_phone_tab failed on proxy try {_proxy_try+1}, rotating...", flush=True)
                    continue

                for att_idx in range(max_attempts):
                    att: dict = {"attempt": att_idx + 1}
                    rent: RentedPhone | None = None
                    for _rent_try in range(6):
                        cand = sms_client.rent_phone(
                            pid=pid,
                            area_code=area_code,
                            mode=mode,
                            card_type="1",
                            isp=isp,
                            keyword=sms_keyword,
                            channel_uid=channel_uid,
                            fresh_only=fresh_only,
                        )
                        if not cand:
                            break
                        if precheck:
                            bad, why = is_recycled_suspect(cand.phone)
                            if bad:
                                sms_client.release(cand.order_id)
                                att.setdefault("skipped", []).append(f"{cand.phone}:{why}")
                                continue
                        rent = cand
                        break

                    if not rent:
                        att["error"] = "rent_failed"
                        out["attempts"].append(att)
                        continue

                    active_order["id"] = rent.order_id
                    att.update(
                        phone=rent.phone,
                        area=rent.area_code,
                        isp=rent.isp,
                        prov=rent.province,
                        prefix=prefix_of(rent.phone),
                    )
                    sms_results.clear()
                    verify_results.clear()
                    cap_store.clear()

                    if page.locator("input[placeholder='请输入手机号']").count() == 0 or page.locator("#tcaptcha_iframe_dy").count() > 0 or att_idx > 0:
                        st_info = create_cbcn_cli_state()
                        if not open_phone_tab(page, st_info["auth_url"], tries=3):
                            sms_client.release(rent.order_id)
                            active_order["id"] = None
                            att["error"] = "tab_lost"
                            out["attempts"].append(att)
                            continue
                    else:
                        page.locator("input[placeholder='请输入手机号']").fill("")
                        code_box = page.locator("input[placeholder='请输入验证码']")
                        if code_box.count() > 0:
                            code_box.fill("")

                    sel = page.locator(".oneid-react-area-code-phone__code-select")
                    cur = sel.inner_text() if sel.count() else ""
                    if rent.area_code not in cur:
                        sel.click()
                        page.wait_for_timeout(400)
                        page.get_by_text(rent.area_code).last.click()
                        page.wait_for_timeout(300)

                    chk = page.locator("input.wb-login-v3-checkbox__input")
                    if chk.count() and not chk.first.is_checked():
                        chk.first.check()

                    phone_inp = page.locator("input[placeholder='请输入手机号']")
                    phone_inp.click()
                    page.wait_for_timeout(100)
                    page.keyboard.type(rent.phone, delay=25)
                    page.wait_for_timeout(350)

                    sent, cap_logs = solve_slider(page, cap_store, verify_results, sms_results)
                    att["slider_logs"] = cap_logs
                    att["tencent_sms"] = [s[1] for s in sms_results][-2:]
                    print(f"[ENGINE] Attempt {att_idx+1}: phone={rent.phone} ({rent.isp} {rent.province}) sent={sent} cap={cap_logs}", flush=True)

                    if not sent:
                        sms_client.release(rent.order_id)
                        active_order["id"] = None
                        record_attempt(rent.phone, sms_provider, "sms_bisu")
                        att["error"] = "sms_not_sent"
                        out["attempts"].append(att)
                        continue

                    att["sms_sent"] = True
                    otp, note = sms_client.poll_otp(rent.order_id, timeout_sec=otp_timeout, interval_sec=3.5)
                    print(f"[ENGINE] Attempt {att_idx+1}: otp={otp} note={note}", flush=True)
                    if not otp:
                        sms_client.release(rent.order_id)
                        active_order["id"] = None
                        record_attempt(rent.phone, sms_provider, "no_otp")
                        att["error"] = "no_otp"
                        att["note"] = note
                        out["attempts"].append(att)
                        continue

                    active_order["id"] = None
                    att["otp"] = otp
                    code_inp = page.locator("input[placeholder='请输入验证码']")
                    code_inp.click()
                    page.wait_for_timeout(100)
                    page.keyboard.type(otp, delay=30)
                    page.wait_for_timeout(350)
                    if chk.count() and not chk.first.is_checked():
                        chk.first.check()
                        page.wait_for_timeout(200)

                    if block_bind:
                        def kill(route):
                            blocked_count["n"] += 1
                            try:
                                route.abort()
                            except Exception:
                                pass
                        page.route("**/signin-callback*", kill)
                        page.route("**/login/signin-callback*", kill)

                    page.locator(".oneid-react-dialog-confirm-button").first.click(force=True)

                    tok = None
                    for _s in range(32):
                        page.wait_for_timeout(1100)
                        t = poll_cbcn_cli_token(st_info["state"])
                        if t.get("ok") and t.get("access_token"):
                            tok = t
                            break
                        for bt in (
                            "同意", "注册个人账号", "创建个人账号", "个人版", "确认登录",
                            "继续登录", "同意并登录", "授权并登录", "免费试用", "立即使用",
                            "进入个人版", "确定", "下一步",
                        ):
                            loc = page.get_by_text(bt, exact=True)
                            if loc.count() and loc.first.is_visible():
                                print(f"[ENGINE] Post-login UI button click: {bt}", flush=True)
                                loc.first.click(force=True)
                                page.wait_for_timeout(450)
                                break

                    att["token_ok"] = bool(tok)
                    att["bind_blocked"] = blocked_count["n"]
                    if tok:
                        pr_before = probe_cbcn_inference(tok["access_token"], uid=tok.get("uid", ""))
                        att["probe_before_harvest"] = pr_before

                        harv = None
                        if not skip_harvest and pr_before.get("ok"):
                            if safe_harvest:
                                harv = harvest_cbcn_safe(tok["access_token"], uid=tok.get("uid", ""))
                            else:
                                harv = harvest_cbcn_all(tok["access_token"], uid=tok.get("uid", ""), nickname=tok.get("nickname") or "U")
                            time.sleep(5)
                            pr_after = probe_cbcn_inference(tok["access_token"], uid=tok.get("uid", ""))
                            att["probe_after_harvest"] = pr_after
                            ri = (harv or {}).get("resource") or {}
                            final_ok = bool(pr_after.get("ok"))
                            probe_checked = pr_after
                        elif safe_harvest and not pr_before.get("ok") and pr_before.get("status") == 429:
                            harv = harvest_cbcn_safe(tok["access_token"], uid=tok.get("uid", ""))
                            time.sleep(4)
                            pr_after = probe_cbcn_inference(tok["access_token"], uid=tok.get("uid", ""))
                            att["probe_after_harvest"] = pr_after
                            ri = (harv or {}).get("resource") or {}
                            final_ok = bool(pr_after.get("ok"))
                            probe_checked = pr_after
                        else:
                            from .harvester import get_cbcn_user_resource
                            ri = get_cbcn_user_resource(tok["access_token"], uid=tok.get("uid", ""))
                            final_ok = bool(pr_before.get("ok"))
                            probe_checked = pr_before

                        rem_c = float(ri.get("remaining_credits") or 0.0)
                        meets_min = rem_c >= min_credits
                        att.update(
                            uid=tok.get("uid"),
                            nickname=tok.get("nickname"),
                            remaining=rem_c,
                            total=ri.get("total_credits"),
                            packs=ri.get("pack_count"),
                            ok=final_ok and meets_min,
                        )
                        probe_body = str(probe_checked.get("body") or "")
                        if final_ok:
                            fp_outcome = "ok"
                        elif probe_checked.get("status") == 403 or '"11140"' in probe_body or ":11140" in probe_body:
                            fp_outcome = "banned"
                        elif probe_checked.get("status") == 429 or "14018" in probe_body:
                            fp_outcome = "empty_quota"
                        else:
                            fp_outcome = "error"
                        record_attempt(rent.phone, sms_provider, fp_outcome, detail=json.dumps(probe_checked)[:120])

                        bundle = export_bundle(
                            access_token=tok["access_token"],
                            refresh_token=tok.get("refresh_token", ""),
                            name=f"CBCN-{tok.get('nickname') or rent.phone}",
                            phone=rent.phone,
                            uid=tok.get("uid", ""),
                            nickname=tok.get("nickname") or "",
                            expires_in=int(tok.get("expires_in") or 5184000),
                            remaining_credits=rem_c,
                            pack_count=int(ri.get("pack_count") or 0),
                        )
                        att["bundle"] = bundle.to_dict()

                        if sink and final_ok and rem_c > 0 and meets_min:
                            try:
                                att["sink_result"] = dispatch_credential_sink(bundle, sink=sink)
                            except Exception as e:
                                att["sink_error"] = str(e)
                        out["attempts"].append(att)
                        if final_ok and meets_min:
                            out["ok"] = True
                            break
                        continue

                    record_attempt(rent.phone, sms_provider, "no_token")
                    out["attempts"].append(att)
                    continue

                try:
                    page.unroute_all(behavior="ignoreErrors")
                except Exception:
                    pass
                return out
        out["error"] = "login_page_failed"
        return out
    finally:
        if active_order["id"]:
            try:
                sms_client.release(active_order["id"])
            except Exception:
                pass
        try:
            sms_client.release_all()
        except Exception:
            pass
