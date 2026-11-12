"""solver.py — Tencent Waterproof Wall Slider Puzzle Captcha Solver and BYOP SMS Clients."""
from __future__ import annotations

import io
import json
import os
import random
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass

from .fingerprint import BAD_CN_PREFIXES
from .harvester import BILLING_BASE_CN, CHAT_BASE_CN, CLI_VER, _derive_id
from .store import load_dotenv_file

load_dotenv_file()

DEFAULT_EXCLUDE_SEGMENTS = "145|146|147|148|149|162|165|167|170|171|172|1789|1849|192"


def _tls_noverify_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@dataclass
class RentedPhone:
    provider: str
    phone: str
    area_code: str
    order_id: str
    project_id: str
    isp: str = ""
    province: str = ""
    last_event_time: str = ""


class FeihuSmsClient:
    """BYOP SMS client for Feihu (api.feihu2026.com)."""

    def __init__(
        self,
        api_user: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        load_dotenv_file()
        self.api_user = api_user or os.environ.get("FEIHU_API_USER", "")
        self.api_key = api_key or os.environ.get("FEIHU_API_KEY", "")
        self.base_url = (base_url or os.environ.get("FEIHU_BASE_URL", "http://api.feihu2026.com/api/sms")).rstrip("/")
        self._ctx = _tls_noverify_context()
        self._token = ""

    def _get(self, path: str, params: dict | None = None) -> dict:
        qs = urllib.parse.urlencode(params or {})
        url = f"{self.base_url}{path}" + (f"?{qs}" if qs else "")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15, context=self._ctx) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def login(self) -> str:
        if not self.api_user or not self.api_key:
            raise ValueError("FEIHU_API_USER and FEIHU_API_KEY are required")
        res = self._get("/login", {"user": self.api_user, "pass": self.api_key})
        tok = (res.get("data") or {}).get("token") or ""
        if res.get("code") != 200 or not tok:
            raise RuntimeError(f"Feihu login failed: {res}")
        self._token = tok
        return tok

    def ensure_token(self) -> str:
        return self._token or self.login()

    def user_info(self) -> dict:
        return self._get("/userInfo", {"token": self.ensure_token()})

    def rent_phone(
        self,
        pid: int | str = 11599,
        area_code: str = "+852",
        mode: int | None = None,
        card_type: str = "1",
        isp: str | None = None,
        exclude: str = DEFAULT_EXCLUDE_SEGMENTS,
        fresh_only: bool = False,
        **_kwargs,
    ) -> RentedPhone | None:
        params: dict[str, object] = {
            "token": self.ensure_token(),
            "pid": pid,
            "exclude": exclude,
        }
        if area_code == "+852":
            params["isp"] = "hk"
        else:
            if card_type:
                params["cardType"] = card_type
            if isp:
                params["isp"] = isp
        if mode is not None:
            params["mode"] = mode

        res = self._get("/getPhone", params)
        data = res.get("data") or {}
        if res.get("code") != 200 or not data.get("phone"):
            return None
        phone = str(data["phone"])
        oid = str(data["order_id"])
        isp_name = str(data.get("isp") or "")
        prov_name = str(data.get("province") or "")
        last_ev = str(data.get("last_event_time") or "").strip()
        eff_area = "+852" if (isp_name == "香港" or prov_name == "香港" or len(phone) == 8) else area_code
        if fresh_only and last_ev:
            self.release(oid)
            return None
        if eff_area == "+86" and (phone.startswith(BAD_CN_PREFIXES) or "虚拟" in isp_name):
            self.release(oid)
            return None
        return RentedPhone(
            provider="feihu",
            phone=phone,
            area_code=eff_area,
            order_id=oid,
            project_id=str(pid),
            isp=isp_name,
            province=prov_name,
            last_event_time=last_ev,
        )

    def poll_otp(self, order_id: str, timeout_sec: int = 55, interval_sec: float = 3.5) -> tuple[str | None, str]:
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            res = self._get("/getMessage", {"token": self.ensure_token(), "order_id": order_id})
            data = res.get("data") or {}
            st = data.get("status")
            if st == 3 and data.get("code"):
                return str(data["code"]).strip(), str(data.get("message") or "")
            if st in (4, 5, 6):
                return None, str(res.get("msg") or st)
            time.sleep(interval_sec)
        return None, "timeout"

    def release(self, order_id: str) -> dict:
        return self._get("/cancelRecv", {"token": self.ensure_token(), "order_id": order_id})

    def release_all(self) -> dict:
        return self._get("/cancelAllRecv", {"token": self.ensure_token()})


class EjiemaSmsClient:
    """BYOP SMS client for Ejiema / Eomsg (https://api.ejiema.com/zc/data.php)."""

    def __init__(self, token: str | None = None, base_url: str = "https://api.ejiema.com/zc/data.php") -> None:
        load_dotenv_file()
        self.token = token or os.environ.get("EJIEMA_API_TOKEN", "")
        self.base_url = base_url.rstrip("/")

    def _call(self, params: dict[str, str]) -> str:
        if not self.token:
            raise ValueError("EJIEMA_API_TOKEN is required")
        qs = urllib.parse.urlencode(params)
        req = urllib.request.Request(f"{self.base_url}?{qs}", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            txt = r.read().decode("utf-8", "replace").strip()
        if txt.startswith("ERROR:"):
            raise RuntimeError(txt)
        return txt

    def login(self) -> str:
        if not self.token:
            raise ValueError("EJIEMA_API_TOKEN is required")
        return self.token

    def left_amount(self) -> str:
        return self._call({"code": "leftAmount", "token": self.token})

    def rent_phone(self, keyword: str = "腾讯科技", card_type: str = "实卡", **_kwargs) -> RentedPhone | None:
        for _ in range(5):
            raw = self._call({"code": "getPhone", "token": self.token, "keyWord": keyword, "cardType": card_type})
            m = re.search(r"(1[3-9]\d{9})", raw)
            if not m:
                return None
            phone = m.group(1)
            if phone.startswith(BAD_CN_PREFIXES):
                self.release(phone)
                time.sleep(0.5)
                continue
            return RentedPhone(provider="ejiema", phone=phone, area_code="+86", order_id=phone, project_id=keyword)
        return None

    def poll_otp(self, order_id: str, keyword: str = "腾讯科技", timeout_sec: int = 55, interval_sec: float = 4.0) -> tuple[str | None, str]:
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            raw = self._call({"code": "getMsg", "token": self.token, "phone": order_id, "keyWord": keyword})
            if "尚未收到" in raw:
                time.sleep(interval_sec)
                continue
            m = re.search(r"(?:验证码\s*(?:是|为|：|:)?\s*|[:：,\s])([0-9]{4,8})", raw) or re.search(r"\b([0-9]{6})\b", raw)
            if m:
                return m.group(1), raw
            time.sleep(interval_sec)
        return None, "timeout"

    def release(self, order_id: str) -> str:
        return self._call({"code": "release", "token": self.token, "phone": order_id})

    def release_all(self) -> None:
        return None


class HaomadunSmsClient:
    """BYOP SMS client for Haomadun (api.haomadun.com/openapi/v1)."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.haomadun.com/openapi/v1",
        proxy_url: str | None = None,
    ) -> None:
        load_dotenv_file()
        self.api_key = api_key or os.environ.get("HAOMADUN_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.proxy_url = (proxy_url or os.environ.get("HAOMADUN_PROXY_URL") or os.environ.get("CBCN_PROXY_URL") or "").strip()

    def _proxies(self) -> dict[str, str] | None:
        raw = self.proxy_url
        if not raw:
            cfg = resolve_proxy_playwright_cfg(None)
            if cfg and cfg.get("server"):
                u = urllib.parse.urlparse(cfg["server"])
                if cfg.get("username"):
                    auth = f"{urllib.parse.quote(cfg['username'])}:{urllib.parse.quote(cfg.get('password', ''))}@"
                    raw = f"{u.scheme}://{auth}{u.hostname}:{u.port}"
                else:
                    raw = cfg["server"]
        if not raw or raw.lower() in ("none", "direct", "off", "false"):
            return None
        if "://" not in raw:
            raw = f"http://{raw}"
        return {"http": raw, "https": raw}

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        import requests

        if not self.api_key:
            raise ValueError("HAOMADUN_API_KEY is required")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "X-Api-Key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
        }
        proxies = self._proxies()
        r = requests.request(
            method,
            f"{self.base_url}{path}",
            json=body,
            headers=headers,
            proxies=proxies,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    def login(self) -> str:
        if not self.api_key:
            raise ValueError("HAOMADUN_API_KEY is required")
        return self.api_key

    def rent_phone(self, pid: str = "21986", channel_uid: str = "21986-HBY3OAE45E", **_kwargs) -> RentedPhone | None:
        for _ in range(5):
            res = self._req("POST", "/phone/rent", {"project_id": str(pid), "platform": "domestic", "channel_uid": channel_uid})
            data = res.get("data") or {}
            if res.get("code") != 0 or not data.get("phone"):
                return None
            phone = str(data["phone"])
            rid = str(data["id"])
            if phone.startswith(BAD_CN_PREFIXES):
                self.release(rid)
                time.sleep(1)
                continue
            return RentedPhone(provider="haomadun", phone=phone, area_code="+86", order_id=rid, project_id=str(pid))
        return None

    def poll_otp(self, order_id: str, timeout_sec: int = 45, interval_sec: float = 3.0) -> tuple[str | None, str]:
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            res = self._req("GET", f"/phone/{order_id}/code")
            data = res.get("data") or {}
            st = data.get("status")
            if st == "success" and data.get("code"):
                return str(data["code"]).strip(), str(data.get("sms") or "")
            if st in ("failed", "released", "blacklist"):
                return None, str(res.get("message") or st)
            time.sleep(interval_sec)
        return None, "timeout"

    def release(self, order_id: str) -> dict:
        return self._req("POST", f"/phone/{order_id}/release", {})

    def release_all(self) -> None:
        return None


def build_sms_client(provider: str = "feihu", proxy_url: str | None = None):
    """Instantiate a BYOP SMS client by provider name."""
    p = provider.strip().lower()
    if p == "feihu":
        return FeihuSmsClient()
    if p in ("ejiema", "eomsg"):
        return EjiemaSmsClient()
    if p == "haomadun":
        return HaomadunSmsClient(proxy_url=proxy_url)
    raise ValueError(f"Unsupported SMS provider: {provider}")


def solve_tcaptcha_dx(pre_json: dict, bg_bytes: bytes, sp_bytes: bytes) -> dict:
    """Compute horizontal slider offset in original sprite coordinates from Tencent Captcha prehandle + images."""
    import numpy as np
    from PIL import Image

    bg = Image.open(io.BytesIO(bg_bytes)).convert("RGBA")
    sp = Image.open(io.BytesIO(sp_bytes)).convert("RGBA")
    dyn = pre_json["data"]["dyn_show_info"]
    fg = [e for e in dyn["fg_elem_list"] if e["id"] == 1][0]
    sx, sy = fg["sprite_pos"]
    sw, sh = fg["size_2d"]
    ix, iy = fg["init_pos"]

    piece = sp.crop((sx, sy, sx + sw, sy + sh))
    mask = (np.array(piece)[:, :, 3] > 128).astype(np.float32)

    edge = np.zeros_like(mask)
    edge[1:, :] += np.abs(mask[1:, :] - mask[:-1, :])
    edge[:, 1:] += np.abs(mask[:, 1:] - mask[:, :-1])
    edge = (edge > 0).astype(np.float32)

    bg_gray = np.array(bg.convert("L"), dtype=np.float32)
    bg_edge = np.zeros_like(bg_gray)
    bg_edge[:, 1:] += np.abs(bg_gray[:, 1:] - bg_gray[:, :-1])
    bg_edge[1:, :] += np.abs(bg_gray[1:, :] - bg_gray[:-1, :])

    strip = bg_edge[iy : iy + sh, :]
    best_score, best_x = -1.0, ix
    for x in range(max(ix + 10, 100), bg.size[0] - sw):
        score = float(np.sum(strip[:, x : x + sw] * edge))
        if score > best_score:
            best_score, best_x = score, x

    return {
        "bg_w": bg.size[0],
        "init_x": ix,
        "target_x": best_x,
        "delta_orig": best_x - ix,
        "score": best_score,
    }


def human_drag(page, start_x: float, start_y: float, dx: float) -> None:
    page.mouse.move(start_x, start_y)
    page.wait_for_timeout(random.randint(120, 200))
    page.mouse.down()
    page.wait_for_timeout(random.randint(80, 130))
    steps = random.randint(24, 32)
    overshoot = random.uniform(2.0, 4.0)
    for i in range(1, steps + 1):
        ease = 1 - pow(1 - i / steps, 3)
        page.mouse.move(start_x + (dx + overshoot) * ease, start_y + random.uniform(-1.2, 1.2))
        time.sleep(random.uniform(0.012, 0.022))
    for j in range(1, 5):
        page.mouse.move(start_x + (dx + overshoot) - overshoot * (j / 4.0), start_y + random.uniform(-0.4, 0.4))
        time.sleep(random.uniform(0.02, 0.04))
    page.wait_for_timeout(random.randint(150, 250))
    page.mouse.up()


def probe_cbcn_inference(access_token: str, model: str = "deepseek-v4.1-flash", uid: str = "") -> dict:
    """Probe live CBCN inference endpoint with official CLI headers to confirm account is active and unbanned."""
    rid = uuid.uuid4().hex
    span = rid[:16]
    cid = uuid.uuid4().hex
    mid = uuid.uuid4().hex
    hdrs = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "User-Agent": f"CLI/{CLI_VER} CodeBuddy/{CLI_VER}",
        "Origin": BILLING_BASE_CN,
        "Referer": f"{BILLING_BASE_CN}/",
        "X-Product": "SaaS",
        "X-Domain": "copilot.tencent.com",
        "X-Requested-With": "XMLHttpRequest",
        "x-codebuddy-request": "1",
        "X-IDE-Type": "CLI",
        "X-IDE-Name": "CLI",
        "X-IDE-Version": CLI_VER,
        "X-Agent-Intent": "craft",
        "X-Request-ID": rid,
        "X-B3-TraceId": rid,
        "X-B3-SpanId": span,
        "X-B3-Sampled": "1",
        "b3": f"{rid}-{span}-1-",
        "X-Conversation-ID": cid,
        "X-Conversation-Request-ID": rid,
        "X-Conversation-Message-ID": mid,
        "x-stainless-arch": "x64",
        "x-stainless-lang": "js",
        "x-stainless-os": "Linux",
        "x-stainless-package-version": CLI_VER,
        "x-stainless-retry-count": "0",
        "x-stainless-runtime": "node",
        "x-stainless-runtime-version": "20.11.0",
    }
    if uid:
        hdrs["X-User-Id"] = uid
    req = urllib.request.Request(
        f"{CHAT_BASE_CN}/v2/chat/completions",
        data=json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "hi"},
            ],
            "stream": True,
            "stream_options": {"include_usage": True},
        }).encode("utf-8"),
        headers=hdrs,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            _ = r.readline()
            return {"ok": r.status == 200, "status": r.status}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "body": e.read().decode("utf-8", "replace")[:300]}
    except Exception as e:
        return {"ok": False, "status": 0, "error": str(e)}


def resolve_proxy_playwright_cfg(proxy_url: str | None = None, country: str = "hk") -> dict | None:
    raw = (proxy_url or os.environ.get("CBCN_PROXY_URL") or "").strip()
    if not raw:
        tpl = os.environ.get("PROXY_TEMPLATE", "")
        host = os.environ.get("PROXY_HOST", "")
        user = os.environ.get("PROXY_USER", "")
        pwd = os.environ.get("PROXY_PASS", "")
        if tpl and host and user:
            pmin = int(os.environ.get("PROXY_PORT_MIN", "10000"))
            pmax = int(os.environ.get("PROXY_PORT_MAX", "29999"))
            port = random.randint(pmin, pmax)
            base_u = user.split(";")[0].split("__")[0]
            raw = tpl.format(user=base_u, password=pwd, host=host, port=port, country=country, ttl=30)
    if not raw or raw.lower() in ("none", "direct", "off", "false"):
        return None
    if "{session}" in raw or "{port}" in raw:
        pmin = int(os.environ.get("PROXY_PORT_MIN", "10000"))
        pmax = int(os.environ.get("PROXY_PORT_MAX", "29999"))
        port = random.randint(pmin, pmax)
        sid = os.urandom(5).hex()
        raw = raw.replace("{port}", str(port)).replace("{session}", sid)
    u = urllib.parse.urlparse(raw if "://" in raw else f"http://{raw}")
    cfg = {"server": f"{u.scheme}://{u.hostname}:{u.port}"}
    if u.username:
        cfg["username"] = urllib.parse.unquote(u.username)
    if u.password:
        cfg["password"] = urllib.parse.unquote(u.password)
    return cfg
