import base64
import hashlib
import json
import random
import re
import secrets
import string
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

from curl_cffi import requests as curl_requests


RETRIABLE_MARKERS_V2 = [
    "tls",
    "ssl",
    "curl: (35)",
    "预授权被拦截",
    "authorize",
    "registration_disallowed",
    "http 400",
    "创建账号失败",
    "未获取到 authorization code",
    "consent",
    "workspace",
    "organization",
    "otp",
    "验证码",
    "session",
    "accesstoken",
    "next-auth",
]


def should_retry_registration_v2(message: str) -> bool:
    text = str(message or "").lower()
    return any(marker in text for marker in RETRIABLE_MARKERS_V2)


class OTPFetcherAdapter:
    def __init__(self, otp_fetcher: Callable[[int], Optional[str]]):
        self.otp_fetcher = otp_fetcher

    def wait_for_verification_code(
        self,
        email: str,
        timeout: int = 60,
        otp_sent_at: Optional[float] = None,
        exclude_codes=None,
    ) -> Optional[str]:
        del email, otp_sent_at, exclude_codes
        return self.otp_fetcher(timeout)


@dataclass
class FlowState:
    page_type: str = ""
    continue_url: str = ""
    method: str = "GET"
    current_url: str = ""
    source: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return {}


def normalize_page_type(value: str) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace("/", "_").replace(" ", "_")


def normalize_flow_url(url: str, auth_base: str = "https://auth.openai.com") -> str:
    value = str(url or "").strip()
    if not value:
        return ""
    if value.startswith("//"):
        return f"https:{value}"
    if value.startswith("/"):
        return f"{auth_base.rstrip('/')}{value}"
    return value


def infer_page_type_from_url(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(url)
    except Exception:
        return ""
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    if "code=" in (parsed.query or ""):
        return "oauth_callback"
    if "chatgpt.com" in host and "/api/auth/callback/" in path:
        return "callback"
    if "create-account/password" in path:
        return "create_account_password"
    if "email-verification" in path or "email-otp" in path:
        return "email_otp_verification"
    if "about-you" in path:
        return "about_you"
    if "log-in/password" in path:
        return "login_password"
    if "sign-in-with-chatgpt" in path and "consent" in path:
        return "consent"
    if "workspace" in path and "select" in path:
        return "workspace_selection"
    if "organization" in path and "select" in path:
        return "organization_selection"
    if "callback" in path:
        return "callback"
    if "chatgpt.com" in host and path in {"", "/"}:
        return "chatgpt_home"
    if path:
        return normalize_page_type(path.strip("/").replace("/", "_"))
    return ""


def extract_flow_state(
    data: Optional[Dict[str, Any]] = None,
    current_url: str = "",
    auth_base: str = "https://auth.openai.com",
    default_method: str = "GET",
) -> FlowState:
    raw = data if isinstance(data, dict) else {}
    page = raw.get("page") or {}
    payload = page.get("payload") or {}
    continue_url = normalize_flow_url(raw.get("continue_url") or payload.get("url") or "", auth_base=auth_base)
    effective_current_url = continue_url if raw and continue_url else current_url
    current = normalize_flow_url(effective_current_url or continue_url, auth_base=auth_base)
    page_type = normalize_page_type(page.get("type")) or infer_page_type_from_url(continue_url or current)
    method = str(raw.get("method") or payload.get("method") or default_method or "GET").upper()
    return FlowState(
        page_type=page_type,
        continue_url=continue_url,
        method=method,
        current_url=current,
        source="api" if raw else "url",
        payload=payload if isinstance(payload, dict) else {},
        raw=raw,
    )


def describe_flow_state(state: FlowState) -> str:
    target = state.continue_url or state.current_url or "-"
    return f"page={state.page_type or '-'} method={state.method or '-'} next={target[:80]}..."


def random_delay(low: float = 0.3, high: float = 1.0) -> None:
    time.sleep(random.uniform(low, high))


def generate_datadog_trace() -> Dict[str, str]:
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), "016x")
    parent_hex = format(int(parent_id), "016x")
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def extract_chrome_full_version(user_agent: str) -> str:
    if not user_agent:
        return ""
    match = re.search(r"Chrome/([0-9.]+)", user_agent)
    return match.group(1) if match else ""


def _registrable_domain(hostname: str) -> str:
    if not hostname:
        return ""
    host = hostname.split(":")[0].strip(".").lower()
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


def infer_sec_fetch_site(url: str, referer: Optional[str] = None, navigation: bool = False) -> str:
    if not referer:
        return "none" if navigation else "same-origin"
    try:
        target = urlparse(url or "")
        source = urlparse(referer or "")
        if not target.scheme or not target.netloc or not source.netloc:
            return "none" if navigation else "same-origin"
        if (target.scheme, target.netloc) == (source.scheme, source.netloc):
            return "same-origin"
        if _registrable_domain(target.hostname or "") == _registrable_domain(source.hostname or ""):
            return "same-site"
    except Exception:
        pass
    return "cross-site"


def build_sec_ch_ua_full_version_list(sec_ch_ua: str, chrome_full_version: str) -> str:
    if not sec_ch_ua or not chrome_full_version:
        return ""
    entries = []
    for brand, version in re.findall(r'"([^"]+)";v="([^"]+)"', sec_ch_ua):
        full_version = chrome_full_version if brand in {"Chromium", "Google Chrome"} else f"{version}.0.0.0"
        entries.append(f'"{brand}";v="{full_version}"')
    return ", ".join(entries)


def build_browser_headers(
    *,
    url: str,
    user_agent: str,
    sec_ch_ua: Optional[str] = None,
    chrome_full_version: Optional[str] = None,
    accept: Optional[str] = None,
    accept_language: str = "en-US,en;q=0.9",
    referer: Optional[str] = None,
    origin: Optional[str] = None,
    content_type: Optional[str] = None,
    navigation: bool = False,
    fetch_mode: Optional[str] = None,
    fetch_dest: Optional[str] = None,
    fetch_site: Optional[str] = None,
    headed: bool = False,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    chrome_full = chrome_full_version or extract_chrome_full_version(user_agent)
    full_version_list = build_sec_ch_ua_full_version_list(sec_ch_ua or "", chrome_full)
    headers = {
        "User-Agent": user_agent or "Mozilla/5.0",
        "Accept-Language": accept_language,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-arch": '"x86"',
        "sec-ch-ua-bitness": '"64"',
    }
    if accept:
        headers["Accept"] = accept
    if referer:
        headers["Referer"] = referer
    if origin:
        headers["Origin"] = origin
    if content_type:
        headers["Content-Type"] = content_type
    if sec_ch_ua:
        headers["sec-ch-ua"] = sec_ch_ua
    if chrome_full:
        headers["sec-ch-ua-full-version"] = f'"{chrome_full}"'
        headers["sec-ch-ua-platform-version"] = '"15.0.0"'
    if full_version_list:
        headers["sec-ch-ua-full-version-list"] = full_version_list
    if navigation:
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-User"] = "?1"
        headers["Upgrade-Insecure-Requests"] = "1"
        headers["Cache-Control"] = "max-age=0"
    else:
        headers["Sec-Fetch-Dest"] = fetch_dest or "empty"
        headers["Sec-Fetch-Mode"] = fetch_mode or "cors"
    headers["Sec-Fetch-Site"] = fetch_site or infer_sec_fetch_site(url, referer, navigation=navigation)
    if headed:
        headers.setdefault("Priority", "u=0, i" if navigation else "u=1, i")
        headers.setdefault("DNT", "1")
        headers.setdefault("Sec-GPC", "1")
    if extra_headers:
        for key, value in extra_headers.items():
            if value is not None:
                headers[key] = value
    return headers


def seed_oai_device_cookie(session, device_id: str) -> None:
    for domain in (
        "chatgpt.com",
        ".chatgpt.com",
        "openai.com",
        ".openai.com",
        "auth.openai.com",
        ".auth.openai.com",
    ):
        try:
            session.cookies.set("oai-did", device_id, domain=domain)
        except Exception:
            continue


class SentinelTokenGenerator:
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id: Optional[str] = None, user_agent: Optional[str] = None):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/145.0.0.0 Safari/537.36"
        )
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _get_config(self):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        date_str = now.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        return [
            "1920x1080", date_str, 4294705152, random.random(), self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js", None, None,
            "en-US", "en-US,en", random.random(), "vendorSub−undefined",
            "location", "Object", perf_now, self.sid, "", random.choice([4, 8, 12, 16]), time_origin,
        ]

    @staticmethod
    def _base64_encode(data) -> str:
        json_str = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        return base64.b64encode(json_str.encode("utf-8")).decode("ascii")

    def _run_check(self, start_time: float, seed: str, difficulty: str, config, nonce: int):
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        diff_len = len(difficulty)
        if hash_hex[:diff_len] <= difficulty:
            return data + "~S"
        return None

    def generate_token(self, seed: Optional[str] = None, difficulty: Optional[str] = None) -> str:
        if seed is None:
            seed = self.requirements_seed
            difficulty = difficulty or "0"
        start_time = time.time()
        config = self._get_config()
        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start_time, seed, difficulty or "0", config, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self) -> str:
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._base64_encode(config)


def fetch_sentinel_challenge(session, device_id: str, flow: str, user_agent: str, sec_ch_ua: str, impersonate: str):
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or "Mozilla/5.0",
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    req_body = {"p": generator.generate_requirements_token(), "id": device_id, "flow": flow}
    try:
        resp = session.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            data=json.dumps(req_body),
            headers=headers,
            timeout=20,
            impersonate=impersonate,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def build_sentinel_token(session, device_id: str, flow: str, user_agent: str, sec_ch_ua: str, impersonate: str) -> Optional[str]:
    challenge = fetch_sentinel_challenge(session, device_id, flow, user_agent, sec_ch_ua, impersonate)
    if not challenge:
        return None
    c_value = challenge.get("token", "")
    if not c_value:
        return None
    pow_data = challenge.get("proofofwork") or {}
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(seed=pow_data.get("seed"), difficulty=pow_data.get("difficulty", "0"))
    else:
        p_value = generator.generate_requirements_token()
    return json.dumps({"p": p_value, "t": "", "c": c_value, "id": device_id, "flow": flow}, separators=(",", ":"))


_CHROME_PROFILES = [
    {"major": 131, "impersonate": "chrome131", "build": 6778, "patch_range": (69, 205), "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'},
    {"major": 133, "impersonate": "chrome133a", "build": 6943, "patch_range": (33, 153), "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"'},
    {"major": 136, "impersonate": "chrome136", "build": 7103, "patch_range": (48, 175), "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"'},
]


def _random_chrome_version():
    profile = random.choice(_CHROME_PROFILES)
    patch = random.randint(*profile["patch_range"])
    full_ver = f"{profile['major']}.0.{profile['build']}.{patch}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
    return profile["impersonate"], profile["major"], full_ver, ua, profile["sec_ch_ua"]


class ChatGPTClientV2:
    BASE = "https://chatgpt.com"
    AUTH = "https://auth.openai.com"

    def __init__(self, proxy: Optional[str] = None, verbose: bool = True, browser_mode: str = "protocol"):
        self.proxy = proxy
        self.verbose = verbose
        self.browser_mode = browser_mode or "protocol"
        self.device_id = str(uuid.uuid4())
        self.accept_language = random.choice(["en-US,en;q=0.9", "en-US,en;q=0.9,zh-CN;q=0.8", "en,en-US;q=0.9", "en-US,en;q=0.8"])
        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()
        self.session = curl_requests.Session(impersonate=self.impersonate)
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": self.accept_language,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
            "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
        })
        seed_oai_device_cookie(self.session, self.device_id)
        self.last_registration_state = FlowState()

    def _log(self, msg: str):
        if self.verbose:
            print(f"  {msg}")

    def _browser_pause(self, low: float = 0.15, high: float = 0.45):
        if self.browser_mode == "headed":
            random_delay(low, high)

    def _headers(self, url: str, *, accept: str, referer: Optional[str] = None, origin: Optional[str] = None, content_type: Optional[str] = None, navigation: bool = False, fetch_mode: Optional[str] = None, fetch_dest: Optional[str] = None, fetch_site: Optional[str] = None, extra_headers: Optional[Dict[str, str]] = None):
        return build_browser_headers(
            url=url,
            user_agent=self.ua,
            sec_ch_ua=self.sec_ch_ua,
            chrome_full_version=self.chrome_full,
            accept=accept,
            accept_language=self.accept_language,
            referer=referer,
            origin=origin,
            content_type=content_type,
            navigation=navigation,
            fetch_mode=fetch_mode,
            fetch_dest=fetch_dest,
            fetch_site=fetch_site,
            headed=self.browser_mode == "headed",
            extra_headers=extra_headers,
        )

    def _reset_session(self):
        self.device_id = str(uuid.uuid4())
        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()
        self.session = curl_requests.Session(impersonate=self.impersonate)
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": self.accept_language,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
            "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
        })
        seed_oai_device_cookie(self.session, self.device_id)

    def _state_from_url(self, url: str, method: str = "GET") -> FlowState:
        state = extract_flow_state(current_url=normalize_flow_url(url, auth_base=self.AUTH), auth_base=self.AUTH, default_method=method)
        state.method = str(method).upper()
        return state

    def _state_from_payload(self, data, current_url: str = "") -> FlowState:
        return extract_flow_state(data=data, current_url=current_url, auth_base=self.AUTH)

    def _state_signature(self, state: FlowState):
        return (state.page_type or "", state.method or "", state.continue_url or "", state.current_url or "")

    def _is_registration_complete_state(self, state: FlowState) -> bool:
        current_url = (state.current_url or "").lower()
        continue_url = (state.continue_url or "").lower()
        page_type = state.page_type or ""
        return page_type in {"callback", "chatgpt_home", "oauth_callback"} or ("chatgpt.com" in current_url and "redirect_uri" not in current_url) or ("chatgpt.com" in continue_url and "redirect_uri" not in continue_url and page_type != "external_url")

    def _state_is_password_registration(self, state: FlowState) -> bool:
        return state.page_type in {"create_account_password", "password"}

    def _state_is_email_otp(self, state: FlowState) -> bool:
        target = f"{state.continue_url} {state.current_url}".lower()
        return state.page_type == "email_otp_verification" or "email-verification" in target or "email-otp" in target

    def _state_is_about_you(self, state: FlowState) -> bool:
        target = f"{state.continue_url} {state.current_url}".lower()
        return state.page_type == "about_you" or "about-you" in target

    def _state_requires_navigation(self, state: FlowState) -> bool:
        if (state.method or "GET").upper() != "GET":
            return False
        if state.page_type == "external_url" and state.continue_url:
            return True
        if state.continue_url and state.continue_url != state.current_url:
            return True
        return False

    def _follow_flow_state(self, state: FlowState, referer: Optional[str] = None):
        target_url = state.continue_url or state.current_url
        if not target_url:
            return False, "缺少可跟随的 continue_url"
        try:
            self._browser_pause()
            r = self.session.get(target_url, headers=self._headers(target_url, accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", referer=referer, navigation=True), allow_redirects=True, timeout=30)
            final_url = str(r.url)
            content_type = (r.headers.get("content-type", "") or "").lower()
            if "application/json" in content_type:
                try:
                    next_state = self._state_from_payload(r.json(), current_url=final_url)
                except Exception:
                    next_state = self._state_from_url(final_url)
            else:
                next_state = self._state_from_url(final_url)
            return True, next_state
        except Exception as e:
            self._log(f"跟随 continue_url 失败: {e}")
            return False, str(e)

    def _get_cookie_value(self, name: str, domain_hint: Optional[str] = None) -> str:
        for cookie in self.session.cookies.jar:
            if cookie.name != name:
                continue
            if domain_hint and domain_hint not in (cookie.domain or ""):
                continue
            return cookie.value
        return ""

    def get_next_auth_session_token(self) -> str:
        return self._get_cookie_value("__Secure-next-auth.session-token", "chatgpt.com")

    def fetch_chatgpt_session(self):
        url = f"{self.BASE}/api/auth/session"
        self._browser_pause()
        response = self.session.get(url, headers=self._headers(url, accept="application/json", referer=f"{self.BASE}/", fetch_site="same-origin"), timeout=30)
        if response.status_code != 200:
            return False, f"/api/auth/session -> HTTP {response.status_code}"
        try:
            data = response.json()
        except Exception as exc:
            return False, f"/api/auth/session 返回非 JSON: {exc}"
        access_token = str(data.get("accessToken") or "").strip()
        if not access_token:
            return False, "/api/auth/session 未返回 accessToken"
        return True, data

    def reuse_session_and_get_tokens(self):
        state = self.last_registration_state or FlowState()
        if state.page_type == "external_url" or self._state_requires_navigation(state):
            ok, followed = self._follow_flow_state(state, referer=state.current_url or f"{self.AUTH}/about-you")
            if not ok:
                return False, f"注册回调落地失败: {followed}"
            self.last_registration_state = followed
        session_cookie = self.get_next_auth_session_token()
        if not session_cookie:
            return False, "缺少 __Secure-next-auth.session-token，注册回调可能未落地"
        ok, session_or_error = self.fetch_chatgpt_session()
        if not ok:
            return False, session_or_error
        session_data = session_or_error
        access_token = str(session_data.get("accessToken") or "").strip()
        session_token = str(session_data.get("sessionToken") or session_cookie or "").strip()
        user = session_data.get("user") or {}
        account = session_data.get("account") or {}
        jwt_payload = decode_jwt_payload(access_token)
        auth_payload = jwt_payload.get("https://api.openai.com/auth") or {}
        account_id = str(account.get("id") or "").strip() or str(auth_payload.get("chatgpt_account_id") or "").strip()
        user_id = str(user.get("id") or "").strip() or str(auth_payload.get("chatgpt_user_id") or "").strip() or str(auth_payload.get("user_id") or "").strip()
        normalized = {
            "access_token": access_token,
            "session_token": session_token,
            "account_id": account_id,
            "user_id": user_id,
            "workspace_id": account_id,
            "expires": session_data.get("expires"),
            "user": user,
            "account": account,
            "auth_provider": session_data.get("authProvider"),
            "raw_session": session_data,
        }
        return True, normalized

    def visit_homepage(self) -> bool:
        url = f"{self.BASE}/"
        try:
            self._browser_pause()
            r = self.session.get(url, headers=self._headers(url, accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", navigation=True), allow_redirects=True, timeout=30)
            return r.status_code == 200
        except Exception as e:
            self._log(f"访问首页失败: {e}")
            return False

    def get_csrf_token(self) -> Optional[str]:
        url = f"{self.BASE}/api/auth/csrf"
        try:
            r = self.session.get(url, headers=self._headers(url, accept="application/json", referer=f"{self.BASE}/", fetch_site="same-origin"), timeout=30)
            if r.status_code == 200:
                return r.json().get("csrfToken", "")
        except Exception as e:
            self._log(f"获取 CSRF token 失败: {e}")
        return None

    def signin(self, email: str, csrf_token: str) -> Optional[str]:
        url = f"{self.BASE}/api/auth/signin/openai"
        params = {
            "prompt": "login",
            "ext-oai-did": self.device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "screen_hint": "login_or_signup",
            "login_hint": email,
        }
        form_data = {"callbackUrl": f"{self.BASE}/", "csrfToken": csrf_token, "json": "true"}
        try:
            self._browser_pause()
            r = self.session.post(url, params=params, data=form_data, headers=self._headers(url, accept="application/json", referer=f"{self.BASE}/", origin=self.BASE, content_type="application/x-www-form-urlencoded", fetch_site="same-origin"), timeout=30)
            if r.status_code == 200:
                return r.json().get("url", "")
        except Exception as e:
            self._log(f"提交邮箱失败: {e}")
        return None

    def authorize(self, url: str, max_retries: int = 3) -> str:
        for attempt in range(max_retries):
            try:
                self._browser_pause()
                r = self.session.get(url, headers=self._headers(url, accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", referer=f"{self.BASE}/", navigation=True), allow_redirects=True, timeout=30)
                return str(r.url)
            except Exception as e:
                error_msg = str(e)
                is_tls_error = "TLS" in error_msg or "SSL" in error_msg or "curl: (35)" in error_msg
                if not (is_tls_error and attempt < max_retries - 1):
                    self._log(f"Authorize 失败: {e}")
                    return ""
        return ""

    def register_user(self, email: str, password: str):
        url = f"{self.AUTH}/api/accounts/user/register"
        headers = self._headers(url, accept="application/json", referer=f"{self.AUTH}/create-account/password", origin=self.AUTH, content_type="application/json", fetch_site="same-origin")
        headers.update(generate_datadog_trace())
        try:
            self._browser_pause()
            r = self.session.post(url, json={"username": email, "password": password}, headers=headers, timeout=30)
            if r.status_code == 200:
                return True, "注册成功"
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            return False, str(e)

    def send_email_otp(self) -> bool:
        url = f"{self.AUTH}/api/accounts/email-otp/send"
        try:
            self._browser_pause()
            r = self.session.get(url, headers=self._headers(url, accept="application/json, text/plain, */*", referer=f"{self.AUTH}/create-account/password", fetch_site="same-origin"), allow_redirects=True, timeout=30)
            return r.status_code == 200
        except Exception:
            return False

    def verify_email_otp(self, otp_code: str, return_state: bool = False):
        url = f"{self.AUTH}/api/accounts/email-otp/validate"
        headers = self._headers(url, accept="application/json", referer=f"{self.AUTH}/email-verification", origin=self.AUTH, content_type="application/json", fetch_site="same-origin")
        headers.update(generate_datadog_trace())
        try:
            self._browser_pause()
            r = self.session.post(url, json={"code": otp_code}, headers=headers, timeout=30)
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                next_state = self._state_from_payload(data, current_url=str(r.url) or f"{self.AUTH}/about-you")
                return (True, next_state) if return_state else (True, "验证成功")
            return False, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    def create_account(self, first_name: str, last_name: str, birthdate: str, return_state: bool = False):
        url = f"{self.AUTH}/api/accounts/create_account"
        sentinel_token = build_sentinel_token(self.session, self.device_id, "authorize_continue", self.ua, self.sec_ch_ua, self.impersonate)
        headers = self._headers(url, accept="application/json", referer=f"{self.AUTH}/about-you", origin=self.AUTH, content_type="application/json", fetch_site="same-origin", extra_headers={"oai-device-id": self.device_id})
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        headers.update(generate_datadog_trace())
        try:
            self._browser_pause()
            r = self.session.post(url, json={"name": f"{first_name} {last_name}", "birthdate": birthdate}, headers=headers, timeout=30)
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                next_state = self._state_from_payload(data, current_url=str(r.url) or self.BASE)
                return (True, next_state) if return_state else (True, "账号创建成功")
            return False, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    def register_complete_flow(self, email: str, password: str, first_name: str, last_name: str, birthdate: str, email_adapter):
        max_auth_attempts = 3
        final_url = ""
        for auth_attempt in range(max_auth_attempts):
            if auth_attempt > 0:
                self._reset_session()
            if not self.visit_homepage():
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "访问首页失败"
            csrf_token = self.get_csrf_token()
            if not csrf_token:
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "获取 CSRF token 失败"
            auth_url = self.signin(email, csrf_token)
            if not auth_url:
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "提交邮箱失败"
            final_url = self.authorize(auth_url)
            if not final_url:
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "Authorize 失败"
            final_path = urlparse(final_url).path
            if "api/accounts/authorize" in final_path or final_path == "/error":
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, f"预授权被拦截: {final_path}"
            break
        state = self._state_from_url(final_url)
        register_submitted = False
        otp_verified = False
        account_created = False
        seen_states = {}
        for _ in range(12):
            signature = self._state_signature(state)
            seen_states[signature] = seen_states.get(signature, 0) + 1
            if seen_states[signature] > 2:
                return False, f"注册状态卡住: {describe_flow_state(state)}"
            if self._is_registration_complete_state(state):
                self.last_registration_state = state
                return True, "注册成功"
            if self._state_is_password_registration(state):
                if register_submitted:
                    return False, "注册密码阶段重复进入"
                success, msg = self.register_user(email, password)
                if not success:
                    return False, f"注册失败: {msg}"
                register_submitted = True
                self.send_email_otp()
                state = self._state_from_url(f"{self.AUTH}/email-verification")
                continue
            if self._state_is_email_otp(state):
                otp_code = email_adapter.wait_for_verification_code(email, timeout=30)
                if not otp_code:
                    return False, "未收到验证码"
                success, next_state = self.verify_email_otp(otp_code, return_state=True)
                if not success:
                    return False, f"验证码失败: {next_state}"
                otp_verified = True
                state = next_state
                self.last_registration_state = state
                continue
            if self._state_is_about_you(state):
                if account_created:
                    return False, "填写信息阶段重复进入"
                success, next_state = self.create_account(first_name, last_name, birthdate, return_state=True)
                if not success:
                    return False, f"创建账号失败: {next_state}"
                account_created = True
                state = next_state
                self.last_registration_state = state
                continue
            if self._state_requires_navigation(state):
                success, next_state = self._follow_flow_state(state, referer=state.current_url or f"{self.AUTH}/about-you")
                if not success:
                    return False, f"跳转失败: {next_state}"
                state = next_state
                self.last_registration_state = state
                continue
            if (not register_submitted) and (not otp_verified) and (not account_created):
                state = self._state_from_url(f"{self.AUTH}/create-account/password")
                continue
            return False, f"未支持的注册状态: {describe_flow_state(state)}"
        return False, "注册状态机超出最大步数"


def run_registration_v2(
    *,
    email: str,
    password: str,
    first_name: str,
    last_name: str,
    birthdate: str,
    otp_fetcher: Callable[[int], Optional[str]],
    proxy_url: Optional[str] = None,
    logger: Optional[Callable[[str], None]] = None,
    max_retries: int = 3,
):
    last_error = "注册失败"
    for attempt in range(max(1, int(max_retries or 1))):
        client = ChatGPTClientV2(proxy=proxy_url, verbose=False, browser_mode="protocol")
        if logger:
            client._log = logger
        adapter = OTPFetcherAdapter(otp_fetcher)
        success, msg = client.register_complete_flow(email, password, first_name, last_name, birthdate, adapter)
        if not success:
            last_error = f"注册流失败: {msg}"
            if attempt < max_retries - 1 and should_retry_registration_v2(last_error):
                if logger:
                    logger(f"注册流失败，准备整流程重试: {msg}")
                continue
            return False, last_error
        session_ok, session_result = client.reuse_session_and_get_tokens()
        if session_ok:
            return True, session_result
        last_error = f"注册成功，但复用会话获取 AccessToken 失败: {session_result}"
        if attempt < max_retries - 1 and should_retry_registration_v2(last_error):
            if logger:
                logger(f"{last_error}，准备整流程重试")
            continue
        return False, last_error
    return False, last_error
