"""
Sentinel Token 浏览器批量生成器
通过 Playwright 加载 sentinel frame 页面，调用 SentinelSDK 批量生成所有 flow 的 token。
一次启动浏览器，生成 authorize_continue / username_password_create / oauth_create_account 等全部 token。
"""
import json
import os
import time
from playwright.sync_api import sync_playwright

DEFAULT_FLOWS = [
    "authorize_continue",
    "username_password_create",
    "email_otp_validate",
    "password_verify",
    "oauth_create_account",
]
_LOG_PREFIX = ""


def set_browser_log_prefix(prefix: str = "") -> None:
    global _LOG_PREFIX
    _LOG_PREFIX = str(prefix or "")


def _browser_log(message: str) -> None:
    prefix = str(_LOG_PREFIX or "")
    if prefix:
        print(f"{prefix}{message}")
    else:
        print(message)

SDK_URL = os.environ.get(
    "SDK_URL",
    "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
).strip()
UA = os.environ.get(
    "UA",
    (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
).strip()
FRAME_URL = os.environ.get(
    "FRAME_URL",
    "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
).strip()


def _normalize_flow_list(flows=None):
    normalized = [str(flow or "").strip() for flow in (flows or DEFAULT_FLOWS)]
    return [flow for flow in normalized if flow] or list(DEFAULT_FLOWS)


def _compact_json_string(value):
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _extract_flow_payload(result, flow):
    if not isinstance(result, dict):
        return None, None

    flows_payload = result.get("flows")
    if isinstance(flows_payload, dict):
        flow_payload = flows_payload.get(flow)
        if isinstance(flow_payload, dict):
            return flow_payload.get("token"), flow_payload.get("soToken")
        return flow_payload, None

    flow_payload = result.get(flow)
    if isinstance(flow_payload, dict) and ("token" in flow_payload or "soToken" in flow_payload):
        return flow_payload.get("token"), flow_payload.get("soToken")
    return flow_payload, None


def get_all_sentinel_artifacts(flows=None, proxy=None, timeout_ms=60000, user_agent=None):
    """
    严格按参考脚本的 Playwright Sentinel 采集方式，返回完整 flow 数据。

    返回:
        dict: 参考脚本风格的完整结果，含 flows.{flow}.token / soToken / cookieAfter
    """
    flows = _normalize_flow_list(flows)
    effective_user_agent = str(user_agent or UA or "").strip() or UA
    t_start = time.time()

    with sync_playwright() as p:
        launch_args = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-blink-features=AutomationControlled"],
        }
        if proxy:
            launch_args["proxy"] = {"server": proxy}

        browser = p.chromium.launch(**launch_args)
        try:
            context = browser.new_context(
                user_agent=effective_user_agent,
                locale="en-US",
                viewport={"width": 1920, "height": 1080},
            )
            page = context.new_page()
            page.goto(FRAME_URL, wait_until="load", timeout=timeout_ms)
            page.wait_for_timeout(8000)
            page.wait_for_function("() => !!window.SentinelSDK", timeout=30000)
            elapsed_load = time.time() - t_start
            _browser_log(f"  [Browser] SentinelSDK 已加载 ({elapsed_load:.1f}s)")

            result = page.evaluate(
                """async (flows) => {
                    const out = {
                        source: 'playwright_sentinel_multi_helper',
                        generatedAt: new Date().toISOString(),
                        frameUrl: location.href,
                        sdkUrl: document.currentScript?.src || null,
                        userAgent: navigator.userAgent,
                        userAgentData: navigator.userAgentData ? navigator.userAgentData.toJSON() : null,
                        cookieBefore: document.cookie,
                        flows: {},
                    };
                    if (!window.SentinelSDK) throw new Error('SentinelSDK missing');
                    for (const flow of flows) {
                        await window.SentinelSDK.init(flow);
                        const tok = await window.SentinelSDK.token(flow);
                        let soTok = null;
                        try {
                            soTok = await window.SentinelSDK.sessionObserverToken(flow);
                        } catch (e) {
                            soTok = null;
                        }
                        out.flows[flow] = {
                            flow,
                            token: tok ? JSON.parse(tok) : null,
                            soToken: soTok ? JSON.parse(soTok) : null,
                            cookieAfter: document.cookie,
                        };
                    }
                    return out;
                }""",
                flows,
            )

            if isinstance(result, dict) and not result.get("sdkUrl"):
                result["sdkUrl"] = SDK_URL or None
            return result or {"flows": {}}
        finally:
            browser.close()


def get_all_sentinel_tokens(flows=None, proxy=None, timeout_ms=60000, user_agent=None):
    """
    一次启动 Playwright，批量生成所有 flow 的 sentinel token。

    返回:
        dict: {flow_name: token_json_string, ...}，失败的 flow 值为 None
    """
    flows = _normalize_flow_list(flows)
    _browser_log(f"  [Browser] 批量生成 sentinel token: {', '.join(flows)}")
    t_start = time.time()

    try:
        result = get_all_sentinel_artifacts(
            flows=flows,
            proxy=proxy,
            timeout_ms=timeout_ms,
            user_agent=user_agent,
        )
    except Exception as e:
        elapsed = time.time() - t_start
        _browser_log(f"  [Browser] 异常 ({elapsed:.1f}s): {e}")
        return {f: None for f in flows}

    elapsed = time.time() - t_start
    tokens = {}
    for flow in flows:
        raw_token, raw_so_token = _extract_flow_payload(result, flow)
        token = _compact_json_string(raw_token)
        so_token = _compact_json_string(raw_so_token)
        if token:
            try:
                parsed = json.loads(token)
                has_t = bool(parsed.get("t"))
                _browser_log(
                    f"  [Browser] {flow}: OK"
                    f" (t:{'Y' if has_t else 'N'}, so:{'Y' if bool(so_token) else 'N'})"
                )
            except Exception:
                _browser_log(f"  [Browser] {flow}: OK (len={len(token)}, so:{'Y' if bool(so_token) else 'N'})")
            tokens[flow] = token
        else:
            _browser_log(f"  [Browser] {flow}: FAIL")
            tokens[flow] = None

    _browser_log(f"  [Browser] 批量完成 ({elapsed:.1f}s)")
    return tokens


def get_sentinel_token_via_browser(flow="oauth_create_account", proxy=None, timeout_ms=45000, user_agent=None):
    """单个 flow 的兼容接口"""
    tokens = get_all_sentinel_tokens(
        flows=[flow],
        proxy=proxy,
        timeout_ms=timeout_ms,
        user_agent=user_agent,
    )
    return tokens.get(flow)
