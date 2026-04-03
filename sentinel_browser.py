"""
Sentinel Token 浏览器批量生成器
通过 Playwright 加载 sentinel frame 页面，调用 SentinelSDK 批量生成所有 flow 的 token。
一次启动浏览器，生成 authorize_continue / username_password_create / oauth_create_account 等全部 token。
"""
import json
import time
from playwright.sync_api import sync_playwright

DEFAULT_FLOWS = [
    "authorize_continue",
    "username_password_create",
    "email_otp_validate",
    "password_verify",
    "oauth_create_account",
]

FRAME_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6"


def get_all_sentinel_tokens(flows=None, proxy=None, timeout_ms=60000):
    """
    一次启动 Playwright，批量生成所有 flow 的 sentinel token。

    返回:
        dict: {flow_name: token_json_string, ...}，失败的 flow 值为 None
    """
    flows = flows or DEFAULT_FLOWS
    print(f"  [Browser] 批量生成 sentinel token: {', '.join(flows)}")
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
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.92 Safari/537.36",
                locale="en-US",
                viewport={"width": 1920, "height": 1080},
            )
            page = context.new_page()
            page.goto(FRAME_URL, wait_until="load", timeout=timeout_ms)
            page.wait_for_timeout(8000)
            page.wait_for_function("() => !!window.SentinelSDK", timeout=30000)
            elapsed_load = time.time() - t_start
            print(f"  [Browser] SentinelSDK 已加载 ({elapsed_load:.1f}s)")

            result = page.evaluate(
                """async (flows) => {
                    const out = {};
                    if (!window.SentinelSDK) throw new Error('SentinelSDK missing');
                    for (const flow of flows) {
                        try {
                            await window.SentinelSDK.init(flow);
                            const tok = await window.SentinelSDK.token(flow);
                            out[flow] = tok || null;
                        } catch (e) {
                            out[flow] = null;
                        }
                    }
                    return out;
                }""",
                flows,
            )

            elapsed = time.time() - t_start
            tokens = {}
            for flow in flows:
                tok = result.get(flow) if result else None
                if tok:
                    try:
                        parsed = json.loads(tok)
                        has_t = bool(parsed.get("t"))
                        print(f"  [Browser] {flow}: OK (t:{'Y' if has_t else 'N'})")
                    except Exception:
                        print(f"  [Browser] {flow}: OK (len={len(tok)})")
                    tokens[flow] = tok
                else:
                    print(f"  [Browser] {flow}: FAIL")
                    tokens[flow] = None

            print(f"  [Browser] 批量完成 ({elapsed:.1f}s)")
            return tokens

        except Exception as e:
            elapsed = time.time() - t_start
            print(f"  [Browser] 异常 ({elapsed:.1f}s): {e}")
            return {f: None for f in flows}
        finally:
            browser.close()


def get_sentinel_token_via_browser(flow="oauth_create_account", proxy=None, timeout_ms=45000):
    """单个 flow 的兼容接口"""
    tokens = get_all_sentinel_tokens(flows=[flow], proxy=proxy, timeout_ms=timeout_ms)
    return tokens.get(flow)
