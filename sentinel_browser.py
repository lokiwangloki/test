"""
Sentinel Token 浏览器辅助生成器
通过 Playwright 加载 auth.openai.com 页面，调用 SentinelSDK.token() 获取完整 token。
只用于 create_account 步骤（需要 Turnstile t 字段）。
"""
import json
import time
from playwright.sync_api import sync_playwright


def get_sentinel_token_via_browser(flow="oauth_create_account", proxy=None, timeout_ms=45000):
    """
    通过 Playwright 无头浏览器获取完整的 sentinel token（含 p/t/c 三个字段）。

    返回:
        str: openai-sentinel-token 头的值（JSON 字符串），失败返回 None
    """
    print(f"  [Browser] 启动 Playwright (flow={flow})...")
    t_start = time.time()

    with sync_playwright() as p:
        launch_args = {
            "headless": True,
            "args": [
                "--no-sandbox",
                "--disable-blink-features=AutomationControlled",
            ],
        }
        if proxy:
            launch_args["proxy"] = {"server": proxy}

        browser = p.chromium.launch(**launch_args)

        try:
            context = browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.92 Safari/537.36",
                ignore_https_errors=True,
            )
            page = context.new_page()

            page.goto("https://auth.openai.com/about-you", wait_until="domcontentloaded", timeout=timeout_ms)
            elapsed_nav = time.time() - t_start
            print(f"  [Browser] 页面加载完成 ({elapsed_nav:.1f}s)")

            page.wait_for_function(
                "() => typeof window.SentinelSDK !== 'undefined' && typeof window.SentinelSDK.token === 'function'",
                timeout=15000,
            )
            print(f"  [Browser] SentinelSDK 已加载")

            result = page.evaluate("""
                async (flow) => {
                    try {
                        const token = await window.SentinelSDK.token(flow);
                        return { success: true, token: token };
                    } catch (e) {
                        return { success: false, error: e.message || String(e) };
                    }
                }
            """, flow)

            elapsed = time.time() - t_start

            if result and result.get("success") and result.get("token"):
                token = result["token"]
                try:
                    parsed = json.loads(token)
                    has_p = bool(parsed.get("p"))
                    has_t = bool(parsed.get("t"))
                    has_c = bool(parsed.get("c"))
                    print(f"  [Browser] sentinel 成功 ({elapsed:.1f}s) | p:{'Y' if has_p else 'N'} t:{'Y' if has_t else 'N'} c:{'Y' if has_c else 'N'}")
                    return token
                except json.JSONDecodeError:
                    print(f"  [Browser] sentinel 成功 ({elapsed:.1f}s) | len={len(token)}")
                    return token
            else:
                error = result.get("error", "unknown") if result else "no result"
                print(f"  [Browser] sentinel 失败 ({elapsed:.1f}s): {error}")
                return None

        except Exception as e:
            elapsed = time.time() - t_start
            print(f"  [Browser] 异常 ({elapsed:.1f}s): {e}")
            return None
        finally:
            browser.close()
