"""
Sentinel Token 浏览器辅助生成器 v3
通过 Playwright 加载 auth.openai.com 页面，拦截 sentinel token 的网络请求/响应。

核心思路：不去 postMessage，而是让 SDK 自然运行，
拦截它发出的 /backend-api/sentinel/req 请求和对 create_account 的 openai-sentinel-token 头。
"""
import json
import time
from playwright.sync_api import sync_playwright


def get_sentinel_token_via_browser(flow="oauth_create_account", proxy=None, timeout_ms=45000):
    """
    通过 Playwright 无头浏览器获取完整的 sentinel token。
    
    方案：在页面上执行 JavaScript 调用 SentinelSDK.token(flow)，
    该调用会自动完成 PoW + Turnstile VM，返回最终可用的 JSON 字符串。
    
    返回:
        str: openai-sentinel-token 头的值（JSON 字符串），失败返回 None
    """
    print(f"  🌐 [Browser] 启动 Playwright (flow={flow})...")
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
            
            # 导航到 auth 页面
            page.goto("https://auth.openai.com/about-you", wait_until="domcontentloaded", timeout=timeout_ms)
            elapsed_nav = time.time() - t_start
            print(f"  🌐 [Browser] 页面加载完成 ({elapsed_nav:.1f}s)")
            
            # 等待 sentinel SDK 加载完成（监测全局 SentinelSDK 对象）
            page.wait_for_function(
                "() => typeof window.SentinelSDK !== 'undefined' && typeof window.SentinelSDK.token === 'function'",
                timeout=15000,
            )
            print(f"  🌐 [Browser] SentinelSDK 已加载")
            
            # 调用 SentinelSDK.token(flow) 获取完整 token
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
                # 验证 token 结构
                try:
                    parsed = json.loads(token)
                    has_p = bool(parsed.get("p"))
                    has_t = bool(parsed.get("t"))
                    has_c = bool(parsed.get("c"))
                    print(f"  🌐 [Browser] ✅ 成功 ({elapsed:.1f}s) | p:{'✓' if has_p else '✗'} t:{'✓' if has_t else '✗'} c:{'✓' if has_c else '✗'}")
                    return token
                except json.JSONDecodeError:
                    # 可能不是 JSON，但仍然是有效 token
                    print(f"  🌐 [Browser] ✅ 成功 ({elapsed:.1f}s) | 长度:{len(token)}")
                    return token
            else:
                error = result.get("error", "unknown") if result else "no result"
                print(f"  🌐 [Browser] ❌ SDK 调用失败 ({elapsed:.1f}s): {error}")
                return None
            
        except Exception as e:
            elapsed = time.time() - t_start
            print(f"  🌐 [Browser] ❌ 异常 ({elapsed:.1f}s): {e}")
            return None
        finally:
            browser.close()


if __name__ == "__main__":
    import sys
    proxy = "http://127.0.0.1:7897"
    flow = sys.argv[1] if len(sys.argv) > 1 else "oauth_create_account"
    
    print(f"测试 sentinel token (flow={flow})\n")
    
    token = get_sentinel_token_via_browser(flow=flow, proxy=proxy, timeout_ms=45000)
    if token:
        print(f"\n✅ 成功！长度: {len(token)}")
        try:
            parsed = json.loads(token)
            for k, v in parsed.items():
                val = str(v)
                if len(val) > 100:
                    val = val[:100] + "..."
                print(f"  {k}: {val}")
        except:
            print(f"  前200字符: {token[:200]}")
    else:
        print("\n❌ 失败")
