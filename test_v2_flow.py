import unittest
import sys
import types
from pathlib import Path


fake_curl_cffi = types.ModuleType("curl_cffi")
fake_curl_cffi.requests = types.SimpleNamespace()
sys.modules.setdefault("curl_cffi", fake_curl_cffi)


class V2FlowTests(unittest.TestCase):
    def test_default_config_prefers_lamail_with_secret_mappings(self):
        config = Path("config.json").read_text(encoding="utf-8")

        self.assertIn('"mail_provider": "lamail"', config)
        self.assertIn('"lamail_api_key_env": "LAMAIL_API_KEY"', config)
        self.assertIn('"lamail_domain_env": "LAMAIL_DOMAIN"', config)

    def test_should_retry_registration_v2_matches_reference_markers(self):
        from ncs_runtime.v2_flow import should_retry_registration_v2

        self.assertTrue(should_retry_registration_v2("预授权被拦截: /authorize"))
        self.assertTrue(should_retry_registration_v2("注册成功，但复用会话获取 AccessToken 失败"))
        self.assertTrue(should_retry_registration_v2("验证码失败: timeout"))
        self.assertFalse(should_retry_registration_v2("邮箱已被注册且不允许继续"))

    def test_otp_fetcher_adapter_calls_existing_timeout_signature(self):
        from ncs_runtime.v2_flow import OTPFetcherAdapter

        seen = []

        def fetcher(timeout):
            seen.append(timeout)
            return "123456"

        adapter = OTPFetcherAdapter(fetcher)

        code = adapter.wait_for_verification_code("user@example.com", timeout=27)

        self.assertEqual(code, "123456")
        self.assertEqual(seen, [27])


if __name__ == "__main__":
    unittest.main()
