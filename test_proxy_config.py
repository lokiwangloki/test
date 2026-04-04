import unittest
import sys
import types
import base64
import io
import json
from pathlib import Path
from unittest import mock

import auto_scheduler

fake_curl_cffi = types.ModuleType("curl_cffi")
fake_curl_cffi.requests = types.SimpleNamespace()
sys.modules.setdefault("curl_cffi", fake_curl_cffi)

import ncs_register
import ncs_register_legacy
import protocol_keygen
import sentinel_browser
from ncs_runtime import batch as runtime_batch, email_services, engine as runtime_engine


class ProxyNormalizationTests(unittest.TestCase):
    def test_extract_stage_failure_reason_prefers_specific_failure_line(self):
        output = "\n".join([
            "进度: [===>] 10%",
            "[existing-session] authorize: 302",
            "❌ 未获取到 authorization code",
        ])

        reason = runtime_engine._extract_stage_failure_reason(output, "OAuth Token 获取失败")

        self.assertEqual(reason, "未获取到 authorization code")

    def test_extract_stage_failure_reason_prefers_token_recovery_context_over_generic_oauth_failure(self):
        output = "\n".join([
            "[existing-session] authorize: 302",
            "[existing-session] session endpoint: 200",
            "[existing-session] 未能直接获取 token，回退浏览器辅助登录",
        ])

        reason = runtime_engine._extract_stage_failure_reason(output, "OAuth Token 获取失败")

        self.assertEqual(reason, "未能直接获取 token，回退浏览器辅助登录")

    def test_extract_stage_failure_reason_prefers_specific_transport_error_over_retry_summary(self):
        output = "\n".join([
            "❌ OAuth 授权请求失败: timed out",
            "❌ 重试次数耗尽，OAuth 授权失败",
        ])

        reason = runtime_engine._extract_stage_failure_reason(output, "OAuth Token 获取失败")

        self.assertEqual(reason, "OAuth 授权请求失败: timed out")

    def test_extract_stage_failure_reason_strips_nested_stage_prefix(self):
        output = "[tmpuser] [仅注册] ❌注册失败: 未能获取验证码"

        reason = runtime_engine._extract_stage_failure_reason(output, "OAuth Token 获取失败")

        self.assertEqual(reason, "未能获取验证码")

    def test_extract_stage_failure_reason_prefers_browser_bootstrap_failure_detail(self):
        output = "\n".join([
            "login_session: ❌ 未获取",
            "浏览器兜底失败: playwright import failed: No module named 'playwright'",
        ])

        reason = runtime_engine._extract_stage_failure_reason(output, "注册失败")

        self.assertEqual(reason, "浏览器兜底失败: playwright import failed: No module named 'playwright'")

    def test_load_oauth_browser_tokens_uses_registration_user_agent(self):
        fake_module = types.ModuleType("sentinel_browser")
        fake_module.get_all_sentinel_tokens = mock.Mock(
            return_value={
                "authorize_continue": '{"flow":"authorize_continue","c":"browser-ac"}',
                "password_verify": '{"flow":"password_verify","c":"browser-pwd"}',
            }
        )

        with mock.patch.dict(sys.modules, {"sentinel_browser": fake_module}):
            tokens = protocol_keygen._load_oauth_browser_tokens(
                flows=["authorize_continue", "password_verify"],
                proxy="http://127.0.0.1:9000",
                timeout_ms=12345,
            )

        self.assertEqual(
            tokens,
            {
                "authorize_continue": '{"flow":"authorize_continue","c":"browser-ac"}',
                "password_verify": '{"flow":"password_verify","c":"browser-pwd"}',
            },
        )
        fake_module.get_all_sentinel_tokens.assert_called_once_with(
            flows=["authorize_continue", "password_verify"],
            proxy="http://127.0.0.1:9000",
            timeout_ms=12345,
            user_agent=protocol_keygen.COMMON_HEADERS.get("user-agent", "") or protocol_keygen.USER_AGENT,
        )

    def test_sentinel_browser_get_all_sentinel_tokens_normalizes_reference_payload(self):
        class FakePage:
            def __init__(self):
                self.goto_args = None
                self.wait_timeout_ms = None
                self.wait_function_args = None

            def goto(self, url, **kwargs):
                self.goto_args = (url, kwargs)

            def wait_for_timeout(self, timeout_ms):
                self.wait_timeout_ms = timeout_ms

            def wait_for_function(self, expression, **kwargs):
                self.wait_function_args = (expression, kwargs)

            def evaluate(self, script, flows):
                del script
                self.flows = list(flows)
                return {
                    "source": "playwright_sentinel_multi_helper",
                    "generatedAt": "2026-04-04T00:00:00Z",
                    "frameUrl": sentinel_browser.FRAME_URL,
                    "sdkUrl": sentinel_browser.SDK_URL,
                    "userAgent": "UA-123",
                    "userAgentData": None,
                    "cookieBefore": "",
                    "flows": {
                        "authorize_continue": {
                            "flow": "authorize_continue",
                            "token": {
                                "p": "pow-1",
                                "t": "turn-1",
                                "c": "challenge-1",
                                "id": "did-1",
                                "flow": "authorize_continue",
                            },
                            "soToken": {"observer": "yes"},
                            "cookieAfter": "cf_clearance=1",
                        },
                        "password_verify": {
                            "flow": "password_verify",
                            "token": None,
                            "soToken": None,
                            "cookieAfter": "cf_clearance=1",
                        },
                    },
                }

        class FakeContext:
            def __init__(self, page):
                self.page = page

            def new_page(self):
                return self.page

        class FakeBrowser:
            def __init__(self, page):
                self.page = page
                self.context_kwargs = None
                self.closed = False

            def new_context(self, **kwargs):
                self.context_kwargs = dict(kwargs)
                return FakeContext(self.page)

            def close(self):
                self.closed = True

        class FakeChromium:
            def __init__(self, browser):
                self.browser = browser
                self.launch_kwargs = None

            def launch(self, **kwargs):
                self.launch_kwargs = dict(kwargs)
                return self.browser

        class FakePlaywrightManager:
            def __init__(self, chromium):
                self.chromium = chromium

        class FakePlaywrightContext:
            def __init__(self, chromium):
                self.playwright = FakePlaywrightManager(chromium)

            def __enter__(self):
                return self.playwright

            def __exit__(self, exc_type, exc, tb):
                del exc_type, exc, tb
                return False

        fake_page = FakePage()
        fake_browser = FakeBrowser(fake_page)
        fake_chromium = FakeChromium(fake_browser)

        with mock.patch.object(
            sentinel_browser,
            "sync_playwright",
            return_value=FakePlaywrightContext(fake_chromium),
        ):
            tokens = sentinel_browser.get_all_sentinel_tokens(
                flows=["authorize_continue", "password_verify"],
                proxy="http://127.0.0.1:8000",
                timeout_ms=120000,
                user_agent="UA-123",
            )

        self.assertEqual(
            tokens["authorize_continue"],
            '{"p":"pow-1","t":"turn-1","c":"challenge-1","id":"did-1","flow":"authorize_continue"}',
        )
        self.assertIsNone(tokens["password_verify"])
        self.assertEqual(fake_chromium.launch_kwargs["proxy"], {"server": "http://127.0.0.1:8000"})
        self.assertEqual(fake_browser.context_kwargs["user_agent"], "UA-123")
        self.assertEqual(fake_page.goto_args[0], sentinel_browser.FRAME_URL)
        self.assertEqual(fake_page.wait_timeout_ms, 8000)

    def test_progress_uses_line_mode_in_github_actions(self):
        with mock.patch.dict("os.environ", {"GITHUB_ACTIONS": "true"}, clear=False):
            with mock.patch("sys.stdout.isatty", return_value=True):
                self.assertFalse(ncs_register_legacy._progress_uses_inline_mode())

    def test_run_cpa_upload_with_compact_log_only_prints_terminal_status(self):
        def fake_upload():
            print("============================================================")
            print("  [CPA] 开始上传 3 个账号到 CPA 管理平台")
            print("  [CPA] 上传完成: 成功 1 个, 失败 2 个")

        output = io.StringIO()
        with mock.patch.dict("os.environ", {}, clear=False):
            with mock.patch.object(ncs_register_legacy, "_upload_all_tokens_to_cpa", side_effect=fake_upload):
                with mock.patch("sys.stdout", new=output):
                    uploaded, failed, reason = runtime_batch._run_cpa_upload_with_compact_log()

        self.assertEqual((uploaded, failed), (1, 2))
        self.assertEqual(reason, "成功 1 个, 失败 2 个")
        self.assertEqual(output.getvalue().strip(), "[CPA上传] ❌上传失败: 成功 1 个, 失败 2 个")

    def test_run_cpa_upload_replays_verbose_logs_in_github_actions(self):
        def fake_upload():
            print("============================================================")
            print("  [CPA] 开始上传 3 个账号到 CPA 管理平台")
            print("  [CPA] 上传完成: 成功 1 个, 失败 0 个")

        output = io.StringIO()
        with mock.patch.dict("os.environ", {"GITHUB_ACTIONS": "true"}, clear=False):
            with mock.patch.object(ncs_register_legacy, "_upload_all_tokens_to_cpa", side_effect=fake_upload):
                with mock.patch("sys.stdout", new=output):
                    uploaded, failed, reason = runtime_batch._run_cpa_upload_with_compact_log()

        self.assertEqual((uploaded, failed, reason), (1, 0, ""))
        rendered = output.getvalue()
        self.assertIn("[CPA] 开始上传 3 个账号到 CPA 管理平台", rendered)
        self.assertIn("[CPA] 上传完成: 成功 1 个, 失败 0 个", rendered)
        self.assertIn("[CPA上传] ✅上传成功", rendered)

    def test_otp_message_ids_are_not_reused_across_calls(self):
        register = ncs_register_legacy.ChatGPTRegister.__new__(ncs_register_legacy.ChatGPTRegister)

        first = ncs_register_legacy._filter_unseen_otp_messages(
            register,
            key="lamail:user@example.com",
            messages=[{"id": "msg-1", "subject": "Your ChatGPT code is 123456"}],
            id_getter=lambda msg: str(msg.get("id") or ""),
        )
        second = ncs_register_legacy._filter_unseen_otp_messages(
            register,
            key="lamail:user@example.com",
            messages=[{"id": "msg-1", "subject": "Your ChatGPT code is 123456"}],
            id_getter=lambda msg: str(msg.get("id") or ""),
        )

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])

    def test_ncs_register_default_proxy_is_disabled(self):
        self.assertEqual(ncs_register._normalize_proxy_value(""), "")
        self.assertEqual(ncs_register._normalize_proxy_value("填入您自己的代理地址"), "")
        self.assertEqual(ncs_register._normalize_proxy_value("direct"), "")

    def test_auto_scheduler_placeholder_proxy_is_disabled(self):
        self.assertEqual(auto_scheduler._normalize_proxy_value(""), "")
        self.assertEqual(auto_scheduler._normalize_proxy_value("填写你的代理"), "")
        self.assertEqual(auto_scheduler._normalize_proxy_value("http://127.0.0.1:7890"), "http://127.0.0.1:7890")

    def test_ncs_register_load_config_supports_env_name_mapping(self):
        fake_config = {
            "lamail_api_key": "",
            "lamail_api_key_env": "MY_LAMAIL_KEY",
            "lamail_domain": "",
            "lamail_domain_env": "MY_LAMAIL_DOMAIN",
            "wildmail_api_base": "",
            "wildmail_api_base_env": "MY_WILDMAIL_API_BASE",
            "wildmail_api_key": "",
            "wildmail_api_key_env": "MY_WILDMAIL_API_KEY",
        }
        with mock.patch.dict("os.environ", {
            "MY_LAMAIL_KEY": "secret-key",
            "MY_LAMAIL_DOMAIN": "mail.example.com",
            "MY_WILDMAIL_API_BASE": "https://mail.example.com",
            "MY_WILDMAIL_API_KEY": "wildmail-secret",
        }, clear=False):
            with mock.patch("ncs_register.os.path.exists", return_value=True):
                with mock.patch("builtins.open", mock.mock_open(read_data="{}")):
                    with mock.patch("ncs_register.json.load", return_value=fake_config):
                        config = ncs_register._load_config()

        self.assertEqual(config["lamail_api_key"], "secret-key")
        self.assertEqual(config["lamail_domain"], "mail.example.com")
        self.assertEqual(config["wildmail_api_base"], "https://mail.example.com")
        self.assertEqual(config["wildmail_api_key"], "wildmail-secret")

    def test_auto_scheduler_load_account_count_config_supports_env_name_mapping(self):
        fake_config = {
            "upload_api_url": "",
            "upload_api_url_env": "MY_UPLOAD_URL",
            "upload_api_token": "",
            "upload_api_token_env": "MY_UPLOAD_TOKEN",
        }
        with mock.patch.dict("os.environ", {
            "MY_UPLOAD_URL": "https://upload.example.com",
            "MY_UPLOAD_TOKEN": "upload-token",
        }, clear=False):
            with mock.patch("auto_scheduler.os.path.exists", return_value=True):
                with mock.patch("builtins.open", mock.mock_open(read_data="{}")):
                    with mock.patch("auto_scheduler.json.load", return_value=fake_config):
                        config = auto_scheduler._load_account_count_config()

        self.assertEqual(config["upload_api_url"], "https://upload.example.com")
        self.assertEqual(config["upload_api_token"], "upload-token")

    def test_auto_scheduler_build_register_input_matches_cli_prompt_order(self):
        cfg = {
            "proxy": "",
            "upload_api_url": "http://example.invalid/v0/management/auth-files",
        }
        params = {
            "proxy": "",
            "preflight": "n",
            "output_file": "registered_accounts.txt",
            "total_accounts": 500,
            "max_workers": 3,
            "cpa_cleanup": "n",
            "cpa_upload_every_n": 3,
        }
        with mock.patch.dict("os.environ", {
            "HTTPS_PROXY": "",
            "https_proxy": "",
            "ALL_PROXY": "",
            "all_proxy": "",
        }, clear=False):
            stdin_input = auto_scheduler.build_register_input(params, cfg)
        self.assertEqual(
            stdin_input,
            "\nn\nregistered_accounts.txt\n500\n3\nn\n3\n",
        )

    def test_auto_scheduler_defaults_target_1000_accounts(self):
        self.assertEqual(auto_scheduler.ACCOUNT_THRESHOLD, 1000)
        self.assertEqual(auto_scheduler.AUTO_PARAMS["total_accounts"], 1000)

    def test_auto_scheduler_defaults_register_workers_to_3(self):
        self.assertEqual(auto_scheduler.AUTO_PARAMS["max_workers"], 3)

    def test_auto_scheduler_uploads_each_success_immediately_by_default(self):
        self.assertEqual(auto_scheduler.AUTO_PARAMS["cpa_upload_every_n"], 1)

    def test_save_tokens_uses_module_file_lock(self):
        fake_lock = mock.MagicMock()
        fake_lock.__enter__.return_value = None
        fake_lock.__exit__.return_value = False

        with mock.patch.object(protocol_keygen, "_file_lock", fake_lock):
            with mock.patch("builtins.open", mock.mock_open()):
                with mock.patch("protocol_keygen.save_token_json") as save_json_mock:
                    protocol_keygen.save_tokens(
                        "user@example.com",
                        {
                            "access_token": "access-123",
                            "refresh_token": "refresh-123",
                            "id_token": "id-123",
                        },
                    )

        fake_lock.__enter__.assert_called_once()
        fake_lock.__exit__.assert_called_once()
        save_json_mock.assert_called_once_with(
            "user@example.com",
            "access-123",
            "refresh-123",
            "id-123",
        )

    def test_run_once_registers_only_missing_gap(self):
        cfg = {"upload_api_url": "", "upload_api_token": ""}
        with mock.patch("auto_scheduler._load_account_count_config", return_value=cfg):
            with mock.patch("auto_scheduler.count_valid_accounts_local", side_effect=[999, 1000]):
                with mock.patch("auto_scheduler.trigger_registration", return_value=True) as trigger_mock:
                    result = auto_scheduler.run_once()

        self.assertTrue(result)
        params, passed_cfg = trigger_mock.call_args[0]
        self.assertEqual(params["total_accounts"], 1)
        self.assertEqual(passed_cfg, cfg)

    def test_run_once_returns_false_when_trigger_registration_fails(self):
        cfg = {"upload_api_url": "", "upload_api_token": ""}
        with mock.patch("auto_scheduler._load_account_count_config", return_value=cfg):
            with mock.patch("auto_scheduler.count_valid_accounts_local", return_value=999):
                with mock.patch("auto_scheduler.trigger_registration", return_value=False):
                    self.assertFalse(auto_scheduler.run_once())

    def test_run_once_returns_false_when_post_registration_recount_stays_below_threshold(self):
        cfg = {"upload_api_url": "", "upload_api_token": ""}
        with mock.patch("auto_scheduler._load_account_count_config", side_effect=[cfg, cfg]):
            with mock.patch("auto_scheduler.count_valid_accounts_local", side_effect=[999, 999]) as count_mock:
                with mock.patch("auto_scheduler.trigger_registration", return_value=True):
                    self.assertFalse(auto_scheduler.run_once())

        self.assertEqual(count_mock.call_count, 2)

    def test_run_once_returns_true_when_post_registration_recount_reaches_threshold(self):
        cfg = {"upload_api_url": "", "upload_api_token": ""}
        with mock.patch("auto_scheduler._load_account_count_config", side_effect=[cfg, cfg]):
            with mock.patch("auto_scheduler.count_valid_accounts_local", side_effect=[999, 1000]) as count_mock:
                with mock.patch("auto_scheduler.trigger_registration", return_value=True):
                    self.assertTrue(auto_scheduler.run_once())

        self.assertEqual(count_mock.call_count, 2)

    def test_run_once_forces_total_accounts_override_even_above_threshold(self):
        cfg = {"upload_api_url": "", "upload_api_token": ""}
        with mock.patch.dict("os.environ", {"AUTO_SCHEDULER_FORCE_TOTAL_ACCOUNTS": "10000"}, clear=False):
            with mock.patch("auto_scheduler._load_account_count_config", side_effect=[cfg, cfg]):
                with mock.patch("auto_scheduler.count_valid_accounts_local", side_effect=[1200, 1200]):
                    with mock.patch("auto_scheduler.trigger_registration", return_value=True) as trigger_mock:
                        result = auto_scheduler.run_once()

        self.assertTrue(result)
        params, passed_cfg = trigger_mock.call_args[0]
        self.assertEqual(params["total_accounts"], 10000)
        self.assertEqual(passed_cfg, cfg)

    def test_cpa_root_url_normalizes_to_management_auth_files(self):
        self.assertEqual(
            auto_scheduler._cpa_auth_files_url("http://example.com:8317"),
            "http://example.com:8317/v0/management/auth-files",
        )
        self.assertEqual(
            ncs_register_legacy._cpa_normalize_api_root("http://example.com:8317"),
            "http://example.com:8317/v0/management",
        )

    def test_auto_scheduler_main_runs_once_without_sleep(self):
        with mock.patch("auto_scheduler._load_account_count_config", return_value={}):
            with mock.patch("auto_scheduler.count_valid_accounts_local", side_effect=[999, 1000]):
                with mock.patch("auto_scheduler.trigger_registration", return_value=True):
                    with mock.patch("auto_scheduler.time.sleep") as sleep_mock:
                        auto_scheduler.main()

        sleep_mock.assert_not_called()

    def test_scheduler_workflow_uses_staggered_cron(self):
        workflow = Path(".github/workflows/scheduler.yml").read_text(encoding="utf-8")
        self.assertIn("cron: '3,33 * * * *'", workflow)

    def test_auto_scheduler_retries_transient_auth_files_dns_error(self):
        class FakeResponse:
            status_code = 200

            @staticmethod
            def json():
                return {"files": []}

        transient_error = Exception(
            "Failed to perform, curl: (6) Could not resolve host: cpa.lokiwang.ccwu.cc"
        )
        fake_requests = sys.modules["curl_cffi"].requests
        with mock.patch.object(fake_requests, "get", side_effect=[transient_error, FakeResponse()], create=True) as get_mock:
            with mock.patch("auto_scheduler.count_valid_accounts_local", return_value=123) as local_count_mock:
                with mock.patch("auto_scheduler.time.sleep") as sleep_mock:
                    count = auto_scheduler.count_valid_accounts_by_probe({
                        "upload_api_url": "https://cpa.lokiwang.ccwu.cc/v0/management/auth-files",
                        "upload_api_token": "token",
                    })

        self.assertEqual(count, 0)
        self.assertEqual(get_mock.call_count, 2)
        sleep_mock.assert_called_once()
        local_count_mock.assert_not_called()

    def test_scheduler_workflow_includes_cpa_dns_diagnostics(self):
        workflow = Path(".github/workflows/scheduler.yml").read_text(encoding="utf-8")
        self.assertIn("Diagnose CPA DNS", workflow)
        self.assertIn("LAMAIL_DOMAIN", workflow)
        self.assertIn("LAMAIL_API_KEY", workflow)
        self.assertIn("MAIL_PROVIDER", workflow)
        self.assertIn("PROXY", workflow)
        self.assertIn("UPLOAD_API_PROXY", workflow)

    def test_scheduler_workflow_cfmail_diagnose_prefers_active_cached_domain(self):
        workflow = Path(".github/workflows/scheduler.yml").read_text(encoding="utf-8")
        self.assertIn("zhuce5_cfmail_accounts.json", workflow)
        self.assertIn("active_domain", workflow)
        self.assertIn("item.get('enabled', True)", workflow)
        self.assertIn("ed = active_domain or os.environ.get('CFMAIL_EMAIL_DOMAIN','').strip()", workflow)

    def test_scheduler_workflow_supports_manual_total_accounts_override(self):
        workflow = Path(".github/workflows/scheduler.yml").read_text(encoding="utf-8")
        self.assertIn("total_accounts_override:", workflow)
        self.assertIn("AUTO_SCHEDULER_FORCE_TOTAL_ACCOUNTS:", workflow)
        self.assertIn("github.event.inputs.total_accounts_override", workflow)

    def test_scheduler_workflow_caps_cfmail_startup_domain_pool_for_8_workers(self):
        workflow = Path(".github/workflows/scheduler.yml").read_text(encoding="utf-8")
        self.assertIn("ZHUCE6_CFMAIL_ACTIVE_DOMAIN_COUNT: 2", workflow)

    def test_scheduler_workflow_does_not_block_cfmail_on_wildmail_diagnose(self):
        workflow = Path(".github/workflows/scheduler.yml").read_text(encoding="utf-8")
        self.assertIn("Diagnose Wildmail", workflow)
        self.assertIn("continue-on-error: true", workflow)

    def test_mailbox_service_factory_supports_cfmail_lamail_tempmail_and_wildmail(self):
        fake_register = object()
        self.assertIsInstance(
            ncs_register._build_mailbox_service(fake_register, "cfmail"),
            email_services.CfmailMailboxService,
        )
        self.assertIsInstance(
            ncs_register._build_mailbox_service(fake_register, "lamail"),
            ncs_register.LaMailMailboxService,
        )
        self.assertIsInstance(
            ncs_register._build_mailbox_service(fake_register, "tempmail_lol"),
            ncs_register.TempmailLolMailboxService,
        )
        self.assertIsInstance(
            ncs_register._build_mailbox_service(fake_register, "wildmail"),
            email_services.WildmailMailboxService,
        )
        with self.assertRaises(ValueError):
            ncs_register._build_mailbox_service(fake_register, "duckmail")

    def test_legacy_mailbox_service_factory_supports_cfmail_and_wildmail(self):
        register_client = mock.Mock()

        self.assertIsInstance(
            ncs_register_legacy._build_mailbox_service(register_client, "cfmail"),
            ncs_register_legacy.CfmailMailboxService,
        )
        self.assertIsInstance(
            ncs_register_legacy._build_mailbox_service(register_client, "wildmail"),
            ncs_register_legacy.WildmailMailboxService,
        )

    def test_legacy_main_accepts_cfmail_provider(self):
        with mock.patch.object(ncs_register_legacy, "MAIL_PROVIDER", "cfmail"):
            with mock.patch.object(ncs_register_legacy, "WILDMAIL_API_BASE", "https://wildmail.example.com"):
                with mock.patch.object(ncs_register_legacy, "UPLOAD_API_URL", ""):
                    with mock.patch.dict("os.environ", {
                        "HTTPS_PROXY": "",
                        "https_proxy": "",
                        "ALL_PROXY": "",
                        "all_proxy": "",
                    }, clear=False):
                        with mock.patch("builtins.input", side_effect=["", "n", "", "", ""]):
                            with mock.patch.object(ncs_register_legacy, "run_batch") as run_batch_mock:
                                ncs_register_legacy.main()

        run_batch_mock.assert_called_once()

    def test_cfmail_service_creates_mailbox_via_register_client(self):
        register_client = mock.Mock()
        register_client.create_cfmail_email.return_value = ("cf@example.com", "", "cf-token")

        service = email_services.CfmailMailboxService(register_client)
        mailbox = service.create_mailbox()

        self.assertEqual(mailbox.email, "cf@example.com")
        self.assertEqual(mailbox.token, "cf-token")
        self.assertEqual(mailbox.provider, "cfmail")
        register_client.create_cfmail_email.assert_called_once()

    def test_cfmail_env_account_values_are_normalized_like_local_project(self):
        with mock.patch.object(ncs_register_legacy, "CFMAIL_WORKER_DOMAIN", "https://tmpemail.lokiw.dpdns.org/"):
            with mock.patch.object(ncs_register_legacy, "CFMAIL_EMAIL_DOMAIN", "https://wocaoniubi.lokiw.dpdns.org/"):
                with mock.patch.object(ncs_register_legacy, "CFMAIL_ADMIN_PASSWORD", "secret"):
                    with mock.patch.object(ncs_register_legacy, "CFMAIL_PROFILE_NAME", "default"):
                        accounts = ncs_register_legacy._build_cfmail_accounts([])

        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0].worker_domain, "tmpemail.lokiw.dpdns.org")
        self.assertEqual(accounts[0].email_domain, "wocaoniubi.lokiw.dpdns.org")

    def test_create_cfmail_email_uses_direct_egress_like_reference_project(self):
        register = ncs_register_legacy.ChatGPTRegister.__new__(ncs_register_legacy.ChatGPTRegister)
        register.proxy = "socks5://127.0.0.1:7890"
        register.impersonate = "chrome"
        register._cfmail_api_base = ""
        register._cfmail_account_name = ""
        register._cfmail_mail_token = ""
        register._print = mock.Mock()

        account = ncs_register_legacy.CfmailAccount(
            name="cfmail-auto",
            worker_domain="worker.example.com",
            email_domain="auto.example.com",
            admin_password="secret",
        )

        class FakeResponse:
            status_code = 200
            content = b'{"address":"user@auto.example.com","jwt":"jwt-token"}'
            text = '{"address":"user@auto.example.com","jwt":"jwt-token"}'

            @staticmethod
            def json():
                return {"address": "user@auto.example.com", "jwt": "jwt-token"}

        with mock.patch("ncs_register_legacy._reload_cfmail_accounts_if_needed", return_value=False):
            with mock.patch("ncs_register_legacy._select_cfmail_account", return_value=account):
                with mock.patch("ncs_register_legacy.curl_requests.post", return_value=FakeResponse(), create=True) as post_mock:
                    email, password, token = register.create_cfmail_email()

        self.assertEqual(email, "user@auto.example.com")
        self.assertEqual(password, "")
        self.assertEqual(token, "jwt-token")
        self.assertIsNone(post_mock.call_args.kwargs["proxies"])

    def test_fetch_emails_cfmail_uses_direct_egress_like_reference_project(self):
        register = ncs_register_legacy.ChatGPTRegister.__new__(ncs_register_legacy.ChatGPTRegister)
        register.proxy = "socks5://127.0.0.1:7890"
        register.impersonate = "chrome"
        register._cfmail_api_base = "https://worker.example.com"

        class FakeResponse:
            status_code = 200
            content = b'{"results":[{"id":"mail-1","address":"user@auto.example.com","raw":"Your ChatGPT code is 123456"}]}'
            text = '{"results":[{"id":"mail-1","address":"user@auto.example.com","raw":"Your ChatGPT code is 123456"}]}'

            @staticmethod
            def json():
                return {
                    "results": [
                        {
                            "id": "mail-1",
                            "address": "user@auto.example.com",
                            "raw": "Your ChatGPT code is 123456",
                        }
                    ]
                }

        with mock.patch("ncs_register_legacy.curl_requests.get", return_value=FakeResponse(), create=True) as get_mock:
            messages = register._fetch_emails_cfmail("jwt-token")

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["id"], "mail-1")
        self.assertIsNone(get_mock.call_args.kwargs["proxies"])

    def test_normalize_to_domain_pool_keeps_worker_active_domain(self):
        config_path = Path("/tmp/test_cfmail_accounts.json")
        config_path.write_text(
            '{"accounts":[{"name":"fresh","worker_domain":"worker.example.com","email_domain":"auto-fresh.example.com","admin_password":"pw","enabled":true},{"name":"stale","worker_domain":"worker.example.com","email_domain":"auto-stale.example.com","admin_password":"pw","enabled":true}]}\n',
            encoding="utf-8",
        )

        provisioner = __import__("ncs_runtime.cfmail_provisioner", fromlist=["CfmailProvisioner", "ProvisioningSettings"]).CfmailProvisioner(
            config_path=config_path,
            settings=__import__("ncs_runtime.cfmail_provisioner", fromlist=["ProvisioningSettings"]).ProvisioningSettings(
                auth_email="a",
                auth_key="b",
                account_id="c",
                zone_id="d",
                worker_name="w",
                zone_name="example.com",
            ),
        )

        with mock.patch.object(provisioner, "current_active_domains", return_value=["auto-fresh.example.com"]):
            with mock.patch.object(provisioner, "_set_worker_domains"):
                with mock.patch.object(provisioner, "_delete_domain_artifacts"):
                    result = provisioner.normalize_to_domain_pool(1)

        self.assertEqual(result["active_domains"], ["auto-fresh.example.com"])
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        accounts = payload["accounts"]
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0]["email_domain"], "auto-fresh.example.com")

    def test_cfmail_provisioner_generates_pure_letter_labels(self):
        provisioner = __import__("ncs_runtime.cfmail_provisioner", fromlist=["CfmailProvisioner", "ProvisioningSettings"]).CfmailProvisioner(
            config_path=Path("/tmp/test_cfmail_letters_accounts.json"),
            settings=__import__("ncs_runtime.cfmail_provisioner", fromlist=["ProvisioningSettings"]).ProvisioningSettings(
                auth_email="a",
                auth_key="b",
                account_id="c",
                zone_id="d",
                worker_name="w",
                zone_name="example.com",
            ),
        )

        label = provisioner._make_new_label()

        self.assertTrue(label.isalpha(), label)
        self.assertTrue(label.islower(), label)
        self.assertGreaterEqual(len(label), 28, label)
        self.assertLessEqual(len(label), 35, label)

    def test_cfmail_provisioner_recognizes_pure_letter_managed_domains(self):
        provisioner = __import__("ncs_runtime.cfmail_provisioner", fromlist=["CfmailProvisioner", "ProvisioningSettings"]).CfmailProvisioner(
            config_path=Path("/tmp/test_cfmail_managed_accounts.json"),
            settings=__import__("ncs_runtime.cfmail_provisioner", fromlist=["ProvisioningSettings"]).ProvisioningSettings(
                auth_email="a",
                auth_key="b",
                account_id="c",
                zone_id="d",
                worker_name="w",
                zone_name="example.com",
            ),
        )

        self.assertTrue(provisioner._is_managed_auto_domain("abcdefghijkl.example.com"))
        self.assertTrue(provisioner._is_managed_auto_domain("abcdefghijklmnopqrstuvwxyzab.example.com"))
        self.assertTrue(provisioner._is_managed_auto_domain("auto-fresh.example.com"))
        self.assertFalse(provisioner._is_managed_auto_domain("mail.example.com"))

    def test_sync_cfmail_accounts_with_env_credentials_refreshes_cached_passwords(self):
        config_path = Path("/tmp/test_cfmail_sync_accounts.json")
        config_path.write_text(
            json.dumps(
                {
                    "accounts": [
                        {
                            "name": "cached-auto",
                            "worker_domain": "old-worker.example.com",
                            "email_domain": "auto-cache.example.com",
                            "admin_password": "old-secret",
                            "enabled": True,
                        }
                    ]
                }
            )
            + "\n",
            encoding="utf-8",
        )

        provisioner = __import__("ncs_runtime.cfmail_provisioner", fromlist=["CfmailProvisioner", "ProvisioningSettings"]).CfmailProvisioner(
            config_path=config_path,
            settings=__import__("ncs_runtime.cfmail_provisioner", fromlist=["ProvisioningSettings"]).ProvisioningSettings(
                auth_email="a",
                auth_key="b",
                account_id="c",
                zone_id="d",
                worker_name="w",
                zone_name="example.com",
            ),
        )

        with mock.patch.object(ncs_register_legacy, "CFMAIL_WORKER_DOMAIN", "https://fresh-worker.example.com/"):
            with mock.patch.object(ncs_register_legacy, "CFMAIL_ADMIN_PASSWORD", "fresh-secret"):
                changed = runtime_batch._sync_cfmail_accounts_with_env_credentials(provisioner)

        self.assertTrue(changed)
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        account = payload["accounts"][0]
        self.assertEqual(account["worker_domain"], "fresh-worker.example.com")
        self.assertEqual(account["admin_password"], "fresh-secret")
        self.assertEqual(account["email_domain"], "auto-cache.example.com")

    def test_run_batch_startup_normalizes_cfmail_pool_without_forced_rotation(self):
        rotate_kwargs = []
        normalize_targets = []

        class FakeProvisioner:
            def __init__(self, *args, **kwargs):
                del args, kwargs

            def _load_all_accounts(self):
                return [
                    {
                        "name": "cached-auto",
                        "worker_domain": "worker.example.com",
                        "email_domain": "auto-live.example.com",
                        "admin_password": "stale-secret",
                        "enabled": True,
                    }
                ]

            def _write_accounts(self, accounts):
                self.accounts = accounts

            def rotate_active_domain(self, **kwargs):
                rotate_kwargs.append(dict(kwargs))
                return types.SimpleNamespace(success=False, error="skip")

            def normalize_to_domain_pool(self, target_count):
                normalize_targets.append(target_count)
                return {"active_domains": []}

        class FakeFuture:
            def result(self):
                return True, "ok@example.com", "", None

        class FakeExecutor:
            def __init__(self, *args, **kwargs):
                del args, kwargs
                self.future = FakeFuture()

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def submit(self, fn, *args, **kwargs):
                del fn, args, kwargs
                return self.future

        fake_account = ncs_register_legacy.CfmailAccount(
            name="default",
            worker_domain="worker.example.com",
            email_domain="base.example.com",
            admin_password="secret",
        )

        with mock.patch.object(ncs_register_legacy, "MAIL_PROVIDER", "cfmail"):
            with mock.patch.object(ncs_register_legacy, "CFMAIL_ACCOUNTS", [fake_account]):
                with mock.patch.object(ncs_register_legacy, "CFMAIL_PROVISIONING_ENABLED", True):
                    with mock.patch.object(ncs_register_legacy, "CFMAIL_WORKER_DOMAIN", "worker.example.com"):
                        with mock.patch.object(ncs_register_legacy, "CFMAIL_ADMIN_PASSWORD", "secret"):
                            with mock.patch.object(ncs_register_legacy, "CFMAIL_EMAIL_DOMAIN", "base.example.com"):
                                with mock.patch.object(ncs_register_legacy, "CF_ZONE_NAME", "example.com"):
                                    with mock.patch.object(ncs_register_legacy, "ENABLE_OAUTH", False):
                                        with mock.patch.object(ncs_register_legacy, "UPLOAD_API_URL", ""):
                                            with mock.patch.object(runtime_batch, "ThreadPoolExecutor", FakeExecutor):
                                                with mock.patch.object(runtime_batch, "wait", side_effect=lambda futures, return_when=None: (set(futures), set())):
                                                    with mock.patch.object(runtime_batch, "run_single", return_value=(True, "ok@example.com", "", None)):
                                                        with mock.patch("ncs_runtime.cfmail_provisioner.CfmailProvisioner", FakeProvisioner):
                                                            with mock.patch("ncs_runtime.cfmail_provisioner.ProvisioningSettings") as settings_cls:
                                                                settings_cls.return_value = object()
                                                                with mock.patch("time.sleep", return_value=None):
                                                                    runtime_batch.run_batch(total_accounts=1, max_workers=1)

        self.assertEqual(rotate_kwargs, [])
        self.assertEqual(normalize_targets, [3])

    def test_run_batch_keeps_only_managed_letter_domain_after_rotation(self):
        managed_domain = "abcdefghijkl.example.com"

        class FakeProvisioner:
            def __init__(self, *args, **kwargs):
                del args, kwargs

            def _load_all_accounts(self):
                return [
                    {
                        "name": "cached-auto",
                        "worker_domain": "worker.example.com",
                        "email_domain": "base.example.com",
                        "admin_password": "stale-secret",
                        "enabled": True,
                    }
                ]

            def _write_accounts(self, accounts):
                self.accounts = accounts

            def _is_managed_auto_domain(self, domain):
                return str(domain or "").strip().lower() == managed_domain

            def rotate_active_domain(self, **kwargs):
                del kwargs
                return types.SimpleNamespace(success=True, old_domain="base.example.com", new_domain=managed_domain)

            def normalize_to_domain_pool(self, target_count):
                del target_count
                return {"active_domains": [managed_domain]}

        class FakeFuture:
            def result(self):
                return True, "ok@example.com", "", None

        class FakeExecutor:
            def __init__(self, *args, **kwargs):
                del args, kwargs
                self.future = FakeFuture()

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def submit(self, fn, *args, **kwargs):
                del fn, args, kwargs
                return self.future

        fake_account = ncs_register_legacy.CfmailAccount(
            name="default",
            worker_domain="worker.example.com",
            email_domain="base.example.com",
            admin_password="secret",
        )
        managed_account = ncs_register_legacy.CfmailAccount(
            name="managed",
            worker_domain="worker.example.com",
            email_domain=managed_domain,
            admin_password="secret",
        )
        manual_account = ncs_register_legacy.CfmailAccount(
            name="manual",
            worker_domain="worker.example.com",
            email_domain="base.example.com",
            admin_password="secret",
        )

        def fake_reload(force=False):
            del force
            ncs_register_legacy.CFMAIL_ACCOUNTS = [managed_account, manual_account]

        with mock.patch.object(ncs_register_legacy, "MAIL_PROVIDER", "cfmail"):
            with mock.patch.object(ncs_register_legacy, "CFMAIL_ACCOUNTS", [fake_account]):
                with mock.patch.object(ncs_register_legacy, "CFMAIL_PROVISIONING_ENABLED", True):
                    with mock.patch.object(ncs_register_legacy, "CFMAIL_WORKER_DOMAIN", "worker.example.com"):
                        with mock.patch.object(ncs_register_legacy, "CFMAIL_ADMIN_PASSWORD", "secret"):
                            with mock.patch.object(ncs_register_legacy, "CFMAIL_EMAIL_DOMAIN", "base.example.com"):
                                with mock.patch.object(ncs_register_legacy, "CF_ZONE_NAME", "example.com"):
                                    with mock.patch.object(ncs_register_legacy, "ENABLE_OAUTH", False):
                                        with mock.patch.object(ncs_register_legacy, "UPLOAD_API_URL", ""):
                                            with mock.patch.object(ncs_register_legacy, "_reload_cfmail_accounts_if_needed", side_effect=fake_reload):
                                                with mock.patch.object(runtime_batch, "ThreadPoolExecutor", FakeExecutor):
                                                    with mock.patch.object(runtime_batch, "wait", side_effect=lambda futures, return_when=None: (set(futures), set())):
                                                        with mock.patch.object(runtime_batch, "run_single", return_value=(True, "ok@example.com", "", None)):
                                                            with mock.patch("ncs_runtime.cfmail_provisioner.CfmailProvisioner", FakeProvisioner):
                                                                with mock.patch("ncs_runtime.cfmail_provisioner.ProvisioningSettings") as settings_cls:
                                                                    settings_cls.return_value = object()
                                                                    with mock.patch("time.sleep", return_value=None):
                                                                        runtime_batch.run_batch(total_accounts=1, max_workers=1)

                                            self.assertEqual(
                                                [item.email_domain for item in ncs_register_legacy.CFMAIL_ACCOUNTS],
                                                [managed_domain],
                                            )

    def test_run_batch_uploads_after_each_success_when_threshold_is_one(self):
        class FakeFuture:
            def __init__(self, result):
                self._result = result

            def result(self):
                return self._result

        class FakeExecutor:
            def __init__(self, *args, **kwargs):
                del args, kwargs
                self._results = [
                    (True, "ok-1@example.com", "", None),
                    (True, "ok-2@example.com", "", None),
                ]

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def submit(self, fn, *args, **kwargs):
                del fn, args, kwargs
                return FakeFuture(self._results.pop(0))

        with mock.patch.object(ncs_register_legacy, "MAIL_PROVIDER", "tempmail_lol"):
            with mock.patch.object(ncs_register_legacy, "ENABLE_OAUTH", False):
                with mock.patch.object(ncs_register_legacy, "UPLOAD_API_URL", "https://cpa.example.com"):
                    with mock.patch.object(runtime_batch, "ThreadPoolExecutor", FakeExecutor):
                        with mock.patch.object(runtime_batch, "wait", side_effect=lambda futures, return_when=None: ({next(iter(futures))}, set())):
                            with mock.patch.object(ncs_register_legacy, "_upload_all_tokens_to_cpa") as upload_mock:
                                ok = runtime_batch.run_batch(total_accounts=2, max_workers=1, cpa_upload_every_n=1)

        self.assertTrue(ok)
        self.assertEqual(upload_mock.call_count, 2)

    def test_run_batch_does_not_rotate_cfmail_domains_before_failure_threshold(self):
        rotate_kwargs = []

        class FakeProvisioner:
            def __init__(self, *args, **kwargs):
                del args, kwargs

            def _load_all_accounts(self):
                return [
                    {
                        "name": "cached-auto",
                        "worker_domain": "worker.example.com",
                        "email_domain": "auto-live.example.com",
                        "admin_password": "stale-secret",
                        "enabled": True,
                    }
                ]

            def _write_accounts(self, accounts):
                self.accounts = accounts

            def rotate_active_domain(self, **kwargs):
                rotate_kwargs.append(dict(kwargs))
                return types.SimpleNamespace(success=False, error="skip")

            def normalize_to_domain_pool(self, target_count):
                del target_count
                return {"active_domains": []}

        class FakeFuture:
            def result(self):
                return False, None, "", "OAuth Token 获取失败（oauth_required=true）"

        class FakeExecutor:
            def __init__(self, *args, **kwargs):
                del args, kwargs
                self.future = FakeFuture()

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def submit(self, fn, *args, **kwargs):
                del fn, args, kwargs
                return self.future

        fake_account = ncs_register_legacy.CfmailAccount(
            name="default",
            worker_domain="worker.example.com",
            email_domain="base.example.com",
            admin_password="secret",
        )

        with mock.patch.object(ncs_register_legacy, "MAIL_PROVIDER", "cfmail"):
            with mock.patch.object(ncs_register_legacy, "CFMAIL_ACCOUNTS", [fake_account]):
                with mock.patch.object(ncs_register_legacy, "CFMAIL_PROVISIONING_ENABLED", True):
                    with mock.patch.object(ncs_register_legacy, "CFMAIL_WORKER_DOMAIN", "worker.example.com"):
                        with mock.patch.object(ncs_register_legacy, "CFMAIL_ADMIN_PASSWORD", "secret"):
                            with mock.patch.object(ncs_register_legacy, "CFMAIL_EMAIL_DOMAIN", "base.example.com"):
                                with mock.patch.object(ncs_register_legacy, "CF_ZONE_NAME", "example.com"):
                                    with mock.patch.object(ncs_register_legacy, "ENABLE_OAUTH", True):
                                        with mock.patch.object(ncs_register_legacy, "UPLOAD_API_URL", ""):
                                            with mock.patch.object(runtime_batch, "ThreadPoolExecutor", FakeExecutor):
                                                with mock.patch.object(runtime_batch, "wait", side_effect=lambda futures, return_when=None: (set(futures), set())):
                                                    with mock.patch("ncs_runtime.cfmail_provisioner.CfmailProvisioner", FakeProvisioner):
                                                        with mock.patch("ncs_runtime.cfmail_provisioner.ProvisioningSettings") as settings_cls:
                                                            settings_cls.return_value = object()
                                                            with mock.patch("time.sleep", return_value=None):
                                                                runtime_batch.run_batch(total_accounts=5, max_workers=1)

        self.assertEqual(rotate_kwargs, [])

    def test_run_batch_rotates_cfmail_domains_after_30_consecutive_failures(self):
        rotate_kwargs = []

        class FakeProvisioner:
            def __init__(self, *args, **kwargs):
                del args, kwargs

            def _load_all_accounts(self):
                return [
                    {
                        "name": "cached-auto",
                        "worker_domain": "worker.example.com",
                        "email_domain": "base.example.com",
                        "admin_password": "stale-secret",
                        "enabled": True,
                    }
                ]

            def _write_accounts(self, accounts):
                self.accounts = accounts

            def rotate_active_domain(self, **kwargs):
                rotate_kwargs.append(dict(kwargs))
                return types.SimpleNamespace(success=False, error="skip")

            def normalize_to_domain_pool(self, target_count):
                del target_count
                return {"active_domains": []}

        class FakeFuture:
            def result(self):
                return False, None, "", "OAuth Token 获取失败（oauth_required=true）"

        class FakeExecutor:
            def __init__(self, *args, **kwargs):
                del args, kwargs
                self._results = [FakeFuture() for _ in range(30)]

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def submit(self, fn, *args, **kwargs):
                del fn, args, kwargs
                return self._results.pop(0)

        class ImmediateThread:
            def __init__(self, *args, target=None, daemon=None, **kwargs):
                del args, daemon, kwargs
                self._target = target

            def start(self):
                if self._target is not None:
                    self._target()

        fake_account = ncs_register_legacy.CfmailAccount(
            name="default",
            worker_domain="worker.example.com",
            email_domain="base.example.com",
            admin_password="secret",
        )

        with mock.patch.object(ncs_register_legacy, "MAIL_PROVIDER", "cfmail"):
            with mock.patch.object(ncs_register_legacy, "CFMAIL_ACCOUNTS", [fake_account]):
                with mock.patch.object(ncs_register_legacy, "CFMAIL_PROVISIONING_ENABLED", True):
                    with mock.patch.object(ncs_register_legacy, "CFMAIL_WORKER_DOMAIN", "worker.example.com"):
                        with mock.patch.object(ncs_register_legacy, "CFMAIL_ADMIN_PASSWORD", "secret"):
                            with mock.patch.object(ncs_register_legacy, "CFMAIL_EMAIL_DOMAIN", "base.example.com"):
                                with mock.patch.object(ncs_register_legacy, "CF_ZONE_NAME", "example.com"):
                                    with mock.patch.object(ncs_register_legacy, "ENABLE_OAUTH", True):
                                        with mock.patch.object(ncs_register_legacy, "UPLOAD_API_URL", ""):
                                            with mock.patch.object(runtime_batch, "ThreadPoolExecutor", FakeExecutor):
                                                with mock.patch.object(runtime_batch, "wait", side_effect=lambda futures, return_when=None: (set(futures), set())):
                                                    with mock.patch.object(runtime_batch.threading, "Thread", ImmediateThread):
                                                        with mock.patch("ncs_runtime.cfmail_provisioner.CfmailProvisioner", FakeProvisioner):
                                                            with mock.patch("ncs_runtime.cfmail_provisioner.ProvisioningSettings") as settings_cls:
                                                                settings_cls.return_value = object()
                                                                with mock.patch("time.sleep", return_value=None):
                                                                    runtime_batch.run_batch(total_accounts=30, max_workers=1)

        self.assertEqual(len(rotate_kwargs), 1)

    def test_wildmail_service_creates_mailbox_via_register_client(self):
        register_client = mock.Mock()
        register_client.create_wildmail_email.return_value = ("wild@example.com", "", "wild-token")

        service = email_services.WildmailMailboxService(register_client)
        mailbox = service.create_mailbox()

        self.assertEqual(mailbox.email, "wild@example.com")
        self.assertEqual(mailbox.token, "wild-token")
        self.assertEqual(mailbox.provider, "wildmail")
        register_client.create_wildmail_email.assert_called_once()

    def test_wildmail_domain_has_public_mx_uses_dns_over_https(self):
        class FakeResponse:
            status_code = 200

            @staticmethod
            def json():
                return {
                    "Answer": [
                        {"type": 15, "data": "10 route1.mx.cloudflare.net."},
                    ]
                }

        with mock.patch("ncs_register_legacy.curl_requests.get", return_value=FakeResponse(), create=True):
            self.assertTrue(ncs_register_legacy._wildmail_domain_has_public_mx("job123.loki.us.ci"))

    def test_create_wildmail_email_rejects_domain_without_public_mx(self):
        register = ncs_register_legacy.ChatGPTRegister.__new__(ncs_register_legacy.ChatGPTRegister)
        register.proxy = None
        register.impersonate = "chrome"
        register._wildmail_api_base = ""
        register._print = mock.Mock()

        class FakeResponse:
            status_code = 200
            content = b'{"address":"diag@job123.loki.us.ci","token":"token-1"}'
            text = '{"address":"diag@job123.loki.us.ci","token":"token-1"}'

            @staticmethod
            def json():
                return {"address": "diag@job123.loki.us.ci", "token": "token-1"}

        with mock.patch.object(ncs_register_legacy, "WILDMAIL_API_BASE", "https://wildmail.example.com"):
            with mock.patch.object(ncs_register_legacy, "WILDMAIL_API_KEY", "secret"):
                with mock.patch("ncs_register_legacy.curl_requests.post", return_value=FakeResponse(), create=True):
                    with mock.patch("ncs_register_legacy._wildmail_domain_has_public_mx", return_value=False):
                        with self.assertRaisesRegex(Exception, "wildmail 域名未配置 MX"):
                            register.create_wildmail_email()

    def test_provider_candidates_prefer_wildmail_then_lamail_then_tempmail(self):
        with mock.patch.object(ncs_register_legacy, "WILDMAIL_API_BASE", "https://wildmail.example.com"):
            self.assertEqual(
                email_services.get_provider_candidates("wildmail"),
                ["wildmail", "lamail", "tempmail_lol"],
            )

    def test_wildmail_falls_back_to_lamail_before_tempmail(self):
        register_client = mock.Mock()
        register_client.create_wildmail_email.side_effect = Exception("wildmail 域名未配置 MX")
        register_client.create_lamail_email.return_value = ("fallback@example.com", "", "token-1")
        register_client._print = mock.Mock()

        with mock.patch.object(ncs_register_legacy, "WILDMAIL_API_BASE", "https://wildmail.example.com"):
            engine = runtime_engine.RegistrationEngine(idx=1, total=1, proxy=None, output_file="out.txt")
            service, mailbox, provider = engine._create_mailbox_with_fallback(register_client, "wildmail")

        self.assertIsInstance(service, email_services.LaMailMailboxService)
        self.assertEqual(provider, "lamail")
        self.assertEqual(mailbox.email, "fallback@example.com")

    def test_wildmail_falls_back_to_tempmail_after_lamail_failure(self):
        register_client = mock.Mock()
        register_client.create_wildmail_email.side_effect = Exception("wildmail 域名未配置 MX")
        register_client.create_lamail_email.side_effect = Exception("lamail 创建失败")
        register_client.create_tempmail_lol_email.return_value = ("fallback2@example.com", "", "token-2")
        register_client._print = mock.Mock()

        with mock.patch.object(ncs_register_legacy, "WILDMAIL_API_BASE", "https://wildmail.example.com"):
            engine = runtime_engine.RegistrationEngine(idx=1, total=1, proxy=None, output_file="out.txt")
            service, mailbox, provider = engine._create_mailbox_with_fallback(register_client, "wildmail")

        self.assertIsInstance(service, email_services.TempmailLolMailboxService)
        self.assertEqual(provider, "tempmail_lol")
        self.assertEqual(mailbox.email, "fallback2@example.com")

    def test_lamail_primary_falls_back_to_tempmail(self):
        register_client = mock.Mock()
        register_client.create_lamail_email.side_effect = Exception("lamail 创建失败")
        register_client.create_tempmail_lol_email.return_value = ("fallback3@example.com", "", "token-3")
        register_client._print = mock.Mock()

        engine = runtime_engine.RegistrationEngine(idx=1, total=1, proxy=None, output_file="out.txt")
        service, mailbox, provider = engine._create_mailbox_with_fallback(register_client, "lamail")

        self.assertIsInstance(service, email_services.TempmailLolMailboxService)
        self.assertEqual(provider, "tempmail_lol")
        self.assertEqual(mailbox.email, "fallback3@example.com")

    def test_wildmail_primary_falls_back_to_lamail_then_tempmail(self):
        register_client = mock.Mock()
        register_client.create_wildmail_email.side_effect = Exception("wildmail 域名未配置 MX")
        register_client.create_lamail_email.return_value = ("fallback4@example.com", "", "token-4")
        register_client._print = mock.Mock()

        with mock.patch.object(ncs_register_legacy, "WILDMAIL_API_BASE", "https://wildmail.example.com"):
            engine = runtime_engine.RegistrationEngine(idx=1, total=1, proxy=None, output_file="out.txt")
            service, mailbox, provider = engine._create_mailbox_with_fallback(register_client, "wildmail")

        self.assertIsInstance(service, email_services.LaMailMailboxService)
        self.assertEqual(provider, "lamail")
        self.assertEqual(mailbox.email, "fallback4@example.com")

    def test_registration_engine_uses_legacy_oauth_flow(self):
        mailbox_service = mock.Mock()
        mailbox_service.create_mailbox.return_value = ncs_register.MailboxSession(
            email="user@example.com",
            password="",
            token="mail-token",
            provider="tempmail_lol",
        )
        mailbox_service.wait_for_verification_code = mock.Mock(return_value="123456")

        with mock.patch.object(runtime_engine, "build_mailbox_service", return_value=mailbox_service):
            with mock.patch("ncs_register_legacy.ChatGPTRegister") as register_cls:
                register_client = mock.Mock()
                register_cls.return_value = register_client
                register_client.fetch_codex_session_tokens.return_value = {"access_token": "token-xyz"}
                with mock.patch("ncs_register_legacy._save_codex_tokens") as save_tokens_mock:
                    engine = runtime_engine.RegistrationEngine(idx=1, total=1, proxy=None, output_file="out.txt")
                    with mock.patch.object(engine, "_append_result"):
                        result = engine.run()

        self.assertTrue(result.success)
        self.assertEqual(result.email, "user@example.com")
        self.assertTrue(result.oauth_ok)
        register_client.run_register.assert_called_once()
        register_client.fetch_codex_session_tokens.assert_called_once()
        save_tokens_mock.assert_called_once()

    def test_registration_engine_uses_provider_aware_protocol_oauth_flow(self):
        mailbox_service = mock.Mock()
        mailbox_service.create_mailbox.return_value = ncs_register.MailboxSession(
            email="user@example.com",
            password="",
            token="mail-token",
            provider="tempmail_lol",
        )
        mailbox_service.wait_for_verification_code = mock.Mock(return_value="123456")

        fake_protocol_keygen = types.ModuleType("protocol_keygen")

        class FakeRegistrar:
            def __init__(self, browser_tokens=None):
                self.browser_tokens = browser_tokens
                self.session = mock.Mock()

            def step0_init_oauth_session(self, email):
                return True

            def step2_register_user(self, email, password):
                return True

            def step3_send_otp(self):
                return True

            def step4_validate_otp(self, code):
                return True

            def step5_create_account(self, first_name, last_name, birthdate):
                return True

        fake_protocol_keygen.ProtocolRegistrar = FakeRegistrar
        fake_protocol_keygen.create_session = mock.Mock()
        fake_protocol_keygen.perform_codex_oauth_login_http = mock.Mock(return_value={"access_token": "token-xyz"})
        fake_protocol_keygen.save_tokens = mock.Mock()
        fake_protocol_keygen.save_account = mock.Mock()
        fake_protocol_keygen.create_temp_email = mock.Mock()
        fake_protocol_keygen.PROXY = ""
        fake_protocol_keygen.COMMON_HEADERS = {"user-agent": "UA-123"}

        fake_sentinel_browser = types.ModuleType("sentinel_browser")
        fake_sentinel_browser.get_all_sentinel_tokens = mock.Mock(return_value={"authorize_continue": '{"token":"ok"}'})

        with mock.patch.object(runtime_engine, "build_mailbox_service", return_value=mailbox_service):
            with mock.patch.object(ncs_register_legacy, "ChatGPTRegister", return_value=mock.Mock(tag="")):
                with mock.patch.dict(sys.modules, {
                    "protocol_keygen": fake_protocol_keygen,
                    "sentinel_browser": fake_sentinel_browser,
                }):
                    with mock.patch("ncs_register_legacy._save_codex_tokens"):
                        engine = runtime_engine.RegistrationEngine(idx=1, total=1, proxy=None, output_file="out.txt")
                        with mock.patch.object(engine, "_append_result"):
                            result = engine.run()

        self.assertTrue(result.success)
        self.assertEqual(result.email, "user@example.com")
        self.assertTrue(result.oauth_ok)
        fake_protocol_keygen.perform_codex_oauth_login_http.assert_called_once()
        fake_protocol_keygen.save_tokens.assert_called_once()
        kwargs = fake_protocol_keygen.perform_codex_oauth_login_http.call_args.kwargs
        self.assertEqual(kwargs["cf_token"], "mail-token")
        self.assertEqual(kwargs["provider"], "cfmail")
        self.assertIs(kwargs["otp_fetcher"], mailbox_service.wait_for_verification_code)

    def test_fetch_codex_session_tokens_falls_back_to_chatgpt_session(self):
        register = ncs_register_legacy.ChatGPTRegister.__new__(ncs_register_legacy.ChatGPTRegister)
        register._print = mock.Mock()
        register.perform_codex_oauth_login_http = mock.Mock(return_value=None)
        register.fetch_chatgpt_session_tokens = mock.Mock(return_value={"access_token": "session-token"})

        tokens = ncs_register_legacy.ChatGPTRegister.fetch_codex_session_tokens(
            register,
            "user@example.com",
            "password-1",
            mail_token="mail-token",
            provider="cfmail",
        )

        self.assertEqual(tokens, {"access_token": "session-token"})
        register.perform_codex_oauth_login_http.assert_called_once()
        register.fetch_chatgpt_session_tokens.assert_called_once_with("user@example.com")

    def test_perform_codex_oauth_login_http_uses_fresh_http_flow_even_with_registrar_session(self):
        class FakeCookies(dict):
            def __init__(self):
                super().__init__()
                self.jar = []

            def set(self, name, value, domain=""):
                del domain
                self[name] = value

        class FakeResponse:
            def __init__(self, status_code, *, headers=None, url="", text="", json_data=None):
                self.status_code = status_code
                self.headers = headers or {}
                self.url = url
                self.text = text
                self._json_data = json_data

            def json(self):
                if self._json_data is None:
                    raise ValueError("no json")
                return self._json_data

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **kwargs):
                snapshot = dict(kwargs)
                if isinstance(snapshot.get("headers"), dict):
                    snapshot["headers"] = dict(snapshot["headers"])
                self.calls.append(("GET", url, snapshot))
                if url.startswith("https://auth.openai.com/oauth/authorize"):
                    self.cookies["login_session"] = "login-cookie"
                    return FakeResponse(200, url="https://auth.openai.com/log-in", text="<html></html>")
                if url == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent":
                    return FakeResponse(
                        302,
                        url=url,
                        headers={
                            "Location": "http://localhost:1455/auth/callback?code=code-browser&state=state-123",
                        },
                    )
                raise AssertionError(f"unexpected GET: {url}")

            def post(self, url, **kwargs):
                snapshot = dict(kwargs)
                if isinstance(snapshot.get("headers"), dict):
                    snapshot["headers"] = dict(snapshot["headers"])
                self.calls.append(("POST", url, snapshot))
                if url == "https://auth.openai.com/api/accounts/authorize/continue":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={"continue_url": "/log-in/password", "page": {"type": "password"}},
                    )
                if url == "https://auth.openai.com/api/accounts/password/verify":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={
                            "continue_url": "/sign-in-with-chatgpt/codex/consent",
                            "page": {"type": "consent"},
                        },
                    )
                raise AssertionError(f"unexpected POST: {url}")

        fake_session = FakeSession()
        mail_session = mock.Mock()
        registrar_session = mock.Mock()

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch("protocol_keygen.create_session", side_effect=[fake_session, mail_session]):
                    with mock.patch("protocol_keygen._load_oauth_browser_tokens", side_effect=AssertionError("browser tokens should not be used")):
                        with mock.patch(
                            "protocol_keygen.build_sentinel_token",
                            side_effect=['{"flow":"authorize_continue","c":"http-ac"}', '{"flow":"password_verify","c":"http-pwd"}'],
                        ) as sentinel_mock:
                            with mock.patch("protocol_keygen.codex_exchange_code", return_value={"access_token": "token-http"}) as exchange_mock:
                                tokens = protocol_keygen.perform_codex_oauth_login_http(
                                    "user@example.com",
                                    "Password-1!",
                                    registrar_session=registrar_session,
                                    cf_token=None,
                                )

        self.assertEqual(tokens, {"access_token": "token-http"})
        registrar_session.get.assert_not_called()
        exchange_mock.assert_called_once_with("code-browser", "verifier-123")
        self.assertEqual(sentinel_mock.call_count, 2)

        authorize_call = next(
            call for call in fake_session.calls
            if call[0] == "POST" and call[1] == "https://auth.openai.com/api/accounts/authorize/continue"
        )
        self.assertEqual(
            authorize_call[2]["headers"]["openai-sentinel-token"],
            '{"flow":"authorize_continue","c":"http-ac"}',
        )

        password_call = next(
            call for call in fake_session.calls
            if call[0] == "POST" and call[1] == "https://auth.openai.com/api/accounts/password/verify"
        )
        self.assertEqual(
            password_call[2]["headers"]["openai-sentinel-token"],
            '{"flow":"password_verify","c":"http-pwd"}',
        )

    def test_perform_codex_oauth_login_http_retries_authorize_after_403(self):
        class FakeCookies(dict):
            def __init__(self):
                super().__init__()
                self.jar = []

            def set(self, name, value, domain=""):
                del domain
                self[name] = value

        class FakeResponse:
            def __init__(self, status_code, *, headers=None, url="", text="", json_data=None):
                self.status_code = status_code
                self.headers = headers or {}
                self.url = url
                self.text = text
                self._json_data = json_data

            def json(self):
                if self._json_data is None:
                    raise ValueError("no json")
                return self._json_data

        class FakeSession:
            def __init__(self, authorize_responses):
                self.cookies = FakeCookies()
                self.calls = []
                self._authorize_responses = list(authorize_responses)

            def get(self, url, **kwargs):
                snapshot = dict(kwargs)
                if isinstance(snapshot.get("headers"), dict):
                    snapshot["headers"] = dict(snapshot["headers"])
                self.calls.append(("GET", url, snapshot))
                if url.startswith("https://auth.openai.com/oauth/authorize"):
                    response = self._authorize_responses.pop(0)
                    if response.status_code == 200:
                        self.cookies["login_session"] = "login-cookie"
                    return response
                if url == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent":
                    return FakeResponse(
                        302,
                        url=url,
                        headers={"Location": "http://localhost:1455/auth/callback?code=code-retry&state=state-123"},
                    )
                raise AssertionError(f"unexpected GET: {url}")

            def post(self, url, **kwargs):
                snapshot = dict(kwargs)
                if isinstance(snapshot.get("headers"), dict):
                    snapshot["headers"] = dict(snapshot["headers"])
                self.calls.append(("POST", url, snapshot))
                if url == "https://auth.openai.com/api/accounts/authorize/continue":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={"continue_url": "/log-in/password", "page": {"type": "password"}},
                    )
                if url == "https://auth.openai.com/api/accounts/password/verify":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={
                            "continue_url": "/sign-in-with-chatgpt/codex/consent",
                            "page": {"type": "consent"},
                        },
                    )
                raise AssertionError(f"unexpected POST: {url}")

        blocked = FakeSession(
            [
                FakeResponse(
                    403,
                    url="https://auth.openai.com/api/oauth/oauth2/auth",
                    text="blocked",
                )
            ]
        )
        recovered = FakeSession(
            [
                FakeResponse(
                    200,
                    url="https://auth.openai.com/log-in",
                    text="<html></html>",
                )
            ]
        )
        mail_session = mock.Mock()

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch("protocol_keygen._random_chrome_version", return_value=("chrome999", 999, "999.0.0.0", "UA-999", '"Chromium";v="999"')):
                    with mock.patch("protocol_keygen.time.sleep", return_value=None):
                        with mock.patch("protocol_keygen.create_session", side_effect=[blocked, recovered, mail_session]) as create_session_mock:
                            with mock.patch(
                                "protocol_keygen.build_sentinel_token",
                                side_effect=['{"flow":"authorize_continue","c":"http-ac"}', '{"flow":"password_verify","c":"http-pwd"}'],
                            ):
                                with mock.patch("protocol_keygen.codex_exchange_code", return_value={"access_token": "token-retry"}) as exchange_mock:
                                    tokens = protocol_keygen.perform_codex_oauth_login_http(
                                        "user@example.com",
                                        "Password-1!",
                                        registrar_session=mock.Mock(),
                                        cf_token=None,
                                    )

        self.assertEqual(tokens, {"access_token": "token-retry"})
        exchange_mock.assert_called_once_with("code-retry", "verifier-123")
        self.assertEqual(create_session_mock.call_args_list[1], mock.call(impersonate="chrome999"))

    def test_perform_codex_oauth_login_http_uses_otp_fetcher_for_email_otp_verification(self):
        class FakeCookies(dict):
            def __init__(self):
                super().__init__()
                self.jar = []

            def set(self, name, value, domain=""):
                del domain
                self[name] = value

        class FakeResponse:
            def __init__(self, status_code, *, headers=None, url="", text="", json_data=None):
                self.status_code = status_code
                self.headers = headers or {}
                self.url = url
                self.text = text
                self._json_data = json_data

            def json(self):
                if self._json_data is None:
                    raise ValueError("no json")
                return self._json_data

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **kwargs):
                snapshot = dict(kwargs)
                if isinstance(snapshot.get("headers"), dict):
                    snapshot["headers"] = dict(snapshot["headers"])
                self.calls.append(("GET", url, snapshot))
                if url.startswith("https://auth.openai.com/oauth/authorize"):
                    self.cookies["login_session"] = "login-cookie"
                    return FakeResponse(200, url="https://auth.openai.com/log-in", text="<html></html>")
                if url == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent":
                    return FakeResponse(
                        302,
                        url=url,
                        headers={
                            "Location": "http://localhost:1455/auth/callback?code=code-otp&state=state-123",
                        },
                    )
                raise AssertionError(f"unexpected GET: {url}")

            def post(self, url, **kwargs):
                snapshot = dict(kwargs)
                if isinstance(snapshot.get("headers"), dict):
                    snapshot["headers"] = dict(snapshot["headers"])
                self.calls.append(("POST", url, snapshot))
                if url == "https://auth.openai.com/api/accounts/authorize/continue":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={"continue_url": "/log-in/password", "page": {"type": "password"}},
                    )
                if url == "https://auth.openai.com/api/accounts/password/verify":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={
                            "continue_url": "/email-verification",
                            "page": {"type": "email_otp_verification"},
                        },
                    )
                if url == "https://auth.openai.com/api/accounts/email-otp/validate":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={
                            "continue_url": "/sign-in-with-chatgpt/codex/consent",
                            "page": {"type": "consent"},
                        },
                    )
                raise AssertionError(f"unexpected POST: {url}")

        fake_session = FakeSession()
        registrar_session = mock.Mock()
        otp_fetcher = mock.Mock(return_value="654321")

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch("protocol_keygen.create_session", return_value=fake_session):
                    with mock.patch(
                        "protocol_keygen.build_sentinel_token",
                        side_effect=[
                            '{"flow":"authorize_continue","c":"http-ac"}',
                            '{"flow":"password_verify","c":"http-pwd"}',
                            '{"flow":"email_otp_validate","c":"http-otp"}',
                        ],
                    ) as sentinel_mock:
                        with mock.patch("protocol_keygen.codex_exchange_code", return_value={"access_token": "token-otp"}) as exchange_mock:
                            tokens = protocol_keygen.perform_codex_oauth_login_http(
                                "user@example.com",
                                "Password-1!",
                                registrar_session=registrar_session,
                                cf_token="mail-token",
                                otp_fetcher=otp_fetcher,
                                provider="duckmail",
                            )

        self.assertEqual(tokens, {"access_token": "token-otp"})
        otp_fetcher.assert_called_once()
        exchange_mock.assert_called_once_with("code-otp", "verifier-123")
        self.assertEqual(sentinel_mock.call_count, 3)
        otp_call = next(
            call for call in fake_session.calls
            if call[0] == "POST" and call[1] == "https://auth.openai.com/api/accounts/email-otp/validate"
        )
        self.assertEqual(otp_call[2]["json"], {"code": "654321"})
        self.assertEqual(
            otp_call[2]["headers"]["openai-sentinel-token"],
            '{"flow":"email_otp_validate","c":"http-otp"}',
        )

    def test_perform_codex_oauth_login_http_rescues_soft_add_phone(self):
        class FakeCookies(dict):
            def __init__(self):
                super().__init__()
                self.jar = []

            def set(self, name, value, domain=""):
                del domain
                self[name] = value

        class FakeResponse:
            def __init__(self, status_code, *, headers=None, url="", text="", json_data=None, history=None):
                self.status_code = status_code
                self.headers = headers or {}
                self.url = url
                self.text = text
                self._json_data = json_data
                self.history = history or []

            def json(self):
                if self._json_data is None:
                    raise ValueError("no json")
                return self._json_data

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **kwargs):
                snapshot = dict(kwargs)
                if isinstance(snapshot.get("headers"), dict):
                    snapshot["headers"] = dict(snapshot["headers"])
                self.calls.append(("GET", url, snapshot))
                if url.startswith("https://auth.openai.com/oauth/authorize"):
                    self.cookies["login_session"] = "login-cookie"
                    return FakeResponse(200, url="https://auth.openai.com/log-in", text="<html></html>")
                if url == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent":
                    return FakeResponse(200, url="https://auth.openai.com/add-phone", text="<html>add phone</html>")
                raise AssertionError(f"unexpected GET: {url}")

            def post(self, url, **kwargs):
                snapshot = dict(kwargs)
                if isinstance(snapshot.get("headers"), dict):
                    snapshot["headers"] = dict(snapshot["headers"])
                self.calls.append(("POST", url, snapshot))
                if url == "https://auth.openai.com/api/accounts/authorize/continue":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={"continue_url": "/log-in/password", "page": {"type": "password"}},
                    )
                if url == "https://auth.openai.com/api/accounts/password/verify":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={
                            "continue_url": "/sign-in-with-chatgpt/codex/consent",
                            "page": {"type": "consent"},
                        },
                    )
                raise AssertionError(f"unexpected POST: {url}")

        fake_session = FakeSession()
        mail_session = mock.Mock()
        registrar_session = mock.Mock()

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch("protocol_keygen.create_session", side_effect=[fake_session, mail_session]):
                    with mock.patch(
                        "protocol_keygen.build_sentinel_token",
                        side_effect=['{"flow":"authorize_continue","c":"http-ac"}', '{"flow":"password_verify","c":"http-pwd"}'],
                    ):
                        with mock.patch(
                            "protocol_keygen._classify_add_phone_gate",
                            return_value={
                                "matched": True,
                                "soft": True,
                                "reason": "workspace_available",
                                "workspace_count": 1,
                                "direct_session_keys": [],
                            },
                        ):
                            with mock.patch(
                                "protocol_keygen._try_add_phone_rescue_oauth",
                                return_value={"access_token": "token-rescued"},
                            ) as rescue_mock:
                                tokens = protocol_keygen.perform_codex_oauth_login_http(
                                    "user@example.com",
                                    "Password-1!",
                                    registrar_session=registrar_session,
                                    cf_token=None,
                                    tag="tmpuser",
                                )

        self.assertEqual(tokens, {"access_token": "token-rescued"})
        rescue_mock.assert_called_once_with(
            "user@example.com",
            registrar_session,
            mock.ANY,
            "verifier-123",
            tag="tmpuser",
        )

    def test_perform_codex_oauth_login_http_fails_fast_for_hard_add_phone(self):
        class FakeCookies(dict):
            def __init__(self):
                super().__init__()
                self.jar = []

            def set(self, name, value, domain=""):
                del domain
                self[name] = value

        class FakeResponse:
            def __init__(self, status_code, *, headers=None, url="", text="", json_data=None, history=None):
                self.status_code = status_code
                self.headers = headers or {}
                self.url = url
                self.text = text
                self._json_data = json_data
                self.history = history or []

            def json(self):
                if self._json_data is None:
                    raise ValueError("no json")
                return self._json_data

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **kwargs):
                snapshot = dict(kwargs)
                if isinstance(snapshot.get("headers"), dict):
                    snapshot["headers"] = dict(snapshot["headers"])
                self.calls.append(("GET", url, snapshot))
                if url.startswith("https://auth.openai.com/oauth/authorize"):
                    self.cookies["login_session"] = "login-cookie"
                    return FakeResponse(200, url="https://auth.openai.com/log-in", text="<html></html>")
                if url == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent":
                    return FakeResponse(200, url="https://auth.openai.com/add-phone", text="<html>add phone</html>")
                raise AssertionError(f"unexpected GET: {url}")

            def post(self, url, **kwargs):
                snapshot = dict(kwargs)
                if isinstance(snapshot.get("headers"), dict):
                    snapshot["headers"] = dict(snapshot["headers"])
                self.calls.append(("POST", url, snapshot))
                if url == "https://auth.openai.com/api/accounts/authorize/continue":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={"continue_url": "/log-in/password", "page": {"type": "password"}},
                    )
                if url == "https://auth.openai.com/api/accounts/password/verify":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={
                            "continue_url": "/sign-in-with-chatgpt/codex/consent",
                            "page": {"type": "consent"},
                        },
                    )
                raise AssertionError(f"unexpected POST: {url}")

        fake_session = FakeSession()
        mail_session = mock.Mock()
        registrar_session = mock.Mock()

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch("protocol_keygen.create_session", side_effect=[fake_session, mail_session]):
                    with mock.patch(
                        "protocol_keygen.build_sentinel_token",
                        side_effect=['{"flow":"authorize_continue","c":"http-ac"}', '{"flow":"password_verify","c":"http-pwd"}'],
                    ):
                        with mock.patch(
                            "protocol_keygen._classify_add_phone_gate",
                            return_value={
                                "matched": True,
                                "soft": False,
                                "reason": "workspace_count=0_warning_banner_only",
                                "workspace_count": 0,
                                "direct_session_keys": ["WARNING_BANNER"],
                            },
                        ):
                            with mock.patch("protocol_keygen._try_add_phone_rescue_oauth") as rescue_mock:
                                tokens = protocol_keygen.perform_codex_oauth_login_http(
                                    "user@example.com",
                                    "Password-1!",
                                    registrar_session=registrar_session,
                                    cf_token=None,
                                    tag="tmpuser",
                                )

        self.assertIsNone(tokens)
        rescue_mock.assert_not_called()

    def test_registration_engine_streams_oauth_logs_in_github_actions(self):
        mailbox_service = mock.Mock()
        mailbox_service.create_mailbox.return_value = ncs_register.MailboxSession(
            email="stream@example.com",
            password="",
            token="mail-token",
            provider="tempmail_lol",
        )
        mailbox_service.wait_for_verification_code = mock.Mock(return_value="123456")

        fake_protocol_keygen = types.ModuleType("protocol_keygen")

        class FakeRegistrar:
            def __init__(self, browser_tokens=None):
                self.browser_tokens = browser_tokens
                self.session = mock.Mock()

            def step0_init_oauth_session(self, email):
                print("REG STEP0")
                return True

            def step2_register_user(self, email, password):
                print("REG STEP2")
                return True

            def step3_send_otp(self):
                print("REG STEP3")
                return True

            def step4_validate_otp(self, code):
                print("REG STEP4")
                return True

            def step5_create_account(self, first_name, last_name, birthdate):
                print("REG STEP5")
                return True

        def fake_oauth(*args, **kwargs):
            print("OAUTH DETAIL LINE")
            return {"access_token": "token-xyz"}

        fake_protocol_keygen.ProtocolRegistrar = FakeRegistrar
        fake_protocol_keygen.create_session = mock.Mock()
        fake_protocol_keygen.perform_codex_oauth_login_http = fake_oauth
        fake_protocol_keygen.save_tokens = mock.Mock()
        fake_protocol_keygen.save_account = mock.Mock(side_effect=lambda *args, **kwargs: print("SAVE ACCOUNT"))
        fake_protocol_keygen.create_temp_email = mock.Mock()
        fake_protocol_keygen.PROXY = ""
        fake_protocol_keygen.COMMON_HEADERS = {"user-agent": "UA-123"}

        fake_sentinel_browser = types.ModuleType("sentinel_browser")
        fake_sentinel_browser.get_all_sentinel_tokens = mock.Mock(return_value={"authorize_continue": '{"token":"ok"}'})

        output = io.StringIO()
        with mock.patch.dict("os.environ", {"GITHUB_ACTIONS": "true"}, clear=False):
            with mock.patch.object(runtime_engine, "build_mailbox_service", return_value=mailbox_service):
                with mock.patch.object(ncs_register_legacy, "ChatGPTRegister", return_value=mock.Mock(tag="")):
                    with mock.patch.dict(sys.modules, {
                        "protocol_keygen": fake_protocol_keygen,
                        "sentinel_browser": fake_sentinel_browser,
                    }):
                        with mock.patch("ncs_register_legacy._save_codex_tokens"):
                            with mock.patch("sys.stdout", new=output):
                                engine = runtime_engine.RegistrationEngine(idx=1, total=1, proxy=None, output_file="out.txt")
                                with mock.patch.object(engine, "_append_result"):
                                    result = engine.run()

        self.assertTrue(result.success)
        rendered = output.getvalue()
        self.assertIn("REG STEP0", rendered)
        self.assertIn("REG STEP5", rendered)
        self.assertIn("OAUTH DETAIL LINE", rendered)
        self.assertIn("[stream] [Oauth获取token] ✅获取Token成功", rendered)

        class FakeCookies(dict):
            def __init__(self):
                super().__init__()
                self.jar = []

            def set(self, name, value, domain=""):
                del domain
                self[name] = value

        class FakeResponse:
            def __init__(self, status_code, *, url="", text="", json_data=None):
                self.status_code = status_code
                self.url = url
                self.text = text
                self._json_data = json_data
                self.headers = {}

            def json(self):
                if self._json_data is None:
                    raise ValueError("no json")
                return self._json_data

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.get_calls = []
                self.post_calls = []

            def get(self, url, **kwargs):
                self.get_calls.append((url, kwargs))
                if url.startswith("https://auth.openai.com/oauth/authorize"):
                    return FakeResponse(
                        403,
                        url="https://auth.openai.com/api/oauth/oauth2/auth",
                        text="<!DOCTYPE html><title>Just a moment...</title>",
                    )
                if url == "https://auth.openai.com/api/oauth/oauth2/auth":
                    self.cookies["login_session"] = "oauth2-cookie"
                    return FakeResponse(200, url="https://auth.openai.com/log-in", text="<html></html>")
                raise AssertionError(f"unexpected GET: {url}")

            def post(self, url, **kwargs):
                self.post_calls.append((url, kwargs))
                return FakeResponse(200, url=url, json_data={"page": {"type": "password"}})

        fake_session = FakeSession()
        with mock.patch("protocol_keygen.create_session", return_value=fake_session):
            registrar = protocol_keygen.ProtocolRegistrar(browser_tokens={"authorize_continue": '{"token":"ok"}'})

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch("protocol_keygen._bootstrap_login_session_via_browser", side_effect=AssertionError("browser bootstrap should not run")):
                    ok = registrar.step0_init_oauth_session("user@example.com")

        self.assertTrue(ok)
        self.assertEqual(fake_session.get_calls[1][0], "https://auth.openai.com/api/oauth/oauth2/auth")
        self.assertEqual(len(fake_session.post_calls), 1)

    def test_protocol_registrar_step0_falls_back_to_browser_bootstrap_when_authorize_blocked(self):
        class FakeCookies(dict):
            def __init__(self):
                super().__init__()
                self.jar = []

            def set(self, name, value, domain=""):
                del domain
                self[name] = value

        class FakeResponse:
            def __init__(self, status_code, *, url="", text="", json_data=None):
                self.status_code = status_code
                self.url = url
                self.text = text
                self._json_data = json_data
                self.headers = {}

            def json(self):
                if self._json_data is None:
                    raise ValueError("no json")
                return self._json_data

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.get_calls = []
                self.post_calls = []

            def get(self, url, **kwargs):
                self.get_calls.append((url, kwargs))
                return FakeResponse(
                    403,
                    url="https://auth.openai.com/api/oauth/oauth2/auth",
                    text="<!DOCTYPE html><title>Just a moment...</title>",
                )

            def post(self, url, **kwargs):
                self.post_calls.append((url, kwargs))
                return FakeResponse(
                    200,
                    url=url,
                    json_data={"page": {"type": "password"}},
                )

        def fake_browser_bootstrap(session, authorize_url, *, user_agent, proxy, timeout_ms):
            self.assertIn("/oauth/authorize?", authorize_url)
            self.assertTrue(user_agent)
            self.assertEqual(proxy, "")
            self.assertEqual(timeout_ms, 45000)
            session.cookies.set("login_session", "login-cookie", domain="auth.openai.com")
            return {
                "success": True,
                "final_url": "https://auth.openai.com/u/signup/identifier",
                "cookie_count": 1,
                "browser_tokens": {
                    "authorize_continue": '{"token":"browser-ok"}',
                },
                "auth_session": {"workspaces": []},
                "sentinel_artifacts": {"flows": {}},
            }

        fake_session = FakeSession()
        with mock.patch("protocol_keygen.create_session", return_value=fake_session):
            registrar = protocol_keygen.ProtocolRegistrar(browser_tokens={"authorize_continue": '{"token":"ok"}'})
        registrar.device_id = "did-123"

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch(
                    "protocol_keygen._bootstrap_login_session_via_browser",
                    side_effect=fake_browser_bootstrap,
                    create=True,
                ) as bootstrap_mock:
                    ok = registrar.step0_init_oauth_session("user@example.com")

        self.assertTrue(ok)
        bootstrap_mock.assert_called_once()
        self.assertEqual(len(fake_session.post_calls), 1)
        post_url, post_kwargs = fake_session.post_calls[0]
        self.assertEqual(post_url, "https://auth.openai.com/api/accounts/authorize/continue")
        self.assertEqual(
            post_kwargs["json"],
            {
                "username": {"kind": "email", "value": "user@example.com"},
                "screen_hint": "signup",
            },
        )
        self.assertEqual(post_kwargs["headers"]["openai-sentinel-token"], '{"token":"browser-ok"}')

    def test_protocol_registrar_step0_fails_when_browser_bootstrap_still_lacks_login_session(self):
        class FakeCookies(dict):
            def __init__(self):
                super().__init__()
                self.jar = []

            def set(self, name, value, domain=""):
                del domain
                self[name] = value

        class FakeResponse:
            def __init__(self, status_code, *, url="", text="", json_data=None):
                self.status_code = status_code
                self.url = url
                self.text = text
                self._json_data = json_data
                self.headers = {}

            def json(self):
                if self._json_data is None:
                    raise ValueError("no json")
                return self._json_data

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.get_calls = []
                self.post_calls = []

            def get(self, url, **kwargs):
                self.get_calls.append((url, kwargs))
                return FakeResponse(
                    403,
                    url="https://auth.openai.com/api/oauth/oauth2/auth",
                    text="<!DOCTYPE html><title>Just a moment...</title>",
                )

            def post(self, url, **kwargs):
                self.post_calls.append((url, kwargs))
                return FakeResponse(200, url=url, json_data={"page": {"type": "password"}})

        fake_session = FakeSession()
        with mock.patch("protocol_keygen.create_session", return_value=fake_session):
            registrar = protocol_keygen.ProtocolRegistrar(browser_tokens={"authorize_continue": '{"token":"ok"}'})

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch(
                    "protocol_keygen._bootstrap_login_session_via_browser",
                    return_value={
                        "success": False,
                        "final_url": "https://auth.openai.com/u/signup/identifier",
                        "cookie_count": 0,
                        "error": "login_session missing after browser bootstrap",
                        "browser_tokens": {
                            "authorize_continue": '{"token":"browser-but-no-login"}',
                        },
                    },
                ) as bootstrap_mock:
                    ok = registrar.step0_init_oauth_session("user@example.com")

        self.assertFalse(ok)
        bootstrap_mock.assert_called_once()
        self.assertEqual(fake_session.post_calls, [])
        self.assertEqual(registrar._browser_tokens["authorize_continue"], '{"token":"ok"}')

    def test_legacy_playwright_init_uses_shared_browser_bootstrap(self):
        register = ncs_register_legacy.ChatGPTRegister.__new__(ncs_register_legacy.ChatGPTRegister)
        register._print = mock.Mock()
        register.session = mock.Mock()
        register.session.cookies = []
        register.session.post = mock.Mock(return_value=mock.Mock(status_code=200, text=""))
        register.AUTH = "https://auth.openai.com"
        register.ua = "UA-123"
        register.proxy = "http://127.0.0.1:9000"
        register.device_id = "did-123"
        register.sec_ch_ua = '"Chromium";v="136"'
        register.impersonate = "chrome136"

        with mock.patch("ncs_register_legacy._generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("ncs_register_legacy.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch("protocol_keygen._bootstrap_login_session_via_browser", return_value={
                    "success": True,
                    "final_url": "https://auth.openai.com/u/signup/identifier",
                    "cookie_count": 2,
                }) as bootstrap_mock:
                    with mock.patch("ncs_register_legacy.build_sentinel_token", return_value='{"token":"legacy-ac"}'):
                        ncs_register_legacy.ChatGPTRegister._init_oauth_via_playwright(register, "user@example.com")

        bootstrap_mock.assert_called_once()
        call_args = bootstrap_mock.call_args
        self.assertEqual(call_args.args[0], register.session)
        self.assertIn("/oauth/authorize?", call_args.args[1])
        self.assertEqual(call_args.kwargs["user_agent"], "UA-123")
        self.assertEqual(call_args.kwargs["proxy"], "http://127.0.0.1:9000")
        self.assertEqual(call_args.kwargs["timeout_ms"], 45000)
        register.session.post.assert_called_once()
        self.assertEqual(
            register.session.post.call_args.kwargs["headers"]["openai-sentinel-token"],
            '{"token":"legacy-ac"}',
        )

    def test_registration_engine_passes_account_tag_into_protocol_oauth(self):
        mailbox_service = mock.Mock()
        mailbox_service.create_mailbox.return_value = ncs_register.MailboxSession(
            email="tagged@example.com",
            password="",
            token="mail-token",
            provider="tempmail_lol",
        )
        mailbox_service.wait_for_verification_code = mock.Mock(return_value="123456")

        fake_protocol_keygen = types.ModuleType("protocol_keygen")

        class FakeRegistrar:
            def __init__(self, browser_tokens=None):
                self.browser_tokens = browser_tokens
                self.session = mock.Mock()

            def step0_init_oauth_session(self, email):
                return True

            def step2_register_user(self, email, password):
                return True

            def step3_send_otp(self):
                return True

            def step4_validate_otp(self, code):
                return True

            def step5_create_account(self, first_name, last_name, birthdate):
                return True

        fake_protocol_keygen.ProtocolRegistrar = FakeRegistrar
        fake_protocol_keygen.create_session = mock.Mock()
        fake_protocol_keygen.perform_codex_oauth_login_http = mock.Mock(return_value={"access_token": "token-xyz"})
        fake_protocol_keygen.save_tokens = mock.Mock()
        fake_protocol_keygen.save_account = mock.Mock()
        fake_protocol_keygen.create_temp_email = mock.Mock()
        fake_protocol_keygen.PROXY = ""
        fake_protocol_keygen.COMMON_HEADERS = {"user-agent": "UA-123"}

        fake_sentinel_browser = types.ModuleType("sentinel_browser")
        fake_sentinel_browser.get_all_sentinel_tokens = mock.Mock(return_value={"authorize_continue": '{"token":"ok"}'})

        with mock.patch.object(runtime_engine, "build_mailbox_service", return_value=mailbox_service):
            with mock.patch.object(ncs_register_legacy, "ChatGPTRegister", return_value=mock.Mock(tag="")):
                with mock.patch.dict(sys.modules, {
                    "protocol_keygen": fake_protocol_keygen,
                    "sentinel_browser": fake_sentinel_browser,
                }):
                    with mock.patch("ncs_register_legacy._save_codex_tokens"):
                        engine = runtime_engine.RegistrationEngine(idx=1, total=1, proxy=None, output_file="out.txt")
                        with mock.patch.object(engine, "_append_result"):
                            result = engine.run()

        self.assertTrue(result.success)
        kwargs = fake_protocol_keygen.perform_codex_oauth_login_http.call_args.kwargs
        self.assertEqual(kwargs["tag"], "tagged")

    def test_run_register_does_not_treat_auth_authorize_url_with_chatgpt_redirect_query_as_complete(self):
        register = ncs_register_legacy.ChatGPTRegister.__new__(ncs_register_legacy.ChatGPTRegister)
        register._print = mock.Mock()
        register.visit_homepage = mock.Mock()
        register.get_csrf = mock.Mock(return_value="csrf-token")
        register.signin = mock.Mock(return_value="https://auth.openai.com/api/accounts/authorize")
        register.authorize = mock.Mock(
            return_value=(
                "https://auth.openai.com/api/accounts/authorize"
                "?redirect_uri=https%3A%2F%2Fchatgpt.com%2Fapi%2Fauth%2Fcallback%2Fopenai"
            )
        )
        register.register = mock.Mock(return_value=(200, {}))
        register.send_otp = mock.Mock(return_value=(200, {}))
        register.wait_for_verification_email = mock.Mock(return_value="123456")
        register.validate_otp = mock.Mock(return_value=(200, {}))
        register.create_account = mock.Mock(return_value=(200, {}))
        register.callback = mock.Mock(return_value=(200, {"final_url": "https://chatgpt.com/"}))
        register._cfmail_account_name = ""

        with mock.patch("ncs_register_legacy._random_delay", return_value=None):
            ok = ncs_register_legacy.ChatGPTRegister.run_register(
                register,
                "user@example.com",
                "Password-1!",
                "Noah Thomas",
                "2002-05-11",
                "mail-token",
                provider="cfmail",
            )

        self.assertTrue(ok)
        register.register.assert_called_once_with("user@example.com", "Password-1!")
        register.send_otp.assert_called_once()
        register.wait_for_verification_email.assert_called_once()
        register.create_account.assert_called_once_with("Noah Thomas", "2002-05-11")
        register.callback.assert_called_once()

    def test_run_register_resends_otp_when_authorize_lands_on_email_verification(self):
        register = ncs_register_legacy.ChatGPTRegister.__new__(ncs_register_legacy.ChatGPTRegister)
        register._print = mock.Mock()
        register.visit_homepage = mock.Mock()
        register.get_csrf = mock.Mock(return_value="csrf-token")
        register.signin = mock.Mock(return_value="https://auth.openai.com/api/accounts/authorize")
        register.authorize = mock.Mock(return_value="https://auth.openai.com/email-verification")
        register.send_otp = mock.Mock(return_value=(200, {}))
        register.wait_for_verification_email = mock.Mock(return_value="123456")
        register.validate_otp = mock.Mock(return_value=(200, {}))
        register.create_account = mock.Mock(return_value=(200, {}))
        register.callback = mock.Mock(return_value=(200, {"final_url": "https://chatgpt.com/"}))
        register._cfmail_account_name = ""

        with mock.patch("ncs_register_legacy._random_delay", return_value=None):
            ok = ncs_register_legacy.ChatGPTRegister.run_register(
                register,
                "user@example.com",
                "Password-1!",
                "Noah Thomas",
                "2002-05-11",
                "mail-token",
                provider="cfmail",
            )

        self.assertTrue(ok)
        register.send_otp.assert_called_once()
        register.wait_for_verification_email.assert_called_once()
        register.validate_otp.assert_called_once_with("123456")
        register.create_account.assert_called_once_with("Noah Thomas", "2002-05-11")

    def test_ncs_register_main_exits_nonzero_when_batch_fails(self):
        with mock.patch("ncs_register.MAIL_PROVIDER", "tempmail_lol"):
            with mock.patch("ncs_register.DEFAULT_PROXY", ""):
                with mock.patch("ncs_register.legacy.UPLOAD_API_URL", ""):
                    with mock.patch.dict("os.environ", {
                        "HTTPS_PROXY": "",
                        "https_proxy": "",
                        "ALL_PROXY": "",
                        "all_proxy": "",
                    }, clear=False):
                        with mock.patch("builtins.input", side_effect=[
                            "",   # proxy
                            "n",  # preflight
                            "registered_accounts.txt",
                            "1",
                            "1",
                            "3",
                        ]):
                            with mock.patch("ncs_register.run_batch", return_value=False):
                                with self.assertRaises(SystemExit) as exc:
                                    ncs_register.main()

        self.assertEqual(exc.exception.code, 1)

    def test_load_config_supports_batch_runtime_defaults(self):
        fake_config = {
            "batch_mode": "pipeline",
            "task_launch_interval_min_seconds": 2,
            "task_launch_interval_max_seconds": 5,
        }
        with mock.patch("ncs_register.os.path.exists", return_value=True):
            with mock.patch("builtins.open", mock.mock_open(read_data="{}")):
                with mock.patch("ncs_register.json.load", return_value=fake_config):
                    config = ncs_register._load_config()

        self.assertEqual(config["batch_mode"], "pipeline")
        self.assertEqual(config["task_launch_interval_min_seconds"], 2)
        self.assertEqual(config["task_launch_interval_max_seconds"], 5)

    def test_build_codex_session_tokens_uses_access_token_and_workspace_email_prefix(self):
        fake_now = mock.Mock()
        fake_now.isoformat.return_value = "2026-03-30T00:00:00+00:00"
        fake_expires = mock.Mock()
        fake_expires.isoformat.return_value = "2026-04-09T00:00:00+00:00"

        with mock.patch("ncs_register_legacy._utc_now", return_value=fake_now):
            with mock.patch("ncs_register_legacy._utc_expiry_after_days", return_value=fake_expires):
                token_data = ncs_register_legacy._build_codex_session_tokens(
                    "workspace123@email.loki.us.ci",
                    {"accessToken": "token-abc"},
                )

        self.assertEqual(token_data["id_token"], "token-abc")
        self.assertEqual(token_data["access_token"], "token-abc")
        self.assertEqual(token_data["refresh_token"], "")
        self.assertEqual(token_data["account_id"], "workspace123")
        self.assertEqual(token_data["email"], "workspace123@email.loki.us.ci")
        self.assertEqual(token_data["type"], "codex")
        self.assertEqual(token_data["last_refresh"], "2026-03-30T00:00:00+00:00")
        self.assertEqual(token_data["expired"], "2026-04-09T00:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
