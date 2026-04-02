import unittest
import sys
import types
from pathlib import Path
from unittest import mock

import auto_scheduler

fake_curl_cffi = types.ModuleType("curl_cffi")
fake_curl_cffi.requests = types.SimpleNamespace()
sys.modules.setdefault("curl_cffi", fake_curl_cffi)

import ncs_register
import ncs_register_legacy
from ncs_runtime import email_services, engine as runtime_engine


class ProxyNormalizationTests(unittest.TestCase):
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

    def test_mailbox_service_factory_supports_lamail_tempmail_and_wildmail(self):
        fake_register = object()
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

    def test_legacy_mailbox_service_factory_supports_wildmail(self):
        register_client = mock.Mock()

        self.assertIsInstance(
            ncs_register_legacy._build_mailbox_service(register_client, "wildmail"),
            ncs_register_legacy.WildmailMailboxService,
        )

    def test_legacy_main_accepts_wildmail_provider(self):
        with mock.patch.object(ncs_register_legacy, "MAIL_PROVIDER", "wildmail"):
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

    def test_wildmail_service_creates_mailbox_via_register_client(self):
        register_client = mock.Mock()
        register_client.create_wildmail_email.return_value = ("wild@example.com", "", "wild-token")

        service = email_services.WildmailMailboxService(register_client)
        mailbox = service.create_mailbox()

        self.assertEqual(mailbox.email, "wild@example.com")
        self.assertEqual(mailbox.token, "wild-token")
        self.assertEqual(mailbox.provider, "wildmail")
        register_client.create_wildmail_email.assert_called_once()

    def test_tempmail_rate_limit_falls_back_to_lamail(self):
        register_client = mock.Mock()
        register_client.create_tempmail_lol_email.side_effect = Exception(
            'TempMail.lol 创建失败: 429 - {"error":"Rate limited (free)"}'
        )
        register_client.create_lamail_email.return_value = ("fallback@example.com", "", "token-1")
        register_client._print = mock.Mock()

        engine = runtime_engine.RegistrationEngine(idx=1, total=1, proxy=None, output_file="out.txt")
        service, mailbox, provider = engine._create_mailbox_with_fallback(register_client, "tempmail_lol")

        self.assertIsInstance(service, email_services.LaMailMailboxService)
        self.assertEqual(provider, "lamail")
        self.assertEqual(mailbox.email, "fallback@example.com")

    def test_tempmail_http_429_without_rate_limit_phrase_still_falls_back(self):
        register_client = mock.Mock()
        register_client.create_tempmail_lol_email.side_effect = Exception(
            "TempMail.lol 创建失败: HTTP 429 Too Many Requests"
        )
        register_client.create_lamail_email.return_value = ("fallback2@example.com", "", "token-2")
        register_client._print = mock.Mock()

        engine = runtime_engine.RegistrationEngine(idx=1, total=1, proxy=None, output_file="out.txt")
        service, mailbox, provider = engine._create_mailbox_with_fallback(register_client, "tempmail_lol")

        self.assertIsInstance(service, email_services.LaMailMailboxService)
        self.assertEqual(provider, "lamail")
        self.assertEqual(mailbox.email, "fallback2@example.com")

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
                with mock.patch.object(runtime_engine, "run_registration_v2", side_effect=AssertionError("v2 flow should not run")):
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
