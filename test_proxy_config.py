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
        }
        with mock.patch.dict("os.environ", {
            "MY_LAMAIL_KEY": "secret-key",
            "MY_LAMAIL_DOMAIN": "mail.example.com",
        }, clear=False):
            with mock.patch("ncs_register.os.path.exists", return_value=True):
                with mock.patch("builtins.open", mock.mock_open(read_data="{}")):
                    with mock.patch("ncs_register.json.load", return_value=fake_config):
                        config = ncs_register._load_config()

        self.assertEqual(config["lamail_api_key"], "secret-key")
        self.assertEqual(config["lamail_domain"], "mail.example.com")

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
            "total_accounts": 200,
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
            "\nn\nregistered_accounts.txt\n200\n3\nn\n3\n",
        )

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
            with mock.patch("auto_scheduler.count_valid_accounts_local", return_value=999):
                with mock.patch("auto_scheduler.time.sleep") as sleep_mock:
                    auto_scheduler.main()

        sleep_mock.assert_not_called()

    def test_scheduler_workflow_uses_staggered_cron(self):
        workflow = Path(".github/workflows/scheduler.yml").read_text(encoding="utf-8")
        self.assertIn("cron: '7 * * * *'", workflow)

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

    def test_mailbox_service_factory_supports_lamail_and_tempmail_only(self):
        fake_register = object()
        self.assertIsInstance(
            ncs_register._build_mailbox_service(fake_register, "lamail"),
            ncs_register.LaMailMailboxService,
        )
        self.assertIsInstance(
            ncs_register._build_mailbox_service(fake_register, "tempmail_lol"),
            ncs_register.TempmailLolMailboxService,
        )
        with self.assertRaises(ValueError):
            ncs_register._build_mailbox_service(fake_register, "duckmail")

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


if __name__ == "__main__":
    unittest.main()
