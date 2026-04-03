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
            "[existing-session] 未能直接获取 token，回退 fresh login",
        ])

        reason = runtime_engine._extract_stage_failure_reason(output, "OAuth Token 获取失败")

        self.assertEqual(reason, "未能直接获取 token，回退 fresh login")

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
        with mock.patch.object(ncs_register_legacy, "_upload_all_tokens_to_cpa", side_effect=fake_upload):
            with mock.patch("sys.stdout", new=output):
                uploaded, failed, reason = runtime_batch._run_cpa_upload_with_compact_log()

        self.assertEqual((uploaded, failed), (1, 2))
        self.assertEqual(reason, "成功 1 个, 失败 2 个")
        self.assertEqual(output.getvalue().strip(), "[CPA上传] ❌上传失败: 成功 1 个, 失败 2 个")

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

    def test_auto_scheduler_defaults_register_workers_to_8(self):
        self.assertEqual(auto_scheduler.AUTO_PARAMS["max_workers"], 8)

    def test_auto_scheduler_uploads_each_success_immediately_by_default(self):
        self.assertEqual(auto_scheduler.AUTO_PARAMS["cpa_upload_every_n"], 1)

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
        self.assertIn("MAIL_PROVIDER", workflow)
        self.assertIn("PROXY", workflow)
        self.assertIn("UPLOAD_API_PROXY", workflow)

    def test_scheduler_workflow_cfmail_diagnose_prefers_active_cached_domain(self):
        workflow = Path(".github/workflows/scheduler.yml").read_text(encoding="utf-8")
        self.assertIn("zhuce5_cfmail_accounts.json", workflow)
        self.assertIn("active_domain", workflow)
        self.assertIn("item.get('enabled', True)", workflow)
        self.assertIn("ed = active_domain or os.environ.get('CFMAIL_EMAIL_DOMAIN','').strip()", workflow)

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

    def test_run_batch_initial_rotation_does_not_skip_cfmail_smoke(self):
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

        self.assertEqual(rotate_kwargs, [{}])
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

        self.assertEqual(rotate_kwargs, [{}])

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

        self.assertEqual(len(rotate_kwargs), 2)

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

    def test_perform_codex_oauth_login_http_reuses_registrar_session_before_fresh_login(self):
        registrar_session = mock.Mock()
        registrar_session.get.return_value = types.SimpleNamespace(
            status_code=302,
            headers={"Location": "http://localhost:1455/auth/callback?code=code-123&state=state-123"},
            url="https://auth.openai.com/oauth/authorize",
            text="",
        )

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch("protocol_keygen.codex_exchange_code", return_value={"access_token": "token-xyz"}) as exchange_mock:
                    with mock.patch("protocol_keygen.create_session", side_effect=AssertionError("fresh session should not be used")):
                        tokens = protocol_keygen.perform_codex_oauth_login_http(
                            "user@example.com",
                            "Password-1!",
                            registrar_session=registrar_session,
                        )

        self.assertEqual(tokens, {"access_token": "token-xyz"})
        exchange_mock.assert_called_once_with("code-123", "verifier-123")

    def test_perform_codex_oauth_login_http_uses_registrar_workspace_flow_before_fresh_login(self):
        def _encode_cookie(payload):
            encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
            return f"{encoded}.timestamp.signature"

        class FakeCookie:
            def __init__(self, name, value, domain="auth.openai.com"):
                self.name = name
                self.value = value
                self.domain = domain

        class FakeCookies(dict):
            def __init__(self, mapping=None):
                super().__init__(mapping or {})
                self.jar = [FakeCookie(name, value) for name, value in self.items()]

            def set(self, name, value, domain=""):
                self[name] = value
                self.jar.append(FakeCookie(name, value, domain=domain or ""))

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
                self.calls = []
                self.cookies = FakeCookies(
                    {
                        "oai-client-auth-session": _encode_cookie({"workspaces": [{"id": "ws-123"}]}),
                    }
                )

            def get(self, url, **kwargs):
                self.calls.append(("GET", url, kwargs))
                if url.startswith("https://auth.openai.com/oauth/authorize"):
                    return FakeResponse(
                        302,
                        headers={"Location": "https://auth.openai.com/add-phone"},
                        url=url,
                    )
                if url == "https://chatgpt.com/api/auth/session":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={"WARNING_BANNER": {"message": "phone required"}},
                    )
                raise AssertionError(f"unexpected GET: {url}")

            def post(self, url, **kwargs):
                self.calls.append(("POST", url, kwargs))
                if url == "https://auth.openai.com/api/accounts/workspace/select":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={
                            "continue_url": "/organization/select",
                            "data": {
                                "orgs": [
                                    {
                                        "id": "org-123",
                                        "projects": [{"id": "proj-123"}],
                                    }
                                ]
                            },
                        },
                    )
                if url == "https://auth.openai.com/api/accounts/organization/select":
                    return FakeResponse(
                        302,
                        url=url,
                        headers={
                            "Location": "http://localhost:1455/auth/callback?code=code-ws&state=state-123",
                        },
                    )
                raise AssertionError(f"unexpected POST: {url}")

        registrar_session = FakeSession()

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch("protocol_keygen.codex_exchange_code", return_value={"access_token": "token-ws"}) as exchange_mock:
                    with mock.patch("protocol_keygen.create_session", side_effect=AssertionError("fresh session should not be used")):
                        tokens = protocol_keygen.perform_codex_oauth_login_http(
                            "user@example.com",
                            "Password-1!",
                            registrar_session=registrar_session,
                        )

        self.assertEqual(tokens, {"access_token": "token-ws"})
        exchange_mock.assert_called_once_with("code-ws", "verifier-123")
        self.assertIn(
            ("POST", "https://auth.openai.com/api/accounts/workspace/select", mock.ANY),
            registrar_session.calls,
        )
        self.assertIn(
            ("POST", "https://auth.openai.com/api/accounts/organization/select", mock.ANY),
            registrar_session.calls,
        )

    def test_perform_codex_oauth_login_http_uses_client_auth_session_dump_before_fresh_login(self):
        class FakeCookies(dict):
            def __init__(self, mapping=None):
                super().__init__(mapping or {})
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
                self.calls = []
                self.cookies = FakeCookies()

            def get(self, url, **kwargs):
                self.calls.append(("GET", url, kwargs))
                if url.startswith("https://auth.openai.com/oauth/authorize"):
                    return FakeResponse(
                        302,
                        headers={"Location": "https://auth.openai.com/add-phone"},
                        url=url,
                    )
                if url == "https://chatgpt.com/api/auth/session":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={"WARNING_BANNER": {"message": "phone required"}},
                    )
                if url == "https://auth.openai.com/api/accounts/client_auth_session_dump":
                    return FakeResponse(
                        200,
                        url=url,
                        json_data={
                            "session_id": "sess-123",
                            "client_auth_session": {"workspaces": [{"id": "ws-dump"}]},
                        },
                    )
                raise AssertionError(f"unexpected GET: {url}")

            def post(self, url, **kwargs):
                self.calls.append(("POST", url, kwargs))
                if url == "https://auth.openai.com/api/accounts/workspace/select":
                    return FakeResponse(
                        302,
                        url=url,
                        headers={
                            "Location": "http://localhost:1455/auth/callback?code=code-dump&state=state-123",
                        },
                    )
                raise AssertionError(f"unexpected POST: {url}")

        registrar_session = FakeSession()

        with mock.patch("protocol_keygen.generate_pkce", return_value=("verifier-123", "challenge-123")):
            with mock.patch("protocol_keygen.secrets.token_urlsafe", return_value="state-123"):
                with mock.patch("protocol_keygen.codex_exchange_code", return_value={"access_token": "token-dump"}) as exchange_mock:
                    with mock.patch("protocol_keygen.create_session", side_effect=AssertionError("fresh session should not be used")):
                        tokens = protocol_keygen.perform_codex_oauth_login_http(
                            "user@example.com",
                            "Password-1!",
                            registrar_session=registrar_session,
                        )

        self.assertEqual(tokens, {"access_token": "token-dump"})
        exchange_mock.assert_called_once_with("code-dump", "verifier-123")
        self.assertIn(
            ("GET", "https://auth.openai.com/api/accounts/client_auth_session_dump", mock.ANY),
            registrar_session.calls,
        )

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
