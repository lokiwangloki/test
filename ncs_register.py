"""CLI entrypoint for the task-driven registration runtime."""

import json
import os

import ncs_register_legacy as legacy
from ncs_runtime.batch import run_batch
from ncs_runtime.email_services import (
    BaseMailboxService,
    CfmailMailboxService,
    DuckMailMailboxService,
    LaMailMailboxService,
    MailboxSession,
    TempmailLolMailboxService,
    WildmailMailboxService,
    build_mailbox_service,
)
from ncs_runtime.engine import RegistrationEngine, RegistrationResult

_normalize_proxy_value = legacy._normalize_proxy_value
_load_config = legacy._load_config
_quick_preflight = legacy._quick_preflight

MAIL_PROVIDER = legacy.MAIL_PROVIDER
SUPPORTED_MAIL_PROVIDERS = legacy.SUPPORTED_MAIL_PROVIDERS
DEFAULT_PROXY = legacy.DEFAULT_PROXY
DEFAULT_OUTPUT_FILE = legacy.DEFAULT_OUTPUT_FILE
DEFAULT_TOTAL_ACCOUNTS = legacy.DEFAULT_TOTAL_ACCOUNTS
CPA_UPLOAD_EVERY_N = legacy.CPA_UPLOAD_EVERY_N
TEMPMAIL_LOL_API_BASE = legacy.TEMPMAIL_LOL_API_BASE
LAMAIL_API_BASE = legacy.LAMAIL_API_BASE
LAMAIL_DOMAIN = legacy.LAMAIL_DOMAIN
ENABLE_OAUTH = legacy.ENABLE_OAUTH
OAUTH_REQUIRED = legacy.OAUTH_REQUIRED


def _build_mailbox_service(register_client, provider: str) -> BaseMailboxService:
    return build_mailbox_service(register_client, provider)


def _register_one(idx, total, proxy, output_file):
    result = RegistrationEngine(idx=idx, total=total, proxy=proxy, output_file=output_file).run()
    return result.success, result.email or None, result.error_message or None


def main():
    print("=" * 60)
    print("  ChatGPT 批量自动注册工具")
    print(f"  邮箱服务: {MAIL_PROVIDER}")
    print("=" * 60)

    provider = MAIL_PROVIDER
    if provider == "duckmail":
        try:
            import get_duck
            duck_pool = get_duck.resolve_output_file()
            duck_count = len(get_duck.load_duck_addresses(str(duck_pool)))
            print(f"\n[Info] Duck 邮箱池: {duck_pool}")
            print(f"[Info] Duck 邮箱数量: {duck_count}")
        except Exception as e:
            print(f"\n[Warn] Duck 邮箱池读取失败: {e}")
    elif provider == "cfmail":
        if legacy.CFMAIL_ACCOUNTS:
            cfmail_names = ", ".join(account.name for account in legacy.CFMAIL_ACCOUNTS)
            print(f"\n[Info] cfmail 配置已加载: {cfmail_names}")
            print(f"[Info] cfmail 模式: {legacy.CFMAIL_PROFILE_MODE}")
        else:
            print(f"\n[Warn] mail_provider=cfmail 但未找到可用配置: {legacy._CFMAIL_CONFIG_PATH}")
            print("[Warn] 也可以通过环境变量注入 CFMAIL_WORKER_DOMAIN / CFMAIL_EMAIL_DOMAIN / CFMAIL_ADMIN_PASSWORD")
    elif provider == "tempmail_lol":
        print(f"\n[Info] TempMail.lol 已启用: {TEMPMAIL_LOL_API_BASE}")
    elif provider == "lamail":
        print(f"\n[Info] LaMail 已启用: {LAMAIL_API_BASE}")
        if LAMAIL_DOMAIN:
            print(f"[Info] LaMail 指定域名: {LAMAIL_DOMAIN}")
    elif provider == "wildmail":
        print(f"\n[Info] Wildmail 已启用: {legacy.WILDMAIL_API_BASE}")
    else:
        print(f"\n❌ 错误: 不支持的 mail_provider={provider}")
        print("   可选值: duckmail / cfmail / lamail / tempmail_lol / wildmail")
        return

    proxy = DEFAULT_PROXY
    if proxy:
        print(f"[Info] 检测到默认代理: {proxy}")
        use_default = input("使用此代理? (Y/n): ").strip().lower()
        if use_default == "n":
            proxy = input("输入代理地址 (留空=不使用代理): ").strip() or None
    else:
        env_proxy = (
            os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
            or os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")
        )
        if env_proxy:
            print(f"[Info] 检测到环境变量代理: {env_proxy}")
            use_env = input("使用此代理? (Y/n): ").strip().lower()
            proxy = None if use_env == "n" else env_proxy
            if use_env == "n":
                proxy = input("输入代理地址 (留空=不使用代理): ").strip() or None
        else:
            proxy = input("输入代理地址 (如 http://127.0.0.1:7890，留空=不使用代理): ").strip() or None

    print(f"[Info] {'使用代理: ' + proxy if proxy else '不使用代理'}")

    preflight_input = input("\n执行启动前连通性预检? (Y/n): ").strip().lower()
    if preflight_input != "n":
        if not _quick_preflight(proxy=proxy, provider=provider):
            print("\n⚠️  预检失败，按 Enter 退出；输入 c 可继续强制运行")
            action = input("继续? (c/Enter): ").strip().lower()
            if action != "c":
                return

    output_file = input(f"\n输出文件名 (默认 {DEFAULT_OUTPUT_FILE}): ").strip() or DEFAULT_OUTPUT_FILE
    total_input = input(f"注册账号数量 (默认 {DEFAULT_TOTAL_ACCOUNTS}): ").strip()
    total_accounts = int(total_input) if total_input else DEFAULT_TOTAL_ACCOUNTS
    workers_input = input("并发数 (默认 3): ").strip()
    max_workers = int(workers_input) if workers_input else 3

    cpa_cleanup = None
    if legacy.UPLOAD_API_URL:
        cleanup_input = input("\n注册前清理 CPA 无效号? (Y/n): ").strip().lower()
        cpa_cleanup = cleanup_input != "n"

    upload_n_input = input(f"每成功多少个账号触发 CPA 上传 (默认 {CPA_UPLOAD_EVERY_N}): ").strip()
    cpa_upload_every_n = int(upload_n_input) if upload_n_input else CPA_UPLOAD_EVERY_N

    ok = run_batch(
        total_accounts=total_accounts,
        output_file=output_file,
        max_workers=max_workers,
        proxy=proxy,
        cpa_cleanup=cpa_cleanup,
        cpa_upload_every_n=cpa_upload_every_n,
    )
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
