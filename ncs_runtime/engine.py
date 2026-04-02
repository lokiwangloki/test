from dataclasses import dataclass
from typing import Optional

import ncs_register_legacy as legacy

from .email_services import LaMailMailboxService, build_mailbox_service, should_fallback_to_lamail
from .v2_flow import run_registration_v2


@dataclass
class RegistrationResult:
    idx: int
    success: bool
    provider: str
    email: str = ""
    email_password: str = ""
    chatgpt_password: str = ""
    oauth_ok: bool = False
    error_message: str = ""


class RegistrationEngine:
    """Single-account registration engine modeled after the reference project."""

    def __init__(self, idx: int, total: int, proxy: Optional[str], output_file: str):
        self.idx = idx
        self.total = total
        self.proxy = proxy
        self.output_file = output_file

    def _append_result(self, mailbox, chatgpt_password: str, oauth_ok: bool) -> None:
        with legacy._file_lock:
            with open(self.output_file, "a", encoding="utf-8") as out:
                line = f"{mailbox.email}----{chatgpt_password}"
                if mailbox.password:
                    line += f"----{mailbox.password}"
                line += f"----oauth={'ok' if oauth_ok else 'fail'}\n"
                out.write(line)

    def _create_mailbox_with_fallback(self, register_client, provider: str):
        mailbox_service = build_mailbox_service(register_client, provider)
        register_client._print(f"[{provider}] 初始化邮箱服务...")
        try:
            mailbox = mailbox_service.create_mailbox()
            return mailbox_service, mailbox, provider
        except Exception as error:
            if provider == "tempmail_lol" and should_fallback_to_lamail(error):
                register_client._print("[tempmail_lol] 命中 429 限流，自动切换到 lamail...")
                fallback_service = LaMailMailboxService(register_client)
                mailbox = fallback_service.create_mailbox()
                return fallback_service, mailbox, "lamail"
            raise

    def run(self) -> RegistrationResult:
        provider = legacy.MAIL_PROVIDER
        try:
            register_client = legacy.ChatGPTRegister(proxy=self.proxy, tag=f"{self.idx}")
            mailbox_service, mailbox, effective_provider = self._create_mailbox_with_fallback(
                register_client, provider
            )
            register_client.tag = mailbox.email.split("@")[0]

            chatgpt_password = legacy._generate_password()
            name = legacy._random_name()
            birthdate = legacy._random_birthdate()

            with legacy._print_lock:
                print(f"\n{'=' * 60}")
                print(f"  [{self.idx}/{self.total}] 注册: {mailbox.email}")
                print(f"  邮箱服务: {effective_provider}")
                print(f"  ChatGPT密码: {chatgpt_password}")
                if mailbox.password:
                    print(f"  邮箱密码: {mailbox.password}")
                print(f"  姓名: {name} | 生日: {birthdate}")
                print(f"{'=' * 60}")

            otp_fetcher = mailbox_service.wait_for_verification_code

            oauth_ok = True
            register_client._print("[Legacy] 开始执行本地同款注册流程...")
            register_client.run_register(
                mailbox.email,
                chatgpt_password,
                name,
                birthdate,
                mailbox.token,
                provider=effective_provider,
                otp_fetcher=otp_fetcher,
            )
            if legacy.ENABLE_OAUTH:
                register_client._print("[OAuth] 开始获取 Codex Token...")
                tokens = register_client.fetch_codex_session_tokens(
                    mailbox.email,
                    chatgpt_password,
                    mail_token=mailbox.token,
                    provider=effective_provider,
                    otp_fetcher=otp_fetcher,
                )
                oauth_ok = bool(tokens and tokens.get("access_token"))
                if oauth_ok:
                    legacy._save_codex_tokens(mailbox.email, tokens)
                    register_client._print("[OAuth] Token 已保存")
                else:
                    message = "OAuth Token 获取失败"
                    if legacy.OAUTH_REQUIRED:
                        raise Exception(f"{message}（oauth_required=true）")
                    register_client._print(f"[OAuth] {message}（按配置继续）")

            self._append_result(mailbox, chatgpt_password, oauth_ok)

            with legacy._print_lock:
                print(f"\n[OK] [{register_client.tag}] {mailbox.email} 注册成功!")

            return RegistrationResult(
                idx=self.idx,
                success=True,
                provider=effective_provider,
                email=mailbox.email,
                email_password=mailbox.password,
                chatgpt_password=chatgpt_password,
                oauth_ok=oauth_ok,
            )
        except Exception as error:
            with legacy._print_lock:
                print(f"\n[FAIL] [{self.idx}] 注册失败: {error}")
                legacy.traceback.print_exc()
            return RegistrationResult(
                idx=self.idx,
                success=False,
                provider=provider,
                error_message=str(error),
            )
