import time
from dataclasses import dataclass
from typing import Optional

import ncs_register_legacy as legacy

from .email_services import build_mailbox_service, get_provider_candidates


_KNOWN_ERROR_CODES = frozenset({
    "registration_disallowed",
    "unsupported_email",
    "user_already_exists",
})


def _extract_error_code(message: str) -> str:
    msg = str(message or "").lower()
    for code in _KNOWN_ERROR_CODES:
        if code in msg:
            return code
    return ""


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
    error_code: str = ""


class RegistrationEngine:
    """Single-account registration engine using protocol_keygen (codex oauth loop)."""

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
        candidates = get_provider_candidates(provider)
        last_error = None

        for index, candidate in enumerate(candidates):
            mailbox_service = build_mailbox_service(register_client, candidate)
            register_client._print(f"[{candidate}] 初始化邮箱服务...")
            try:
                mailbox = mailbox_service.create_mailbox()
                return mailbox_service, mailbox, candidate
            except Exception as error:
                last_error = error
                if index >= len(candidates) - 1:
                    raise
                next_provider = candidates[index + 1]
                register_client._print(f"[{candidate}] 创建邮箱失败: {error}")
                register_client._print(f"[fallback] 切换到 {next_provider}...")

        if last_error:
            raise last_error
        raise RuntimeError("未找到可用邮箱服务")

    def run(self) -> RegistrationResult:
        provider = legacy.MAIL_PROVIDER
        _email_on_failure = ""
        try:
            register_client = legacy.ChatGPTRegister(proxy=self.proxy, tag=f"{self.idx}")
            mailbox_service, mailbox, effective_provider = self._create_mailbox_with_fallback(
                register_client, provider
            )
            _email_on_failure = mailbox.email
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

            # ===== 使用 protocol_keygen 的纯 HTTP 注册流程 =====
            from protocol_keygen import (
                ProtocolRegistrar, create_session, perform_codex_oauth_login_http,
                save_tokens, save_account, create_temp_email,
            )

            registrar = ProtocolRegistrar()
            otp_fetcher = mailbox_service.wait_for_verification_code

            register_client._print("[Protocol] 步骤0: OAuth 初始化 + 邮箱提交")
            if not registrar.step0_init_oauth_session(mailbox.email):
                raise Exception("Protocol 步骤0 失败: OAuth 会话初始化失败")

            time.sleep(1)

            register_client._print("[Protocol] 步骤2: 注册用户")
            if not registrar.step2_register_user(mailbox.email, chatgpt_password):
                raise Exception("Protocol 步骤2 失败: 注册用户失败")

            time.sleep(1)

            register_client._print("[Protocol] 步骤3: 触发 OTP")
            registrar.step3_send_otp()

            register_client._print("[Protocol] 等待验证码...")
            otp_code = otp_fetcher(120)
            if not otp_code:
                raise Exception("未能获取验证码")

            register_client._print(f"[Protocol] 步骤4: 验证 OTP ({otp_code})")
            if not registrar.step4_validate_otp(otp_code):
                raise Exception("Protocol 步骤4 失败: OTP 验证失败")

            time.sleep(1)

            first_name, last_name = name.split(" ", 1) if " " in name else (name, "Smith")
            register_client._print("[Protocol] 步骤5: 创建账号（Playwright sentinel）")
            if not registrar.step5_create_account(first_name, last_name, birthdate):
                raise Exception("Protocol 步骤5 失败: 创建账号失败")

            register_client._print("[Protocol] 注册成功!")
            save_account(mailbox.email, chatgpt_password)

            oauth_ok = True
            if legacy.ENABLE_OAUTH:
                register_client._print("[OAuth] 开始获取 Codex Token...")
                time.sleep(5)
                tokens = perform_codex_oauth_login_http(
                    mailbox.email, chatgpt_password,
                    registrar_session=registrar.session,
                    cf_token=mailbox.token,
                )
                oauth_ok = bool(tokens and tokens.get("access_token"))
                if oauth_ok:
                    save_tokens(mailbox.email, tokens)
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
                email=_email_on_failure,
                error_message=str(error),
                error_code=_extract_error_code(str(error)),
            )
