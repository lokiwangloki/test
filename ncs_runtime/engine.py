import io
import re
import time
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from typing import Optional

import ncs_register_legacy as legacy

from .email_services import build_mailbox_service, get_provider_candidates


_KNOWN_ERROR_CODES = frozenset({
    "registration_disallowed",
    "unsupported_email",
    "user_already_exists",
})

_FAILURE_REASON_MARKERS = (
    "❌",
    "失败",
    "错误",
    "exception",
    "traceback",
    "timeout",
    "超时",
    "未能",
    "未获取",
    "missing",
)
_DIAGNOSTIC_REASON_MARKERS = (
    "warning_banner",
    "add-phone",
    "session endpoint",
    "未能直接获取 token",
    "回退 fresh login",
    "未获得 login_session",
    "login_session: ❌",
    "login_session: n",
)
_GENERIC_FAILURE_FRAGMENTS = (
    "oauth token 获取失败",
    "oauth 授权失败",
    "注册失败",
    "获取失败",
    "未知错误",
    "重试次数耗尽",
)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _extract_error_code(message: str) -> str:
    msg = str(message or "").lower()
    for code in _KNOWN_ERROR_CODES:
        if code in msg:
            return code
    return ""


def _sanitize_log_line(line: str) -> str:
    text = _ANSI_ESCAPE_RE.sub("", str(line or "")).strip()
    if not text:
        return ""
    if text.startswith("进度:"):
        return ""
    if set(text) <= {"=", "#", "-", " "}:
        return ""
    return text


def _is_reason_candidate(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in _FAILURE_REASON_MARKERS) or any(
        marker in lowered for marker in _DIAGNOSTIC_REASON_MARKERS
    )


def _score_reason_candidate(line: str) -> int:
    lowered = line.lower()
    score = 0
    if any(marker in lowered for marker in _FAILURE_REASON_MARKERS):
        score += 40
    if any(marker in lowered for marker in _DIAGNOSTIC_REASON_MARKERS):
        score += 25
    if ":" in line or "：" in line:
        score += 8
    if re.search(r"\b\d{3}\b", line):
        score += 5
    if "http" in lowered or "https" in lowered:
        score += 4
    if any(fragment in lowered for fragment in _GENERIC_FAILURE_FRAGMENTS):
        score -= 20
    if "重试次数耗尽" in lowered:
        score -= 10
    score += min(len(line), 120) // 24
    return score


def _extract_stage_failure_reason(output: str, fallback: str = "") -> str:
    candidates: list[str] = []
    for raw_line in str(output or "").splitlines():
        line = _sanitize_log_line(raw_line)
        if not line:
            continue
        if _is_reason_candidate(line):
            candidates.append(line)

    if candidates:
        chosen = max(
            enumerate(candidates),
            key=lambda item: (_score_reason_candidate(item[1]), item[0]),
        )[1]
    else:
        chosen = _sanitize_log_line(fallback)
    chosen = chosen or str(fallback or "").strip() or "未知错误"
    chosen = re.sub(r"^\[[^\]]+\]\s*", "", chosen).strip()
    chosen = re.sub(r"^[❌⚠️]+\s*", "", chosen).strip()
    return chosen or "未知错误"


@contextmanager
def _capture_stage_output():
    buffer = io.StringIO()
    with redirect_stdout(buffer), redirect_stderr(buffer):
        yield buffer


def _print_stage_status(tag: str, stage: str, ok: bool, success_text: str, failure_text: str, reason: str = "") -> None:
    prefix = f"[{tag}] " if tag else ""
    if ok:
        message = f"{prefix}[{stage}] ✅{success_text}"
    else:
        detail = f": {reason}" if reason else ""
        message = f"{prefix}[{stage}] ❌{failure_text}{detail}"
    with legacy._print_lock:
        print(message)


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
            try:
                mailbox = mailbox_service.create_mailbox()
                return mailbox_service, mailbox, candidate
            except Exception as error:
                last_error = error
                if index >= len(candidates) - 1:
                    raise

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
            account_tag = register_client.tag or str(self.idx)

            chatgpt_password = legacy._generate_password()
            name = legacy._random_name()
            birthdate = legacy._random_birthdate()

            # ===== 使用 protocol_keygen 的纯 HTTP 注册流程 =====
            from protocol_keygen import (
                ProtocolRegistrar, create_session, perform_codex_oauth_login_http,
                save_tokens, save_account, create_temp_email, PROXY,
            )
            from sentinel_browser import get_all_sentinel_tokens

            otp_fetcher = mailbox_service.wait_for_verification_code
            registration_output = io.StringIO()
            try:
                with _capture_stage_output() as registration_output:
                    browser_tokens = get_all_sentinel_tokens(
                        proxy=PROXY if PROXY else None,
                    )
                    registrar = ProtocolRegistrar(browser_tokens=browser_tokens)

                    if not registrar.step0_init_oauth_session(mailbox.email):
                        raise Exception("OAuth 会话初始化失败")

                    time.sleep(1)

                    if not registrar.step2_register_user(mailbox.email, chatgpt_password):
                        raise Exception("注册用户失败")

                    time.sleep(1)

                    registrar.step3_send_otp()

                    otp_code = otp_fetcher(120)
                    if not otp_code:
                        raise Exception("未能获取验证码")

                    if not registrar.step4_validate_otp(otp_code):
                        raise Exception("OTP 验证失败")

                    time.sleep(1)

                    first_name, last_name = name.split(" ", 1) if " " in name else (name, "Smith")
                    if not registrar.step5_create_account(first_name, last_name, birthdate):
                        raise Exception("创建账号失败")

                    save_account(mailbox.email, chatgpt_password)
            except Exception as error:
                reason = _extract_stage_failure_reason(registration_output.getvalue(), str(error))
                _print_stage_status(account_tag, "仅注册", False, "注册成功", "注册失败", reason)
                return RegistrationResult(
                    idx=self.idx,
                    success=False,
                    provider=provider,
                    email=_email_on_failure,
                    error_message=reason,
                    error_code=_extract_error_code(reason),
                )

            _print_stage_status(account_tag, "仅注册", True, "注册成功", "注册失败")

            oauth_ok = True
            if legacy.ENABLE_OAUTH:
                oauth_output = io.StringIO()
                tokens = None
                try:
                    with _capture_stage_output() as oauth_output:
                        time.sleep(5)
                        tokens = perform_codex_oauth_login_http(
                            mailbox.email, chatgpt_password,
                            registrar_session=registrar.session,
                            cf_token=mailbox.token,
                        )
                    oauth_ok = bool(tokens and tokens.get("access_token"))
                except Exception as error:
                    reason = _extract_stage_failure_reason(oauth_output.getvalue(), str(error))
                    _print_stage_status(account_tag, "Oauth获取token", False, "获取Token成功", "获取失败", reason)
                    if legacy.OAUTH_REQUIRED:
                        return RegistrationResult(
                            idx=self.idx,
                            success=False,
                            provider=effective_provider,
                            email=mailbox.email,
                            email_password=mailbox.password,
                            error_message=f"OAuth Token 获取失败: {reason}",
                            error_code=_extract_error_code(reason),
                        )
                    oauth_ok = False
                else:
                    if oauth_ok:
                        save_tokens(mailbox.email, tokens)
                        legacy._save_codex_tokens(mailbox.email, tokens)
                        _print_stage_status(account_tag, "Oauth获取token", True, "获取Token成功", "获取失败")
                    else:
                        reason = _extract_stage_failure_reason(oauth_output.getvalue(), "OAuth Token 获取失败")
                        _print_stage_status(account_tag, "Oauth获取token", False, "获取Token成功", "获取失败", reason)
                        if legacy.OAUTH_REQUIRED:
                            return RegistrationResult(
                                idx=self.idx,
                                success=False,
                                provider=effective_provider,
                                email=mailbox.email,
                                email_password=mailbox.password,
                                error_message=f"OAuth Token 获取失败: {reason}",
                                error_code=_extract_error_code(reason),
                            )

            self._append_result(mailbox, chatgpt_password, oauth_ok)

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
            reason = _extract_stage_failure_reason("", str(error))
            _print_stage_status(str(self.idx), "仅注册", False, "注册成功", "注册失败", reason)
            return RegistrationResult(
                idx=self.idx,
                success=False,
                provider=provider,
                email=_email_on_failure,
                error_message=reason,
                error_code=_extract_error_code(reason),
            )
