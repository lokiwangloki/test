import os
from dataclasses import dataclass
from typing import Optional

import ncs_register_legacy as legacy


@dataclass
class MailboxSession:
    email: str
    password: str
    token: str
    provider: str


class BaseMailboxService:
    provider: str = ""

    def __init__(self, register_client: "legacy.ChatGPTRegister"):
        self.register_client = register_client
        self._session: Optional[MailboxSession] = None

    @property
    def session(self) -> Optional[MailboxSession]:
        return self._session

    def create_mailbox(self) -> MailboxSession:
        raise NotImplementedError

    def wait_for_verification_code(self, timeout: int, stage: str = "otp") -> Optional[str]:
        if not self._session:
            return None
        return self.register_client.wait_for_verification_email(
            self._session.token,
            timeout=timeout,
            email=self._session.email,
            provider=self.provider,
            stage=stage,
        )


class TempmailLolMailboxService(BaseMailboxService):
    provider = "tempmail_lol"

    def create_mailbox(self) -> MailboxSession:
        email, password, token = self.register_client.create_tempmail_lol_email()
        self._session = MailboxSession(email=email, password=password, token=token, provider=self.provider)
        return self._session


class LaMailMailboxService(BaseMailboxService):
    provider = "lamail"

    def create_mailbox(self) -> MailboxSession:
        email, password, token = self.register_client.create_lamail_email()
        self._session = MailboxSession(email=email, password=password, token=token, provider=self.provider)
        return self._session


class CfmailMailboxService(BaseMailboxService):
    provider = "cfmail"

    def create_mailbox(self) -> MailboxSession:
        email, password, token = self.register_client.create_cfmail_email()
        self._session = MailboxSession(email=email, password=password, token=token, provider=self.provider)
        return self._session


class WildmailMailboxService(BaseMailboxService):
    provider = "wildmail"

    def create_mailbox(self) -> MailboxSession:
        email, password, token = self.register_client.create_wildmail_email()
        self._session = MailboxSession(email=email, password=password, token=token, provider=self.provider)
        return self._session


class DuckMailMailboxService(BaseMailboxService):
    provider = "duckmail"

    def create_mailbox(self) -> MailboxSession:
        email, password, token = self.register_client.create_duckmail_email()
        self._session = MailboxSession(email=email, password=password, token=token, provider=self.provider)
        return self._session


def should_fallback_to_lamail(error: Exception) -> bool:
    text = str(error or "").lower()
    if "tempmail" not in text:
        return False
    if "429" in text:
        return True
    return any(marker in text for marker in ("rate limit", "too many requests", "rate limited"))


def _split_provider_chain(raw: str) -> list[str]:
    return [
        item.strip().lower()
        for item in str(raw or "").split(",")
        if item.strip()
    ]


def _provider_is_configured(provider: str) -> bool:
    normalized = str(provider or "").strip().lower()
    if normalized == "duckmail":
        try:
            import get_duck
            return bool(get_duck.load_duck_addresses())
        except Exception:
            return False
    if normalized == "cfmail":
        if bool(getattr(legacy, "CFMAIL_ACCOUNTS", [])):
            return True
        worker_domain = getattr(legacy, "CFMAIL_WORKER_DOMAIN", "") or os.environ.get("CFMAIL_WORKER_DOMAIN", "")
        email_domain = getattr(legacy, "CFMAIL_EMAIL_DOMAIN", "") or os.environ.get("CFMAIL_EMAIL_DOMAIN", "")
        admin_password = getattr(legacy, "CFMAIL_ADMIN_PASSWORD", "") or os.environ.get("CFMAIL_ADMIN_PASSWORD", "")
        return bool(
            legacy._normalize_host(worker_domain)
            and legacy._normalize_host(email_domain)
            and str(admin_password or "").strip()
        )
    if normalized == "wildmail":
        return bool(str(getattr(legacy, "WILDMAIL_API_BASE", "") or "").strip())
    return normalized in {"tempmail_lol", "lamail"}


def get_provider_candidates(provider: str) -> list[str]:
    normalized = str(provider or "").strip().lower()
    configured_chain = _split_provider_chain(getattr(legacy, "MAIL_PROVIDER_CHAIN", ""))
    if configured_chain:
        raw_candidates = configured_chain
    elif normalized == "duckmail":
        raw_candidates = ["duckmail"]
    elif normalized == "cfmail":
        raw_candidates = ["cfmail"]
    elif normalized == "wildmail":
        raw_candidates = ["wildmail", "lamail", "tempmail_lol"]
    elif normalized == "lamail":
        raw_candidates = ["lamail", "tempmail_lol"]
    elif normalized == "tempmail_lol":
        raw_candidates = ["tempmail_lol"]
    else:
        raw_candidates = [normalized]

    candidates: list[str] = []
    for item in raw_candidates:
        if item in {"duckmail", "cfmail", "tempmail_lol", "lamail", "wildmail"} and item not in candidates and _provider_is_configured(item):
            candidates.append(item)

    if not candidates:
        return [normalized]
    return candidates


def build_mailbox_service(register_client: "legacy.ChatGPTRegister", provider: str) -> BaseMailboxService:
    normalized = str(provider or "").strip().lower()
    if normalized == "duckmail":
        return DuckMailMailboxService(register_client)
    if normalized == "cfmail":
        return CfmailMailboxService(register_client)
    if normalized == "tempmail_lol":
        return TempmailLolMailboxService(register_client)
    if normalized == "lamail":
        return LaMailMailboxService(register_client)
    if normalized == "wildmail":
        return WildmailMailboxService(register_client)
    raise ValueError(f"不支持的 mail_provider={provider}，当前仅支持 duckmail / cfmail / tempmail_lol / lamail / wildmail")
