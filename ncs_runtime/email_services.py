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

    def wait_for_verification_code(self, timeout: int) -> Optional[str]:
        if not self._session:
            return None
        return self.register_client.wait_for_verification_email(
            self._session.token,
            timeout=timeout,
            email=self._session.email,
            provider=self.provider,
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


class WildmailMailboxService(BaseMailboxService):
    provider = "wildmail"

    def create_mailbox(self) -> MailboxSession:
        email, password, token = self.register_client.create_wildmail_email()
        self._session = MailboxSession(email=email, password=password, token=token, provider=self.provider)
        return self._session


def should_fallback_to_lamail(error: Exception) -> bool:
    text = str(error or "").lower()
    if "tempmail" not in text:
        return False
    if "429" in text:
        return True
    return any(marker in text for marker in ("rate limit", "too many requests", "rate limited"))


def build_mailbox_service(register_client: "legacy.ChatGPTRegister", provider: str) -> BaseMailboxService:
    normalized = str(provider or "").strip().lower()
    if normalized == "tempmail_lol":
        return TempmailLolMailboxService(register_client)
    if normalized == "lamail":
        return LaMailMailboxService(register_client)
    if normalized == "wildmail":
        return WildmailMailboxService(register_client)
    raise ValueError(f"不支持的 mail_provider={provider}，当前仅支持 tempmail_lol / lamail / wildmail")
