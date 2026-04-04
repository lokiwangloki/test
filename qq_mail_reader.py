from __future__ import annotations

import argparse
import imaplib
import os
import re
import time
from dataclasses import dataclass, replace
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses
from html import unescape

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional local convenience only
    def load_dotenv(*args, **kwargs):
        return False


@dataclass(frozen=True)
class MailConfig:
    email: str
    auth_code: str
    imap_server: str
    imap_port: int
    target_to: str
    folder: str
    poll_interval_seconds: int
    poll_timeout_seconds: int


def load_config(require_target_to: bool = True) -> MailConfig:
    load_dotenv()

    email = os.getenv("QQ_EMAIL", "").strip()
    auth_code = os.getenv("QQ_AUTH_CODE", "").strip()
    target_to = os.getenv("TARGET_TO", "").strip()

    required_values = {"QQ_EMAIL": email, "QQ_AUTH_CODE": auth_code}
    if require_target_to:
        required_values["TARGET_TO"] = target_to

    missing = [name for name, value in required_values.items() if not value]
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

    return MailConfig(
        email=email,
        auth_code=auth_code,
        imap_server=os.getenv("QQ_IMAP_SERVER", "imap.qq.com").strip() or "imap.qq.com",
        imap_port=int(os.getenv("QQ_IMAP_PORT", "993")),
        target_to=target_to,
        folder=os.getenv("MAIL_FOLDER", "INBOX").strip() or "INBOX",
        poll_interval_seconds=int(os.getenv("POLL_INTERVAL_SECONDS", "5")),
        poll_timeout_seconds=int(os.getenv("POLL_TIMEOUT_SECONDS", "120")),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--to", dest="to", default=None)
    parser.add_argument("--full", action="store_true")
    return parser.parse_args(argv)


def apply_cli_overrides(config: MailConfig, args: argparse.Namespace) -> MailConfig:
    if args.to:
        return replace(config, target_to=args.to.strip())
    return config


def decode_mime_header(value: str | None) -> str:
    if not value:
        return ""
    return str(make_header(decode_header(value)))


def message_matches_target_to(message: Message, target_to: str) -> bool:
    normalized_target = target_to.strip().lower()
    addresses = getaddresses([message.get("To", "")])
    return any(address.strip().lower() == normalized_target for _, address in addresses)


def html_to_text(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html)
    text = unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_body_text(message: Message) -> str:
    if message.is_multipart():
        html_fallback = ""
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace").strip()
            if part.get_content_type() == "text/plain":
                return text
            if part.get_content_type() == "text/html" and not html_fallback:
                html_fallback = html_to_text(text)
        return html_fallback

    payload = message.get_payload(decode=True)
    if not payload:
        return ""
    charset = message.get_content_charset() or "utf-8"
    text = payload.decode(charset, errors="replace").strip()
    if message.get_content_type() == "text/html":
        return html_to_text(text)
    return text


def extract_verification_code(text: str) -> str | None:
    if not text:
        return None
    patterns = [
        r"Verification code:?\s*(\d{6})",
        r"code is\s*(\d{6})",
        r"验证码[:：]?\s*(\d{6})",
        r"代码[:：]?\s*(\d{6})",
        r"(?<![#&])\b(\d{6})\b",
    ]
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for code in matches:
            if code == "177010":
                continue
            return code
    return None


def fetch_unread_ids(client: imaplib.IMAP4_SSL) -> list[bytes]:
    status, data = client.search(None, "UNSEEN")
    if status != "OK":
        raise RuntimeError("Failed to search unread messages")
    return data[0].split() if data and data[0] else []


def fetch_message(client: imaplib.IMAP4_SSL, message_id: bytes) -> Message | None:
    status, data = client.fetch(message_id, "(RFC822)")
    if status != "OK" or not data or not data[0]:
        return None
    raw_message = data[0][1]
    if not isinstance(raw_message, bytes):
        return None
    return message_from_bytes(raw_message)


def mark_message_as_seen(client: imaplib.IMAP4_SSL, message_id: bytes) -> None:
    status, _ = client.store(message_id, "+FLAGS", "\\Seen")
    if status != "OK":
        raise RuntimeError(f"Failed to mark message {message_id.decode()} as read")


def format_message_output(message: Message) -> str:
    return (
        f"Subject: {decode_mime_header(message.get('Subject'))}\n"
        f"From: {decode_mime_header(message.get('From'))}\n"
        f"To: {decode_mime_header(message.get('To'))}\n"
        f"Date: {decode_mime_header(message.get('Date'))}\n\n"
        f"{extract_body_text(message)}"
    )


def process_latest_matching_unread_message(
    client: imaplib.IMAP4_SSL,
    target_to: str,
) -> str:
    unread_ids = fetch_unread_ids(client)
    for message_id in reversed(unread_ids):
        message = fetch_message(client, message_id)
        if message is None:
            continue
        if not message_matches_target_to(message, target_to):
            continue
        output = format_message_output(message)
        mark_message_as_seen(client, message_id)
        return output
    return f"No unread email found for To: {target_to}"


def poll_for_matching_unread_message(
    client: imaplib.IMAP4_SSL,
    target_to: str,
    poll_interval_seconds: int,
    poll_timeout_seconds: int,
    sleep_func=time.sleep,
    now_func=time.monotonic,
) -> str:
    deadline = now_func() + poll_timeout_seconds
    while True:
        output = process_latest_matching_unread_message(client, target_to)
        if not output.startswith("No unread email found for To: "):
            return output
        if now_func() >= deadline:
            return (
                f"No unread email found for To: {target_to} "
                f"within {poll_timeout_seconds} seconds"
            )
        sleep_func(poll_interval_seconds)


def poll_for_matching_verification_code(
    client: imaplib.IMAP4_SSL,
    target_to: str,
    poll_interval_seconds: int,
    poll_timeout_seconds: int,
    sleep_func=time.sleep,
    now_func=time.monotonic,
) -> str | None:
    deadline = now_func() + poll_timeout_seconds
    while True:
        unread_ids = fetch_unread_ids(client)
        for message_id in reversed(unread_ids):
            message = fetch_message(client, message_id)
            if message is None or not message_matches_target_to(message, target_to):
                continue
            text = extract_body_text(message)
            subject = decode_mime_header(message.get("Subject"))
            code = extract_verification_code(f"{subject}\n{text}")
            mark_message_as_seen(client, message_id)
            if code:
                return code
        if now_func() >= deadline:
            return None
        sleep_func(poll_interval_seconds)


def fetch_verification_code_for_recipient(
    target_to: str,
    *,
    poll_interval_seconds: int | None = None,
    poll_timeout_seconds: int | None = None,
) -> str | None:
    config = load_config(require_target_to=False)
    config = replace(
        config,
        target_to=target_to.strip(),
        poll_interval_seconds=poll_interval_seconds or config.poll_interval_seconds,
        poll_timeout_seconds=poll_timeout_seconds or config.poll_timeout_seconds,
    )
    with imaplib.IMAP4_SSL(config.imap_server, config.imap_port) as client:
        login_status, _ = client.login(config.email, config.auth_code)
        if login_status != "OK":
            raise RuntimeError("Failed to log in to QQ Mail IMAP")
        select_status, _ = client.select(config.folder)
        if select_status != "OK":
            raise RuntimeError(f"Failed to select folder: {config.folder}")
        return poll_for_matching_verification_code(
            client,
            config.target_to,
            poll_interval_seconds=config.poll_interval_seconds,
            poll_timeout_seconds=config.poll_timeout_seconds,
        )


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    config = apply_cli_overrides(load_config(require_target_to=args.to is None), args)
    with imaplib.IMAP4_SSL(config.imap_server, config.imap_port) as client:
        login_status, _ = client.login(config.email, config.auth_code)
        if login_status != "OK":
            raise RuntimeError("Failed to log in to QQ Mail IMAP")

        select_status, _ = client.select(config.folder)
        if select_status != "OK":
            raise RuntimeError(f"Failed to select folder: {config.folder}")

        if args.full:
            print(
                poll_for_matching_unread_message(
                    client,
                    config.target_to,
                    poll_interval_seconds=config.poll_interval_seconds,
                    poll_timeout_seconds=config.poll_timeout_seconds,
                )
            )
            return

        code = poll_for_matching_verification_code(
            client,
            config.target_to,
            poll_interval_seconds=config.poll_interval_seconds,
            poll_timeout_seconds=config.poll_timeout_seconds,
        )
        if not code:
            raise SystemExit(
                f"No verification code found for To: {config.target_to} "
                f"within {config.poll_timeout_seconds} seconds"
            )
        print(code)


if __name__ == "__main__":
    main()
