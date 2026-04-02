import json
import os
import secrets
import sys
from typing import Any

from curl_cffi import requests as curl_requests


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"[wildmail] 缺少环境变量: {name}")
    return value


def _expect_status(resp: Any, expected: int, action: str) -> None:
    if resp.status_code != expected:
        body = resp.text[:1000]
        raise SystemExit(
            f"[wildmail] {action} 失败: status={resp.status_code}, expected={expected}, body={body}"
        )


def main() -> int:
    base = _require_env("WILDMAIL_API_BASE").rstrip("/")
    api_key = _require_env("WILDMAIL_API_KEY")

    session = curl_requests.Session()
    session.headers.update({"user-agent": "wildmail-diagnose/1.0"})

    print(f"[wildmail] base={base}")

    health = session.get(f"{base}/health_check", timeout=20)
    _expect_status(health, 200, "health_check")
    print(f"[wildmail] health_check=200 body={health.text[:128]}")

    mailbox_payload = {
        "localPart": f"diag{secrets.token_hex(3)}",
        "subdomain": f"job{secrets.token_hex(3)}",
    }
    create_resp = session.post(
        f"{base}/open_api/wildmail/new",
        headers={"x-api-key": api_key, "content-type": "application/json"},
        data=json.dumps(mailbox_payload),
        timeout=20,
    )
    _expect_status(create_resp, 200, "create mailbox")
    create_data = create_resp.json()
    address = str(create_data["address"])
    token = str(create_data["token"])
    print(f"[wildmail] create=200 address={address}")

    webhook_resp = session.post(
        f"{base}/open_api/wildmail/webhooks/mailgun",
        data={
            "recipient": address,
            "sender": "diag@example.net",
            "subject": "Wildmail workflow diagnose",
            "body-plain": "workflow-end-to-end-ok",
            "message-id": f"<diag-{secrets.token_hex(6)}@example.net>",
        },
        timeout=20,
    )
    _expect_status(webhook_resp, 200, "inject webhook")
    print(f"[wildmail] webhook=200 body={webhook_resp.text[:128]}")

    messages_resp = session.get(
        f"{base}/open_api/wildmail/messages",
        params={"token": token},
        timeout=20,
    )
    _expect_status(messages_resp, 200, "list messages")
    messages_data = messages_resp.json()
    messages = messages_data.get("messages") or []
    if not messages:
        raise SystemExit("[wildmail] 读取消息失败: messages 为空")

    latest = messages[0]
    subject = str(latest.get("subject") or "")
    text = str(latest.get("text") or "")
    if "Wildmail workflow diagnose" not in subject or "workflow-end-to-end-ok" not in text:
        raise SystemExit(
            f"[wildmail] 消息内容不匹配: subject={subject!r}, text={text[:200]!r}"
        )

    print(f"[wildmail] messages=200 count={len(messages)} subject={subject}")
    print("[wildmail] diagnose=ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
