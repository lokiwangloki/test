from __future__ import annotations

import argparse
import os
import threading
import time
from pathlib import Path

DEFAULT_API_URL = "https://quack.duckduckgo.com/api/email/addresses"
DEFAULT_STOP_COUNT = 3
DEFAULT_DELAY = 0.5
_POOL_LOCK = threading.Lock()


def _repo_default_output_file() -> Path:
    return Path(__file__).resolve().with_name("duckaddress.txt")


def resolve_output_file(output_file: str | None = None) -> Path:
    candidates: list[Path] = []
    if output_file:
        candidates.append(Path(output_file).expanduser())

    env_file = os.environ.get("DUCK_ADDRESS_FILE", "").strip()
    if env_file:
        candidates.append(Path(env_file).expanduser())

    repo_file = _repo_default_output_file()
    candidates.append(repo_file)

    desktop_file = Path("/Users/LokiTina/Desktop/getemail/duckaddress.txt")
    if desktop_file not in candidates:
        candidates.append(desktop_file)

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return repo_file


def load_duck_addresses(address_file: str | None = None) -> list[str]:
    path = resolve_output_file(address_file)
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().lower().endswith("@duck.com")
    ]


def _write_duck_addresses(addresses: list[str], address_file: str | None = None) -> Path:
    path = resolve_output_file(address_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(addresses)
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")
    return path


def take_duck_address(address_file: str | None = None) -> str:
    with _POOL_LOCK:
        addresses = load_duck_addresses(address_file)
        if not addresses:
            raise RuntimeError("duckaddress.txt 中没有可用的 duck 邮箱")
        chosen = addresses[0]
        _write_duck_addresses(addresses[1:], address_file)
        return chosen


def _duck_headers(bearer: str) -> dict[str, str]:
    return {
        "Accept": "*/*",
        "Authorization": f"Bearer {bearer}",
        "Sec-Fetch-Site": "same-site",
        "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Mode": "cors",
        "Host": "quack.duckduckgo.com",
        "Origin": "https://duckduckgo.com",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/26.3.1 Safari/605.1.15 Ddg/26.3.1"
        ),
        "Referer": "https://duckduckgo.com/",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Priority": "u=3, i",
        "Content-Length": "0",
    }


def fetch_duck_addresses(
    *,
    output_file: str | None = None,
    bearer: str | None = None,
    api_url: str | None = None,
    stop_count: int = DEFAULT_STOP_COUNT,
    delay_seconds: float = DEFAULT_DELAY,
) -> list[str]:
    from curl_cffi import requests as curl_requests

    token = str(bearer or os.environ.get("DUCK_EMAIL_BEARER", "")).strip()
    if not token:
        raise RuntimeError("DUCK_EMAIL_BEARER 未设置，无法生成 duck 邮箱池")

    url = str(api_url or os.environ.get("DUCK_EMAIL_API_URL", DEFAULT_API_URL)).strip() or DEFAULT_API_URL
    existing_addresses = set(load_duck_addresses(output_file))
    all_addresses: list[str] = []
    last_address = ""
    same_count = 0

    print("=== 开始自动获取 DuckDuckGo 邮箱地址（追加模式）===")
    while True:
        response = curl_requests.post(
            url,
            headers=_duck_headers(token),
            timeout=10,
            impersonate="chrome",
        )
        response.raise_for_status()
        data = response.json()
        current_address = str(data.get("address") or "").strip()
        if not current_address:
            print("[!] 未获取到地址，跳过")
            time.sleep(delay_seconds)
            continue

        full_address = f"{current_address}@duck.com"
        print(f"[+] 获取到：{full_address}")
        all_addresses.append(full_address)

        if current_address == last_address:
            same_count += 1
        else:
            same_count = 1
            last_address = current_address

        print(f"ℹ️ 连续相同次数：{same_count}/{stop_count}")
        if same_count >= stop_count:
            break
        time.sleep(delay_seconds)

    seen = set(existing_addresses)
    to_add: list[str] = []
    for item in all_addresses:
        if item not in seen:
            to_add.append(item)
            seen.add(item)

    if to_add:
        path = resolve_output_file(output_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(to_add) + "\n")

    print("\n==================== 完成 ====================")
    print(f"本次新增：{len(to_add)} 个")
    print(f"文件总共有：{len(existing_addresses) + len(to_add)} 个")
    print(f"已安全追加到：{resolve_output_file(output_file)} ✅")
    return to_add


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=None)
    parser.add_argument("--stop-count", type=int, default=DEFAULT_STOP_COUNT)
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    fetch_duck_addresses(
        output_file=args.output,
        stop_count=max(1, int(args.stop_count)),
        delay_seconds=max(0.0, float(args.delay)),
    )


if __name__ == "__main__":
    main()
