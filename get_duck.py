from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path

DEFAULT_API_URL = "https://quack.duckduckgo.com/api/email/addresses"
DEFAULT_STOP_COUNT = 3
DEFAULT_DELAY = 0.5
_POOL_LOCK = threading.Lock()
_LOG_PREFIX = ""


def set_duck_log_prefix(prefix: str = "") -> None:
    global _LOG_PREFIX
    _LOG_PREFIX = str(prefix or "")


def _duck_log(message: str) -> None:
    prefix = str(_LOG_PREFIX or "")
    if prefix:
        print(f"{prefix}{message}")
    else:
        print(message)


def _repo_default_output_file() -> Path:
    return Path(__file__).resolve().with_name("duckaddress.txt")


def resolve_output_file(output_file: str | None = None) -> Path:
    if output_file:
        return Path(output_file).expanduser()

    env_file = os.environ.get("DUCK_ADDRESS_FILE", "").strip()
    if env_file:
        return Path(env_file).expanduser()

    candidates: list[Path] = []
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


def _state_file(address_file: str | None = None) -> Path:
    path = resolve_output_file(address_file)
    return path.with_name("duck_state.json")


def load_duck_state(address_file: str | None = None) -> dict:
    path = _state_file(address_file)
    if not path.exists():
        return {"bearers": {}, "recent_api_addresses": {}, "active_bearer_index": 0}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"bearers": {}, "recent_api_addresses": {}, "active_bearer_index": 0}
    if not isinstance(data, dict):
        return {"bearers": {}, "recent_api_addresses": {}, "active_bearer_index": 0}
    bearers = data.get("bearers") if isinstance(data.get("bearers"), dict) else {}
    recent = data.get("recent_api_addresses") if isinstance(data.get("recent_api_addresses"), dict) else {}
    active_index = int(data.get("active_bearer_index") or 0)
    return {"bearers": bearers, "recent_api_addresses": recent, "active_bearer_index": active_index}


def save_duck_state(state: dict, address_file: str | None = None) -> None:
    payload = {
        "bearers": state.get("bearers") if isinstance(state.get("bearers"), dict) else {},
        "recent_api_addresses": state.get("recent_api_addresses") if isinstance(state.get("recent_api_addresses"), dict) else {},
        "active_bearer_index": int(state.get("active_bearer_index") or 0),
    }
    path = _state_file(address_file)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _bearer_state_key(bearer: str) -> str:
    return hashlib.sha256(str(bearer or "").encode("utf-8")).hexdigest()


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


def ensure_duck_address_available(
    address_file: str | None = None,
    *,
    refill_attempts: int = 3,
    stop_count: int = 1,
    delay_seconds: float = 0,
) -> str:
    last_error: Exception | None = None
    attempts = max(1, int(refill_attempts or 1))

    with _POOL_LOCK:
        for attempt in range(1, attempts + 1):
            addresses = load_duck_addresses(address_file)
            if addresses:
                chosen = addresses[0]
                _write_duck_addresses(addresses[1:], address_file)
                state = load_duck_state(address_file)
                recent = state.get("recent_api_addresses") or {}
                if isinstance(recent, dict):
                    recent[str(chosen).strip().lower()] = time.strftime("%Y-%m-%dT%H:%M:%S")
                    state["recent_api_addresses"] = recent
                    save_duck_state(state, address_file)
                return chosen

            try:
                added = fetch_duck_addresses(
                    output_file=address_file,
                    stop_count=stop_count,
                    delay_seconds=delay_seconds,
                )
            except Exception as exc:
                last_error = exc
                added = []
            if added:
                addresses = load_duck_addresses(address_file)
                if addresses:
                    chosen = addresses[0]
                    _write_duck_addresses(addresses[1:], address_file)
                    state = load_duck_state(address_file)
                    recent = state.get("recent_api_addresses") or {}
                    if isinstance(recent, dict):
                        recent[str(chosen).strip().lower()] = time.strftime("%Y-%m-%dT%H:%M:%S")
                        state["recent_api_addresses"] = recent
                        save_duck_state(state, address_file)
                    return chosen
            if attempt < attempts:
                _duck_log(f"[duckmail] 地址池为空，第 {attempt}/{attempts} 次补充失败，重试中...")

    if last_error is not None:
        raise RuntimeError(f"duckaddress.txt 中没有可用的 duck 邮箱（已重试 {attempts} 次）") from last_error
    raise RuntimeError(f"duckaddress.txt 中没有可用的 duck 邮箱（已重试 {attempts} 次）")


def remove_duck_addresses(addresses: list[str] | tuple[str, ...] | set[str], address_file: str | None = None) -> int:
    normalized = {
        str(item or "").strip().lower()
        for item in addresses
        if str(item or "").strip()
    }
    if not normalized:
        return 0

    with _POOL_LOCK:
        existing = load_duck_addresses(address_file)
        if not existing:
            return 0
        filtered = [item for item in existing if item.strip().lower() not in normalized]
        removed = len(existing) - len(filtered)
        state = load_duck_state(address_file)
        recent = state.get("recent_api_addresses") or {}
        if isinstance(recent, dict):
            for item in normalized:
                recent[item] = time.strftime("%Y-%m-%dT%H:%M:%S")
            state["recent_api_addresses"] = recent
        if removed > 0:
            _write_duck_addresses(filtered, address_file)
        save_duck_state(state, address_file)
        return removed


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


def _parse_duck_bearer_list(raw: str | None) -> list[str]:
    text = str(raw or "").strip()
    if not text:
        return []

    if text.startswith("["):
        try:
            data = json.loads(text)
        except Exception:
            data = None
        if isinstance(data, list):
            return [str(item).strip() for item in data if str(item).strip()]

    parts = re.split(r"[\r\n,]+", text)
    normalized = [part.strip().strip("\"'") for part in parts if part.strip()]
    if normalized:
        return normalized
    return [text]


def load_duck_bearers(bearer: str | list[str] | tuple[str, ...] | None = None) -> list[str]:
    if isinstance(bearer, (list, tuple)):
        return [str(item).strip() for item in bearer if str(item).strip()]

    explicit = _parse_duck_bearer_list(bearer)
    if explicit:
        return explicit

    multi_env = _parse_duck_bearer_list(os.environ.get("DUCK_EMAIL_BEARERS", ""))
    if multi_env:
        return multi_env

    return _parse_duck_bearer_list(os.environ.get("DUCK_EMAIL_BEARER", ""))


def _collect_duck_addresses_with_bearer(
    curl_requests,
    *,
    bearer: str,
    api_url: str,
    stop_count: int,
    delay_seconds: float,
) -> tuple[list[str], int]:
    all_addresses: list[str] = []
    last_address = ""
    same_count = 0

    while True:
        response = curl_requests.post(
            api_url,
            headers=_duck_headers(bearer),
            timeout=10,
            impersonate="chrome",
        )
        response.raise_for_status()
        data = response.json()
        current_address = str(data.get("address") or "").strip()
        if not current_address:
            _duck_log("[!] 未获取到地址，跳过")
            time.sleep(delay_seconds)
            continue

        full_address = f"{current_address}@duck.com"
        _duck_log(f"[+] 获取到：{full_address}")
        all_addresses.append(full_address)

        if current_address == last_address:
            same_count += 1
        else:
            same_count = 1
            last_address = current_address

        _duck_log(f"ℹ️ 连续相同次数：{same_count}/{stop_count}")
        if same_count >= stop_count:
            return all_addresses, same_count
        time.sleep(delay_seconds)


def fetch_duck_addresses(
    *,
    output_file: str | None = None,
    bearer: str | list[str] | tuple[str, ...] | None = None,
    api_url: str | None = None,
    stop_count: int = DEFAULT_STOP_COUNT,
    delay_seconds: float = DEFAULT_DELAY,
) -> list[str]:
    from curl_cffi import requests as curl_requests

    bearers = load_duck_bearers(bearer)
    if not bearers:
        raise RuntimeError("DUCK_EMAIL_BEARERS / DUCK_EMAIL_BEARER 未设置，无法生成 duck 邮箱池")

    url = str(api_url or os.environ.get("DUCK_EMAIL_API_URL", DEFAULT_API_URL)).strip() or DEFAULT_API_URL
    existing_addresses = set(load_duck_addresses(output_file))
    state = load_duck_state(output_file)
    recent_api_addresses = state.get("recent_api_addresses") if isinstance(state.get("recent_api_addresses"), dict) else {}
    bearer_states = state.get("bearers") if isinstance(state.get("bearers"), dict) else {}
    active_index = int(state.get("active_bearer_index") or 0) if isinstance(state, dict) else 0
    if bearers:
        active_index %= len(bearers)
    to_add: list[str] = []
    seen = set(existing_addresses)
    last_error: Exception | None = None

    _duck_log("=== 开始自动获取 DuckDuckGo 邮箱地址（追加模式）===")

    ordered_indexes = list(range(active_index, len(bearers))) + list(range(0, active_index))
    for index in ordered_indexes:
        token = bearers[index]
        token_key = _bearer_state_key(token)
        bearer_state = bearer_states.get(token_key) if isinstance(bearer_states.get(token_key), dict) else {}
        try:
            candidates, same_count = _collect_duck_addresses_with_bearer(
                curl_requests,
                bearer=token,
                api_url=url,
                stop_count=stop_count,
                delay_seconds=delay_seconds,
            )
        except Exception as exc:
            last_error = exc
            _duck_log(f"[!] Duck bearer {index + 1}/{len(bearers)} 获取失败: {exc}")
            state["active_bearer_index"] = (index + 1) % len(bearers)
            continue

        accepted = False
        for item in candidates:
            normalized = item.strip().lower()
            bearer_state["last_seen"] = normalized
            if normalized in recent_api_addresses:
                _duck_log(f"[duckmail] 跳过近期已用地址: {item}")
                continue
            if item in seen:
                _duck_log(f"[duckmail] 跳过池内已存在地址: {item}")
                continue
            to_add.append(item)
            seen.add(item)
            bearer_state["last_accepted"] = normalized
            recent_api_addresses[normalized] = time.strftime("%Y-%m-%dT%H:%M:%S")
            accepted = True
            state["active_bearer_index"] = index
            break

        bearer_states[token_key] = bearer_state
        if accepted:
            if same_count >= stop_count:
                state["active_bearer_index"] = (index + 1) % len(bearers)
                _duck_log(f"[duckmail] 当前 bearer 连续重复 {same_count} 次，切换到下一个 bearer")
            break
        if same_count >= stop_count:
            state["active_bearer_index"] = (index + 1) % len(bearers)
            _duck_log(f"[duckmail] 当前 bearer 连续重复 {same_count} 次，切换到下一个 bearer")
            continue

    if not to_add and last_error is not None:
        raise RuntimeError(f"所有 Duck bearer 均不可用，已尝试 {len(bearers)} 个: {last_error}")

    state["bearers"] = bearer_states
    state["recent_api_addresses"] = recent_api_addresses
    state["active_bearer_index"] = int(state.get("active_bearer_index") or 0)
    save_duck_state(state, output_file)

    if to_add:
        path = resolve_output_file(output_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(to_add) + "\n")

    _duck_log("\n==================== 完成 ====================")
    _duck_log(f"本次新增：{len(to_add)} 个")
    _duck_log(f"文件总共有：{len(existing_addresses) + len(to_add)} 个")
    _duck_log(f"已安全追加到：{resolve_output_file(output_file)} ✅")
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
