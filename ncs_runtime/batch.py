from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import io
import os
import re
import threading
import time
from contextlib import redirect_stderr, redirect_stdout

import ncs_register_legacy as legacy

from .engine import RegistrationEngine, _extract_stage_failure_reason

_MAX_CONSECUTIVE_FAILURES = 30
_CPA_UPLOAD_RESULT_RE = re.compile(r"上传完成:\s*成功\s*(\d+)\s*个,\s*失败\s*(\d+)\s*个")
_DUCK_POOL_EMPTY_MARKER = "duck 邮箱地址池不可用"


def _cfmail_active_domain_target() -> int:
    raw = str(os.getenv("ZHUCE6_CFMAIL_ACTIVE_DOMAIN_COUNT", "3") or "3").strip()
    try:
        return max(1, int(raw or "3"))
    except Exception:
        return 3


def run_single(idx: int, total: int, proxy: str, output_file: str, mailbox_email: str = ""):
    result = RegistrationEngine(idx=idx, total=total, proxy=proxy, output_file=output_file, mailbox_email=mailbox_email).run()
    return result.success, result.email or None, result.error_code or "", result.error_message or None


def _active_cfmail_accounts_for_domains(active_domains: list[str]) -> list:
    active_domain_set = {
        str(domain or "").strip().lower()
        for domain in active_domains
        if str(domain or "").strip()
    }
    if not active_domain_set:
        return []
    return [
        account for account in legacy.CFMAIL_ACCOUNTS
        if str(getattr(account, "email_domain", "") or "").strip().lower() in active_domain_set
    ]


def _sync_cfmail_accounts_with_env_credentials(provisioner) -> bool:
    worker_domain = legacy._normalize_host(legacy.CFMAIL_WORKER_DOMAIN)
    admin_password = str(legacy.CFMAIL_ADMIN_PASSWORD or "").strip()
    if not worker_domain or not admin_password:
        return False

    accounts = provisioner._load_all_accounts()
    changed = False
    normalized_accounts = []
    for item in accounts:
        if not isinstance(item, dict):
            continue
        updated = dict(item)
        if legacy._normalize_host(updated.get("worker_domain", "")) != worker_domain:
            updated["worker_domain"] = worker_domain
            changed = True
        if str(updated.get("admin_password") or "").strip() != admin_password:
            updated["admin_password"] = admin_password
            changed = True
        normalized_accounts.append(updated)

    if changed:
        provisioner._write_accounts(normalized_accounts)
    return changed


def _run_cpa_upload_with_compact_log() -> tuple[int, int, str]:
    buffer = io.StringIO()
    with redirect_stdout(buffer), redirect_stderr(buffer):
        legacy._upload_all_tokens_to_cpa()

    output = buffer.getvalue()
    match = _CPA_UPLOAD_RESULT_RE.search(output)
    if match:
        uploaded = int(match.group(1))
        failed = int(match.group(2))
        if failed == 0 and uploaded > 0:
            return uploaded, failed, ""
        reason = f"成功 {uploaded} 个, 失败 {failed} 个"
        return uploaded, failed, reason

    reason = _extract_stage_failure_reason(output, "未找到可上传 token")
    return 0, 0, reason


def _log_batch_status(success_count: int, fail_count: int, *, pool_count: int | None = None) -> None:
    if pool_count is not None:
        print(f"[email] 当前 Email 池内数量：{pool_count}")
    print(f"[account] 已成功：{success_count}  已失败：{fail_count}")


def _is_duck_pool_exhausted(error_message: str) -> bool:
    return _DUCK_POOL_EMPTY_MARKER in str(error_message or "")


def _produce_duck_addresses_until_exhausted(
    *,
    stop_count: int = 2,
    delay_seconds: float = 0,
) -> tuple[int, str | None]:
    import get_duck

    produced = 0
    last_error: str | None = None
    while True:
        try:
            get_duck.produce_one_duck_address(
                stop_count=stop_count,
                delay_seconds=delay_seconds,
            )
            produced += 1
        except Exception as error:
            last_error = str(error)
            with legacy._print_lock:
                print(f"[duckmail] 生产者停止: {last_error}")
            break
    return produced, last_error


def run_batch(total_accounts: int = 3, output_file: str = "registered_accounts.txt",
              max_workers: int = 3, proxy: str = None, cpa_cleanup=None,
              cpa_upload_every_n: int = 1):
    provider = legacy.MAIL_PROVIDER
    if provider == "cfmail" and not legacy.CFMAIL_ACCOUNTS:
        print("❌ 错误: mail_provider=cfmail 但未找到可用的 cfmail 配置")
        print(f"   请检查配置文件: {legacy._CFMAIL_CONFIG_PATH}")
        print("   或配置环境变量: CFMAIL_WORKER_DOMAIN / CFMAIL_EMAIL_DOMAIN / CFMAIL_ADMIN_PASSWORD")
        return False
    if provider not in legacy.SUPPORTED_MAIL_PROVIDERS:
        print(f"❌ 错误: 不支持的 mail_provider={provider}")
        print("   可选值: cfmail / lamail / tempmail_lol / wildmail")
        return False

    actual_workers = min(max_workers, total_accounts)
    duckmail_mode = provider == "duckmail"
    if duckmail_mode:
        actual_workers = min(actual_workers, 5)
    print(f"\n{'#' * 60}")
    print("  ChatGPT 批量自动注册")
    print(f"  注册数量: {total_accounts} | 并发数: {actual_workers}")
    print(f"  批量模式: {legacy.BATCH_MODE}")
    print(f"  邮箱服务: {provider}")
    if provider == "cfmail":
        cfmail_names = ", ".join(account.name for account in legacy.CFMAIL_ACCOUNTS)
        print(f"  cfmail 配置: {cfmail_names}")
        print(f"  cfmail 模式: {legacy.CFMAIL_PROFILE_MODE}")
    elif provider == "tempmail_lol":
        print(f"  TempMail.lol: {legacy.TEMPMAIL_LOL_API_BASE}")
    elif provider == "lamail":
        print(f"  LaMail: {legacy.LAMAIL_API_BASE}")
        if legacy.LAMAIL_DOMAIN:
            print(f"  LaMail 域名: {legacy.LAMAIL_DOMAIN}")
    elif provider == "wildmail":
        print(f"  Wildmail: {legacy.WILDMAIL_API_BASE}")
    print(f"  OAuth: {'开启' if legacy.ENABLE_OAUTH else '关闭'} | required: {'是' if legacy.OAUTH_REQUIRED else '否'}")
    if legacy.ENABLE_OAUTH:
        print(f"  Token输出: {legacy.TOKEN_JSON_DIR}/, {legacy.AK_FILE}, {legacy.RK_FILE}")
    print(f"  CPA分批上传: 每 {max(1, int(cpa_upload_every_n))} 个成功账号触发一次")
    print(f"  输出文件: {output_file}")
    print(f"{'#' * 60}\n")

    # cfmail 子域名自动配置
    _provisioner = None
    _rotation_lock = threading.Lock()
    _consec_fail_lock = threading.Lock()
    _consec_fail_count = [0]
    _rotation_in_progress = [False]
    _active_domain_target = _cfmail_active_domain_target()

    if provider == "cfmail" and legacy.CFMAIL_PROVISIONING_ENABLED:
        from .cfmail_provisioner import CfmailProvisioner, ProvisioningSettings
        _settings = ProvisioningSettings(
            auth_email=legacy.CF_AUTH_EMAIL,
            auth_key=legacy.CF_AUTH_KEY,
            account_id=legacy.CF_ACCOUNT_ID,
            zone_id=legacy.CF_ZONE_ID,
            worker_name=legacy.CF_WORKER_NAME,
            zone_name=legacy.CF_ZONE_NAME,
        )
        _provisioner = CfmailProvisioner(proxy_url=proxy, settings=_settings)
        print("[cfmail] 正在整理激活域池...")
        try:
            _sync_cfmail_accounts_with_env_credentials(_provisioner)
            # 若账号文件中没有任何有效账号，先用 env 变量写入 base 账号作为 provisioning 来源
            _existing = _provisioner._load_all_accounts()
            _valid_existing = [
                a for a in _existing
                if str(a.get("worker_domain", "")).strip()
                and str(a.get("admin_password", "")).strip()
            ]
            if not _valid_existing:
                _base_worker = legacy.CFMAIL_WORKER_DOMAIN
                _base_pass = legacy.CFMAIL_ADMIN_PASSWORD
                _base_email = legacy.CFMAIL_EMAIL_DOMAIN or legacy.CF_ZONE_NAME
                if _base_worker and _base_pass and _base_email:
                    _provisioner._write_accounts([{
                        "name": "cfmail-base",
                        "worker_domain": _base_worker,
                        "email_domain": _base_email,
                        "admin_password": _base_pass,
                        "enabled": True,
                    }])
                    print(f"[cfmail] 已写入 base 账号: {_base_email}")

            _pool = _provisioner.normalize_to_domain_pool(_active_domain_target)
            _active_domains = list(_pool.get("active_domains") or [])
            _provisioned_domains = list(_pool.get("provisioned_domains") or [])
            _retired_domains = list(_pool.get("retired_domains") or [])
            if _provisioned_domains or _retired_domains:
                print(
                    "[cfmail] 域池整理完成: "
                    f"新增={', '.join(_provisioned_domains) if _provisioned_domains else '无'} "
                    f"移除={', '.join(_retired_domains) if _retired_domains else '无'}"
                )
            print(f"[cfmail] Worker 当前激活域名: {', '.join(_active_domains) if _active_domains else '无'}")
            # 重新加载账号
            legacy._reload_cfmail_accounts_if_needed(force=True)
            _active_accounts = _active_cfmail_accounts_for_domains(_active_domains)
            if _active_accounts:
                legacy.CFMAIL_ACCOUNTS = _active_accounts
                print(f"[cfmail] 注册将使用随机子域名: {', '.join(a.email_domain for a in _active_accounts)}")
            else:
                print(f"[cfmail] 使用现有账号: {', '.join(a.email_domain for a in legacy.CFMAIL_ACCOUNTS)}")

        except Exception as _norm_err:
            print(f"[cfmail] 随机子域名初始化失败（继续执行原有域名）: {_norm_err}")
            _provisioner = None

    def _try_rotate_domain() -> None:
        if _provisioner is None:
            return
        with _rotation_lock:
            if _rotation_in_progress[0]:
                return
            _rotation_in_progress[0] = True
        try:
            print(f"\n[cfmail] 连续失败 {_MAX_CONSECUTIVE_FAILURES} 次，触发域名轮换...")
            _sync_cfmail_accounts_with_env_credentials(_provisioner)
            result = _provisioner.rotate_active_domain()
            if result.success:
                print(f"[cfmail] 域名轮换成功: {result.old_domain} -> {result.new_domain}")
            else:
                print(f"[cfmail] 域名轮换失败: {result.error}")
            _pool = _provisioner.normalize_to_domain_pool(_active_domain_target)
            _active_domains = list(_pool.get("active_domains") or [])
            print(f"[cfmail] Worker 当前激活域名: {', '.join(_active_domains) if _active_domains else '无'}")
            legacy._reload_cfmail_accounts_if_needed(force=True)
            _active_accounts = _active_cfmail_accounts_for_domains(_active_domains)
            if _active_accounts:
                legacy.CFMAIL_ACCOUNTS = _active_accounts
        except Exception as _rot_err:
            print(f"[cfmail] 域名轮换异常: {_rot_err}")
        finally:
            with _rotation_lock:
                _rotation_in_progress[0] = False

    def _record_failure_and_maybe_rotate() -> None:
        if _provisioner is None:
            return
        with _consec_fail_lock:
            _consec_fail_count[0] += 1
            should_rotate = _consec_fail_count[0] >= _MAX_CONSECUTIVE_FAILURES
            if should_rotate:
                _consec_fail_count[0] = 0
        if should_rotate:
            threading.Thread(
                target=_try_rotate_domain,
                daemon=True,
            ).start()

    do_cleanup = cpa_cleanup if cpa_cleanup is not None else legacy.CPA_CLEANUP_ENABLED
    if do_cleanup and legacy.UPLOAD_API_URL:
        legacy._run_cpa_cleanup_before_register()

    success_count = 0
    fail_count = 0
    completed_count = 0
    start_time = time.time()
    upload_every_n = max(1, int(cpa_upload_every_n or 1))
    since_last_upload = 0

    initial_pool_count = 0
    if duckmail_mode:
        import get_duck
        get_duck.reset_duck_bearer_repeat_counts()
        initial_pool_count = len(get_duck.load_duck_addresses())
        if initial_pool_count > 0:
            print("[调度] 当前 Email 池内数量 > 0, 启动消费者。")
        else:
            print("[调度] 当前 Email 池内数量 = 0，等待生产者补充。")
        _log_batch_status(success_count, fail_count, pool_count=initial_pool_count)

    duck_poll_min = max(5, int(getattr(legacy, "TASK_LAUNCH_INTERVAL_MIN_SECONDS", 5) or 5))
    duck_poll_max = max(
        duck_poll_min,
        int(getattr(legacy, "TASK_LAUNCH_INTERVAL_MAX_SECONDS", duck_poll_min) or duck_poll_min),
    )
    producer_done = threading.Event()
    producer_summary = {"produced": 0, "error": None}

    producer_thread = None
    if duckmail_mode:
        def _duck_producer_main() -> None:
            produced, last_error = _produce_duck_addresses_until_exhausted(
                stop_count=2,
                delay_seconds=0,
            )
            producer_summary["produced"] = produced
            producer_summary["error"] = last_error
            producer_done.set()

        producer_thread = threading.Thread(target=_duck_producer_main, daemon=True)
        producer_thread.start()
        with legacy._print_lock:
            print(f"[duckmail] 已启动独立生产者，消费者轮询间隔 {duck_poll_min}-{duck_poll_max} 秒")

    legacy._render_apt_like_progress(completed_count, total_accounts, success_count, fail_count, start_time)

    with ThreadPoolExecutor(max_workers=actual_workers) as executor:
        pending_indexes = list(range(1, total_accounts + 1))
        active_futures = {}
        duck_stop_launch = False
        empty_reads = 0
        empty_reads_after_stop = 0

        while pending_indexes or active_futures:
            if duckmail_mode:
                import get_duck

                while not duck_stop_launch and pending_indexes and len(active_futures) < actual_workers:
                    mailbox_email = get_duck.try_take_duck_address()
                    if mailbox_email:
                        get_duck.mark_duck_address_reserved(mailbox_email)
                    if not mailbox_email:
                        empty_reads += 1
                        if producer_done.is_set():
                            empty_reads_after_stop += 1
                        else:
                            empty_reads_after_stop = 0
                        if producer_done.is_set() and empty_reads_after_stop >= 3:
                            duck_stop_launch = True
                            with legacy._print_lock:
                                print("[调度] Email 池已空，消费者已退出")
                            break
                        if not producer_done.is_set():
                            delay = legacy.random.uniform(duck_poll_min, duck_poll_max)
                            with legacy._print_lock:
                                print(f"[调度] 当前 Email 池内数量：0")
                                print(f"[account] 已成功：{success_count}  已失败：{fail_count}")
                                print(f"[duckmail] 地址池为空，生产者运行中，{delay:.1f} 秒后重试")
                            time.sleep(delay)
                            break
                        delay = legacy.random.uniform(duck_poll_min, duck_poll_max)
                        with legacy._print_lock:
                            print(f"[调度] 当前生产者已退出")
                            print(f"[duckmail] 地址池为空，第 {empty_reads_after_stop}/3 次空读，{delay:.1f} 秒后重试")
                        time.sleep(delay)
                        break

                    empty_reads = 0
                    empty_reads_after_stop = 0
                    idx = pending_indexes.pop(0)
                    future = executor.submit(run_single, idx, total_accounts, proxy, output_file, mailbox_email)
                    active_futures[future] = (idx, mailbox_email)
                    with legacy._print_lock:
                        print(f"[duckmail] 投放地址: {mailbox_email}")
                    if pending_indexes and len(active_futures) < actual_workers:
                        time.sleep(legacy.random.uniform(duck_poll_min, duck_poll_max))
            else:
                while pending_indexes and len(active_futures) < actual_workers:
                    idx = pending_indexes.pop(0)
                    future = executor.submit(run_single, idx, total_accounts, proxy, output_file)
                    active_futures[future] = (idx, "")
                    if legacy.BATCH_MODE == "pipeline" and pending_indexes:
                        time.sleep(legacy.random.uniform(
                            legacy.TASK_LAUNCH_INTERVAL_MIN_SECONDS,
                            legacy.TASK_LAUNCH_INTERVAL_MAX_SECONDS,
                        ))

            if not active_futures:
                if duckmail_mode and not duck_stop_launch:
                    continue
                break

            done, _ = wait(list(active_futures.keys()), return_when=FIRST_COMPLETED)
            for future in done:
                idx, reserved_email = active_futures.pop(future)
                try:
                    ok, email, error_code, err = future.result()
                    account_label = str(email or reserved_email or idx)
                    if ok:
                        success_count += 1
                        if duckmail_mode and account_label:
                            get_duck.clear_duck_address_reserved(account_label)
                        with legacy._print_lock:
                            print(f"[{account_label}] [结果] ✅成功")
                        since_last_upload += 1
                        with _consec_fail_lock:
                            _consec_fail_count[0] = 0
                        if legacy.UPLOAD_API_URL and since_last_upload >= upload_every_n:
                            uploaded, failed, reason = _run_cpa_upload_with_compact_log()
                            with legacy._print_lock:
                                if failed == 0 and uploaded > 0:
                                    print(f"[{account_label}] ✅CPA 上传成功")
                                else:
                                    detail = reason or "未找到可上传 token"
                                    print(f"[{account_label}] ❌CPA 上传失败: {detail}")
                            since_last_upload = 0
                    else:
                        fail_count += 1
                        if duckmail_mode and account_label:
                            get_duck.clear_duck_address_reserved(account_label)
                        with legacy._print_lock:
                            detail = f": {err}" if err else ""
                            print(f"[{account_label}] [结果] ❌失败{detail}")
                        if _is_duck_pool_exhausted(err):
                            pending_indexes.clear()
                            duck_stop_launch = True
                            with legacy._print_lock:
                                print("[duckmail] 地址池补充重试 3 次后仍为空，停止投放新任务，等待已启动任务完成")
                        del error_code
                        _record_failure_and_maybe_rotate()
                except Exception as error:
                    fail_count += 1
                    with legacy._print_lock:
                        print(f"[{reserved_email or idx}] [结果] ❌失败: 线程异常: {error}")
                    _record_failure_and_maybe_rotate()
                finally:
                    completed_count += 1
                    with legacy._print_lock:
                        _log_batch_status(success_count, fail_count)
                    legacy._render_apt_like_progress(
                        completed_count, total_accounts, success_count, fail_count, start_time
                    )

    if duckmail_mode and producer_thread is not None:
        producer_thread.join()

    with legacy._print_lock:
        print()

    batch_completed = completed_count >= total_accounts if total_accounts else True
    if duckmail_mode and pending_indexes:
        with legacy._print_lock:
            print(f"[duckmail] 仍有 {len(pending_indexes)} 个账号未被投放，本轮按失败处理")
        batch_completed = False

    if duckmail_mode:
        with legacy._print_lock:
            current_pool_count = len(__import__('get_duck').load_duck_addresses())
            print(f"[email] 当前 Email 池内数量：{current_pool_count}")
            print("[调度] 当前生产者已退出")
            print(f"[duckmail] 生产者累计追加: {producer_summary['produced']} 个")
            if producer_summary["error"]:
                print(f"[duckmail] 生产者结束原因: {producer_summary['error']}")

    elapsed = time.time() - start_time
    avg = elapsed / total_accounts if total_accounts else 0
    print(f"\n{'#' * 60}")
    print(f"  注册完成! 耗时 {elapsed:.1f} 秒")
    print(f"  总数: {total_accounts} | 成功: {success_count} | 失败: {fail_count}")
    print(f"  平均速度: {avg:.1f} 秒/个")
    if success_count > 0:
        print(f"  结果文件: {output_file}")
    print(f"{'#' * 60}")

    if success_count > 0 and legacy.UPLOAD_API_URL and since_last_upload > 0:
        _run_cpa_upload_with_compact_log()

    return batch_completed and success_count > 0
