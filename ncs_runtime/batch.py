from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import threading
import time

import ncs_register_legacy as legacy

from .engine import RegistrationEngine

_MAX_CONSECUTIVE_FAILURES = 5


def run_single(idx: int, total: int, proxy: str, output_file: str):
    result = RegistrationEngine(idx=idx, total=total, proxy=proxy, output_file=output_file).run()
    return result.success, result.email or None, result.error_code or "", result.error_message or None


def run_batch(total_accounts: int = 3, output_file: str = "registered_accounts.txt",
              max_workers: int = 3, proxy: str = None, cpa_cleanup=None,
              cpa_upload_every_n: int = 3):
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
        print("[cfmail] 正在准备随机子域名...")
        try:
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

            # 每次都创建新的随机子域名（缓存中的旧 auto 域名 Worker 绑定可能已失效）
            _rot = _provisioner.rotate_active_domain(skip_smoke=True)
            if _rot.success:
                print(f"[cfmail] 随机子域名已创建: {_rot.new_domain}")
                print("[cfmail] 等待 60 秒让 CF Workers 绑定生效...")
                time.sleep(60)
            else:
                print(f"[cfmail] 随机子域名创建失败: {_rot.error}，将继续使用现有域名")

            # 强制重新加载账号，让注册流程使用新域名
            legacy._reload_cfmail_accounts_if_needed(force=True)

            # 优先使用 auto 随机子域名账号
            _auto_accounts = [a for a in legacy.CFMAIL_ACCOUNTS if a.email_domain.startswith("auto")]
            if _auto_accounts:
                legacy.CFMAIL_ACCOUNTS = _auto_accounts
                print(f"[cfmail] 注册将使用随机子域名: {', '.join(a.email_domain for a in _auto_accounts)}")
            else:
                print(f"[cfmail] 未找到 auto 账号，使用现有账号: {', '.join(a.email_domain for a in legacy.CFMAIL_ACCOUNTS)}")

        except Exception as _norm_err:
            print(f"[cfmail] 随机子域名初始化失败（继续执行原有域名）: {_norm_err}")
            _provisioner = None

    _consec_fail_lock = threading.Lock()
    _consec_fail_count = [0]
    _rotation_in_progress = [False]

    def _try_rotate_domain() -> None:
        if _provisioner is None:
            return
        with _rotation_lock:
            if _rotation_in_progress[0]:
                return
            _rotation_in_progress[0] = True
        try:
            print(f"\n[cfmail] 连续失败 {_MAX_CONSECUTIVE_FAILURES} 次，触发域名轮换...")
            result = _provisioner.rotate_active_domain(skip_smoke=True)
            if result.success:
                print(f"[cfmail] 域名轮换成功: {result.old_domain} -> {result.new_domain}")
                print("[cfmail] 等待 60 秒让 CF Workers 绑定生效...")
                time.sleep(60)
                legacy._reload_cfmail_accounts_if_needed(force=True)
                _auto_accounts = [a for a in legacy.CFMAIL_ACCOUNTS if a.email_domain.startswith("auto")]
                if _auto_accounts:
                    legacy.CFMAIL_ACCOUNTS = _auto_accounts
            else:
                print(f"[cfmail] 域名轮换失败: {result.error}")
        except Exception as _rot_err:
            print(f"[cfmail] 域名轮换异常: {_rot_err}")
        finally:
            with _rotation_lock:
                _rotation_in_progress[0] = False

    do_cleanup = cpa_cleanup if cpa_cleanup is not None else legacy.CPA_CLEANUP_ENABLED
    if do_cleanup and legacy.UPLOAD_API_URL:
        legacy._run_cpa_cleanup_before_register()

    success_count = 0
    fail_count = 0
    completed_count = 0
    start_time = time.time()
    upload_every_n = max(1, int(cpa_upload_every_n or 1))
    since_last_upload = 0

    legacy._render_apt_like_progress(completed_count, total_accounts, success_count, fail_count, start_time)

    with ThreadPoolExecutor(max_workers=actual_workers) as executor:
        pending_indexes = list(range(1, total_accounts + 1))
        active_futures = {}

        while pending_indexes or active_futures:
            while pending_indexes and len(active_futures) < actual_workers:
                idx = pending_indexes.pop(0)
                future = executor.submit(run_single, idx, total_accounts, proxy, output_file)
                active_futures[future] = idx
                if legacy.BATCH_MODE == "pipeline" and pending_indexes:
                    time.sleep(legacy.random.uniform(
                        legacy.TASK_LAUNCH_INTERVAL_MIN_SECONDS,
                        legacy.TASK_LAUNCH_INTERVAL_MAX_SECONDS,
                    ))

            done, _ = wait(list(active_futures.keys()), return_when=FIRST_COMPLETED)
            for future in done:
                idx = active_futures.pop(future)
                try:
                    ok, email, error_code, err = future.result()
                    if ok:
                        success_count += 1
                        since_last_upload += 1
                        with _consec_fail_lock:
                            _consec_fail_count[0] = 0
                        if legacy.UPLOAD_API_URL and since_last_upload >= upload_every_n:
                            print(f"\n[CPA] 达到分批上传阈值: {since_last_upload}/{upload_every_n}，开始上传...")
                            legacy._upload_all_tokens_to_cpa()
                            since_last_upload = 0
                    else:
                        fail_count += 1
                        print(f"  [账号 {idx}] 失败: {err}")
                        if _provisioner is not None:
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
                except Exception as error:
                    fail_count += 1
                    with legacy._print_lock:
                        print(f"[FAIL] 账号 {idx} 线程异常: {error}")
                finally:
                    completed_count += 1
                    legacy._render_apt_like_progress(
                        completed_count, total_accounts, success_count, fail_count, start_time
                    )

    with legacy._print_lock:
        print()

    elapsed = time.time() - start_time
    avg = elapsed / total_accounts if total_accounts else 0
    print(f"\n{'#' * 60}")
    print(f"  注册完成! 耗时 {elapsed:.1f} 秒")
    print(f"  总数: {total_accounts} | 成功: {success_count} | 失败: {fail_count}")
    print(f"  平均速度: {avg:.1f} 秒/个")
    if success_count > 0:
        print(f"  结果文件: {output_file}")
    print(f"{'#' * 60}")

    if success_count > 0:
        if legacy.UPLOAD_API_URL and since_last_upload > 0:
            print(f"\n[CPA] 收尾上传剩余 {since_last_upload} 个成功账号对应 token...")
        legacy._upload_all_tokens_to_cpa()

    return success_count > 0
