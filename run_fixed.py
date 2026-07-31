# -*- coding: utf-8 -*-
"""Zepp Life login compatibility layer for the legacy step uploader.

The legacy repository still contains the working step-upload payload, but its
password-login endpoint is obsolete and triggers HTTP 429 easily. This runner
keeps the existing upload implementation and replaces only login/token handling.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import traceback
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

import requests
from Crypto.Cipher import AES

import main as legacy


CACHE_PATH = Path("encrypted_tokens.data")
CACHE_MAGIC = b"ZLS1"
HM_AES_KEY = b"xeNtBVqzDc6tuNTh"
HM_AES_IV = b"MAAAYAAAAAAAAABg"
REQUEST_TIMEOUT = 15

_cache_lock = threading.Lock()
_token_cache: dict[str, dict[str, Any]] = {}
_cache_dirty = False
_cache_key: bytes | None = None

_original_init = legacy.MiMotionRunner.__init__


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len]) * pad_len


def _derive_cache_key(config_text: str) -> bytes:
    """Prefer AES_KEY, otherwise derive a stable key from the existing CONFIG secret."""
    configured_key = os.environ.get("AES_KEY", "").strip()
    key_material = configured_key if configured_key else config_text
    return hashlib.sha256(("zepp-life-steps-token-cache-v1:" + key_material).encode("utf-8")).digest()


def _load_cache() -> dict[str, dict[str, Any]]:
    if not CACHE_PATH.exists() or _cache_key is None:
        return {}
    try:
        raw = CACHE_PATH.read_bytes()
        if not raw.startswith(CACHE_MAGIC) or len(raw) < 32:
            raise ValueError("unknown token cache format")
        nonce = raw[4:16]
        tag = raw[16:32]
        ciphertext = raw[32:]
        cipher = AES.new(_cache_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        decoded = json.loads(plaintext.decode("utf-8"))
        return decoded if isinstance(decoded, dict) else {}
    except Exception as exc:
        print(f"token缓存无法读取，将重新登录生成：{exc}")
        return {}


def _persist_cache() -> None:
    global _cache_dirty
    if not _cache_dirty or _cache_key is None:
        return
    with _cache_lock:
        payload = json.dumps(_token_cache, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        cipher = AES.new(_cache_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        tmp_path = CACHE_PATH.with_suffix(".tmp")
        tmp_path.write_bytes(CACHE_MAGIC + cipher.nonce + tag + ciphertext)
        tmp_path.replace(CACHE_PATH)
        _cache_dirty = False
        print("已更新加密token缓存")


def _set_cache(user: str, record: dict[str, Any]) -> None:
    global _cache_dirty
    with _cache_lock:
        _token_cache[user] = record
        _cache_dirty = True


def _request_json(method: str, url: str, **kwargs: Any) -> dict[str, Any] | None:
    try:
        response = requests.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        if response.status_code != 200:
            return None
        data = response.json()
        return data if isinstance(data, dict) else None
    except (requests.RequestException, ValueError):
        return None


def _extract_access_token(location: str) -> str | None:
    query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    values = query.get("access")
    return values[0] if values else None


def _login_access_token(user: str, password: str) -> tuple[str | None, str | None]:
    headers = {
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "user-agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
        "app_name": "com.xiaomi.hm.health",
        "appname": "com.xiaomi.hm.health",
        "appplatform": "android_phone",
        "x-hm-ekv": "1",
        "hm-privacy-ceip": "false",
    }
    login_data = {
        "emailOrPhone": user,
        "password": password,
        "state": "REDIRECTION",
        "client_id": "HuaMi",
        "country_code": "CN",
        "token": "access",
        "redirect_uri": "https://s3-us-west-2.amazonaws.com/hm-registration/successsignin.html",
    }
    plaintext = urllib.parse.urlencode(login_data).encode("utf-8")
    cipher = AES.new(HM_AES_KEY, AES.MODE_CBC, HM_AES_IV)
    encrypted = cipher.encrypt(_pkcs7_pad(plaintext))
    try:
        response = requests.post(
            "https://api-user.zepp.com/v2/registrations/tokens",
            data=encrypted,
            headers=headers,
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return None, f"登录网络异常：{exc}"
    if response.status_code != 303:
        retry_after = response.headers.get("Retry-After")
        suffix = f"，Retry-After={retry_after}" if retry_after else ""
        return None, f"登录异常，status: {response.status_code}{suffix}"
    access_token = _extract_access_token(response.headers.get("Location", ""))
    if not access_token:
        return None, "登录响应中没有access token"
    return access_token, None


def _grant_login_tokens(
    access_token: str, device_id: str, is_phone: bool
) -> tuple[str | None, str | None, str | None, str | None]:
    headers = {
        "user-agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
        "app_name": "com.xiaomi.hm.health",
        "x-request-id": str(uuid.uuid4()),
        "accept-language": "zh-CN",
        "appname": "com.xiaomi.hm.health",
        "cv": "50818_6.14.0",
        "v": "2.0",
        "appplatform": "android_phone",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    }
    data: dict[str, str] = {
        "app_name": "com.xiaomi.hm.health",
        "app_version": "6.14.0",
        "code": access_token,
        "country_code": "CN",
        "device_id": device_id,
        "device_model": "phone" if is_phone else "android_phone",
        "grant_type": "access_token",
        "third_name": "huami_phone" if is_phone else "email",
    }
    if not is_phone:
        data.update(
            {
                "allow_registration": "false",
                "dn": "account.zepp.com,api-user.zepp.com,api-mifit.zepp.com,api-watch.zepp.com,app-analytics.zepp.com,api-analytics.huami.com,auth.zepp.com",
                "lang": "zh_CN",
                "os_version": "1.5.0",
                "source": "com.xiaomi.hm.health:6.14.0:50818",
            }
        )

    last_error = "客户端登录请求失败"
    for url in (
        "https://account.zepp.com/v2/client/login",
        "https://account.huami.com/v2/client/login",
    ):
        try:
            response = requests.post(url, data=data, headers=headers, timeout=REQUEST_TIMEOUT)
            if response.status_code != 200:
                last_error = f"客户端登录status={response.status_code}"
                continue
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            last_error = f"客户端登录异常：{exc}"
            continue
        if payload.get("result") != "ok":
            last_error = f"客户端登录失败：{payload.get('result') or payload.get('error_code')}"
            continue
        token_info = payload.get("token_info") or {}
        login_token = token_info.get("login_token")
        app_token = token_info.get("app_token")
        user_id = token_info.get("user_id")
        if login_token and app_token and user_id:
            return str(login_token), str(app_token), str(user_id), None
        last_error = "客户端登录返回token不完整"
    return None, None, None, last_error


def _grant_app_token(login_token: str) -> tuple[str | None, str | None]:
    params = {
        "app_name": "com.xiaomi.hm.health",
        "dn": "api-user.huami.com,api-mifit.huami.com,app-analytics.huami.com",
        "login_token": login_token,
    }
    headers = {"User-Agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)"}
    for url in (
        "https://account-cn3.zepp.com/v1/client/app_tokens",
        "https://account-cn.huami.com/v1/client/app_tokens",
    ):
        payload = _request_json("GET", url, params=params, headers=headers)
        if not payload or payload.get("result") != "ok":
            continue
        app_token = (payload.get("token_info") or {}).get("app_token")
        if app_token:
            return str(app_token), None
    return None, "login_token无法换取app_token"


def _check_app_token(app_token: str, user_id: str | None) -> bool:
    if not app_token:
        return False
    params = {
        "r": str(uuid.uuid4()),
        "userid": user_id or "0",
        "appid": "428135909242707968",
        "channel": "Normal",
        "country": "CN",
        "cv": "50818_6.14.0",
        "device": "android_31",
        "device_type": "android_phone",
        "lang": "zh_CN",
        "timezone": "Asia/Shanghai",
        "v": "2.0",
    }
    headers = {
        "User-Agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
        "country": "CN",
        "appplatform": "android_phone",
        "x-request-id": str(uuid.uuid4()),
        "timezone": "Asia/Shanghai",
        "channel": "Normal",
        "cv": "50818_6.14.0",
        "appname": "com.xiaomi.hm.health",
        "v": "2.0",
        "apptoken": app_token,
        "lang": "zh_CN",
        "clientid": "428135909242707968",
    }
    payload = _request_json(
        "GET",
        "https://api-mifit-cn3.zepp.com/huami.health.getUserInfo.json",
        params=params,
        headers=headers,
    )
    return bool(payload and payload.get("message") == "success")


def _patched_init(self: Any, user: str, password: str) -> None:
    _original_init(self, user, password)
    self.log_str = "\n"
    self._cached_app_token = None


def _patched_login(self: Any) -> tuple[str | int, str | int]:
    user = self.user
    with _cache_lock:
        record = dict(_token_cache.get(user) or {})

    device_id = str(record.get("device_id") or uuid.uuid4())
    access_token = record.get("access_token")
    login_token = record.get("login_token")
    app_token = record.get("app_token")
    user_id = record.get("user_id")

    if app_token and _check_app_token(str(app_token), str(user_id) if user_id else None):
        self._cached_app_token = str(app_token)
        self.log_str += "使用加密缓存的app_token，跳过账号密码登录\n"
        return str(login_token or "cached"), str(user_id)

    if login_token:
        refreshed_app_token, _ = _grant_app_token(str(login_token))
        if refreshed_app_token:
            record.update(
                {
                    "device_id": device_id,
                    "app_token": refreshed_app_token,
                    "app_token_time": int(time.time() * 1000),
                }
            )
            _set_cache(user, record)
            self._cached_app_token = refreshed_app_token
            self.log_str += "已使用login_token刷新app_token\n"
            return str(login_token), str(user_id)

    if access_token:
        new_login, new_app, new_user_id, _ = _grant_login_tokens(
            str(access_token), device_id, self.is_phone
        )
        if new_login and new_app and new_user_id:
            record.update(
                {
                    "device_id": device_id,
                    "login_token": new_login,
                    "app_token": new_app,
                    "user_id": new_user_id,
                    "login_token_time": int(time.time() * 1000),
                    "app_token_time": int(time.time() * 1000),
                }
            )
            _set_cache(user, record)
            self._cached_app_token = new_app
            self.log_str += "已使用access_token刷新登录凭据\n"
            return new_login, new_user_id

    new_access, error = _login_access_token(user, self.password)
    if not new_access:
        self.log_str += f"登录获取accessToken失败：{error}\n"
        return 0, 0

    new_login, new_app, new_user_id, error = _grant_login_tokens(
        new_access, device_id, self.is_phone
    )
    if not new_login or not new_app or not new_user_id:
        self.log_str += f"登录提取token失败：{error}\n"
        return 0, 0

    now_ms = int(time.time() * 1000)
    record = {
        "device_id": device_id,
        "access_token": new_access,
        "login_token": new_login,
        "app_token": new_app,
        "user_id": new_user_id,
        "access_token_time": now_ms,
        "login_token_time": now_ms,
        "app_token_time": now_ms,
    }
    _set_cache(user, record)
    self._cached_app_token = new_app
    self.log_str += "新版Zepp加密登录成功，已生成token缓存\n"
    return new_login, new_user_id


def _patched_get_app_token(self: Any, login_token: str) -> str:
    if self._cached_app_token:
        return str(self._cached_app_token)
    app_token, error = _grant_app_token(login_token)
    if not app_token:
        raise RuntimeError(error or "无法获取app_token")
    self._cached_app_token = app_token
    return app_token


def _initialize_legacy(config: dict[str, Any]) -> None:
    legacy.time_bj = legacy.get_beijing_time()
    legacy.config = config
    legacy.PUSH_PLUS_TOKEN = config.get("PUSH_PLUS_TOKEN")
    legacy.PUSH_PLUS_HOUR = config.get("PUSH_PLUS_HOUR")
    legacy.PUSH_PLUS_MAX = legacy.get_int_value_default(config, "PUSH_PLUS_MAX", 30)
    sleep_seconds = config.get("SLEEP_GAP")
    legacy.sleep_seconds = float(sleep_seconds) if sleep_seconds not in (None, "") else 5.0
    legacy.users = config.get("USER")
    legacy.passwords = config.get("PWD")
    if not legacy.users or not legacy.passwords:
        raise ValueError("未正确配置账号密码")
    legacy.min_step, legacy.max_step = legacy.get_min_max_by_time()
    legacy.use_concurrent = config.get("USE_CONCURRENT") == "True"
    if not legacy.use_concurrent:
        print(f"多账号执行间隔：{legacy.sleep_seconds}")


def main() -> int:
    global _cache_key, _token_cache
    config_text = os.environ.get("CONFIG")
    if not config_text:
        print("未配置CONFIG变量，无法执行")
        return 1
    try:
        config = json.loads(config_text)
        if not isinstance(config, dict):
            raise ValueError("CONFIG必须是JSON对象")
    except Exception:
        print("CONFIG格式不正确，请严格使用JSON格式")
        traceback.print_exc()
        return 1

    _cache_key = _derive_cache_key(config_text)
    _token_cache = _load_cache()

    legacy.MiMotionRunner.__init__ = _patched_init
    legacy.MiMotionRunner.login = _patched_login
    legacy.MiMotionRunner.get_app_token = _patched_get_app_token

    try:
        _initialize_legacy(config)
        legacy.execute()
        return 0
    except Exception:
        traceback.print_exc()
        return 1
    finally:
        _persist_cache()


if __name__ == "__main__":
    raise SystemExit(main())
