# -*- coding: utf-8 -*-
"""Runtime fixes for run_fixed.py.

Keeps the existing Zepp compatibility layer untouched while fixing:
1. AES-GCM token cache parsing (16-byte nonce + 16-byte tag).
2. GitHub Actions false-green status when all accounts fail.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from Crypto.Cipher import AES

import run_fixed as base


_result_lock = threading.Lock()
_attempt_count = 0
_success_count = 0
_original_run_single_account = base.legacy.run_single_account


def _fixed_load_cache() -> dict[str, dict[str, Any]]:
    """Load token cache using the same binary layout used by _persist_cache()."""
    if not base.CACHE_PATH.exists() or base._cache_key is None:
        return {}

    try:
        raw = base.CACHE_PATH.read_bytes()

        # Layout written by run_fixed._persist_cache():
        # CACHE_MAGIC (4) + GCM nonce (16) + tag (16) + ciphertext.
        if not raw.startswith(base.CACHE_MAGIC) or len(raw) < 36:
            raise ValueError("unknown token cache format")

        nonce = raw[4:20]
        tag = raw[20:36]
        ciphertext = raw[36:]

        cipher = AES.new(base._cache_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        decoded = json.loads(plaintext.decode("utf-8"))

        if isinstance(decoded, dict):
            print(f"已读取加密token缓存：{len(decoded)}个账号")
            return decoded
        return {}
    except Exception as exc:
        print(f"token缓存无法读取，将重新登录生成：{exc}")
        return {}


def _tracked_run_single_account(total: int, idx: int, user_mi: str, passwd_mi: str):
    global _attempt_count, _success_count

    result = _original_run_single_account(total, idx, user_mi, passwd_mi)
    with _result_lock:
        _attempt_count += 1
        if result.get("success") is True:
            _success_count += 1
    return result


def main() -> int:
    # Patch only the two behaviours that are broken; leave Zepp auth/upload logic intact.
    base._load_cache = _fixed_load_cache
    base.legacy.run_single_account = _tracked_run_single_account

    rc = base.main()
    if rc != 0:
        return rc

    if _attempt_count > 0 and _success_count == 0:
        print("所有账号均执行失败，返回非0退出码以标记GitHub Actions失败")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
