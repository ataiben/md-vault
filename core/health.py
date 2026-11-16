from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.models import AccountEntry

MIN_MASTER_PASSWORD_LEN = 8

COMMON_WEAK_PASSWORDS = {
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "password",
    "password123",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "admin",
    "admin123",
    "admin888",
    "root1234",
    "welcome1",
    "iloveyou",
    "abc12345",
    "00000000",
    "88888888",
    "11111111",
    "66666666",
}

PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)
API_SECRET_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16})\b"
)
SEED_PHRASE_LINE_RE = re.compile(r"^(?:[a-z]{3,8}\s+){11}(?:[a-z]{3,8})(?:\s+[a-z]{3,8}){0,12}$")
EXPLICIT_SECRET_NOTE_RE = re.compile(
    r"(?:^|\n)\s*(?:明文密码|登录密码|支付密码|交易密码|私钥|助记词|seed\s*phrase|private\s*key|password)\s*[:：=]\s*\S{4,}",
    re.IGNORECASE,
)


def evaluate_password_strength(password: str, username: str = "") -> Dict[str, Any]:
    """
    Evaluate password entropy and structural weaknesses locally.
    Returns score in 0..4 ('极弱' | '较弱' | '一般' | '强' | '极强') and reason hints.
    """
    pwd = password or ""
    if not pwd:
        return {
            "score": 0,
            "label": "未设置",
            "is_weak": True,
            "entropy_bits": 0.0,
            "reasons": ["未填写密码"],
            "warnings": ["未填写密码"],
        }

    reasons: List[str] = []
    lower = pwd.lower()
    stripped = pwd.strip()

    has_lower = any("a" <= c <= "z" for c in pwd)
    has_upper = any("A" <= c <= "Z" for c in pwd)
    has_digit = any("0" <= c <= "9" for c in pwd)
    has_symbol = any(not c.isalnum() for c in pwd)

    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_symbol:
        pool += 32
    if pool == 0:
        pool = 26

    # Effective unique ratio dampens repeated-character inflation like 'aaaaaaaaaaaa'
    unique_ratio = len(set(pwd)) / max(1, len(pwd))
    entropy = len(pwd) * math.log2(pool) * (0.5 + 0.5 * unique_ratio)

    if len(pwd) < 8:
        reasons.append("长度不足 8 位")
    elif len(pwd) < 10:
        reasons.append("长度较短（建议至少 12 位）")

    if len(set(stripped)) <= 2 and len(stripped) >= 4:
        reasons.append("由单一或极少重复字符组成")
        entropy = min(entropy, 14.0)

    if lower in COMMON_WEAK_PASSWORDS:
        reasons.append("属于常见高频弱口令")
        entropy = min(entropy, 12.0)

    if pwd.isdigit():
        reasons.append("纯数字口令")
    elif pwd.isalpha() and len(pwd) < 14:
        reasons.append("仅包含字母，缺少数字与符号")

    if username:
        clean_user = username.split("@")[0].strip().lower()
        if len(clean_user) >= 4 and clean_user in lower:
            reasons.append("密码中包含登录账号名特征")
            entropy = max(0.0, entropy - 18.0)

    if len(pwd) < 8 or lower in COMMON_WEAK_PASSWORDS or len(set(stripped)) <= 1:
        score = 0
    elif entropy < 38 or len(pwd) < 10:
        score = 1
    elif entropy < 56:
        score = 2
    elif entropy < 78:
        score = 3
    else:
        score = 4

    labels = {0: "极弱", 1: "较弱", 2: "一般", 3: "强", 4: "极强"}
    return {
        "score": score,
        "label": labels[score],
        "is_weak": score <= 1,
        "entropy_bits": round(entropy, 1),
        "reasons": reasons,
        "warnings": reasons,
    }


def validate_master_password_policy(master_password: str) -> Optional[str]:
    """
    Validate minimum baseline rules for a vault master password.
    Returns an error message string if rejected, or None if valid.
    """
    pwd = master_password or ""
    if not pwd.strip() or len(pwd) < MIN_MASTER_PASSWORD_LEN:
        return f"主密码长度至少需要 {MIN_MASTER_PASSWORD_LEN} 个字符（且不能全为空格）"
    if len(set(pwd.strip())) <= 1:
        return "主密码不能由完全相同的单一字符组成"
    return None


def scan_plaintext_notes_risks(notes: str) -> List[str]:
    """
    Inspect plaintext Markdown notes for accidentally pasted high-sensitivity secrets.
    Returns human-readable risk descriptions if detected.
    """
    text = (notes or "").strip()
    if not text:
        return []

    risks: List[str] = []
    if PRIVATE_KEY_RE.search(text):
        risks.append("检测到 PEM / SSH 私钥文本块（-----BEGIN ... PRIVATE KEY-----）")

    if API_SECRET_RE.search(text):
        risks.append("检测到疑似高权限 API 密钥 / Token（如 sk-... / ghp_... / AKIA...）")

    if EXPLICIT_SECRET_NOTE_RE.search(text):
        risks.append("检测到疑似明文密码、私钥或助记词键值记录")

    for line in text.splitlines():
        candidate = " ".join(line.strip().split())
        if SEED_PHRASE_LINE_RE.match(candidate):
            word_cnt = len(candidate.split())
            if word_cnt in (12, 15, 18, 21, 24):
                risks.append(f"检测到疑似 {word_cnt} 词区块链助记词（Seed Phrase）")
                break

    return risks


def _parse_updated_at(raw: str) -> Optional[datetime]:
    s = (raw or "").strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def audit_vault_health(
    plain_entries: List[AccountEntry],
    now: Optional[datetime] = None,
    stale_days: int = 180,
) -> Dict[str, Any]:
    """
    Perform a 100% offline password health check across decrypted entries.
    Never includes plaintext passwords or secrets in the returned dictionary.
    """
    ref_now = now or datetime.now()
    total = len(plain_entries)

    pwd_buckets: Dict[str, List[Dict[str, Any]]] = {}
    weak_entries: List[Dict[str, Any]] = []
    missing_2fa_entries: List[Dict[str, Any]] = []
    stale_entries: List[Dict[str, Any]] = []

    for ent in plain_entries:
        summary = {
            "id": ent.id,
            "title": ent.title,
            "category": ent.category,
            "platform": ent.platform,
            "username": ent.username,
            "favorite": bool(ent.favorite),
            "updated_at": ent.updated_at,
        }

        eval_res = evaluate_password_strength(ent.password, ent.username)
        if not ent.password or eval_res["score"] <= 1:
            weak_entries.append(
                {
                    **summary,
                    "length": len(ent.password or ""),
                    "strength_score": eval_res["score"],
                    "strength_label": eval_res["label"],
                    "reasons": eval_res["reasons"] or ["密码强度偏弱"],
                }
            )

        if ent.password:
            digest = hashlib.sha256(ent.password.encode("utf-8")).hexdigest()[:16]
            pwd_buckets.setdefault(digest, []).append(summary)

            has_any_2fa = bool(
                (ent.totp_secret and ent.totp_secret.strip())
                or (ent.two_fa_recovery and ent.two_fa_recovery.strip())
            )
            if not has_any_2fa:
                missing_2fa_entries.append(summary)

        dt = _parse_updated_at(ent.updated_at)
        if dt is not None:
            age_days = (ref_now - dt).days
            if age_days >= stale_days:
                stale_entries.append({**summary, "age_days": age_days})

    reused_groups: List[Dict[str, Any]] = []
    reused_entry_count = 0
    for group_items in pwd_buckets.values():
        if len(group_items) >= 2:
            reused_entry_count += len(group_items)
            reused_groups.append(
                {
                    "count": len(group_items),
                    "entries": group_items,
                }
            )
    reused_groups.sort(key=lambda g: g["count"], reverse=True)
    missing_2fa_entries.sort(key=lambda item: (not item["favorite"], item["title"]))
    stale_entries.sort(key=lambda item: item["age_days"], reverse=True)

    if total == 0:
        health_score = 100
    else:
        penalty = (
            (len(weak_entries) / total) * 45.0
            + (reused_entry_count / total) * 35.0
            + (len(missing_2fa_entries) / total) * 12.0
            + (len(stale_entries) / total) * 8.0
        )
        health_score = max(0, min(100, round(100.0 - penalty)))

    total_issues = (
        len(weak_entries)
        + len(reused_groups)
        + len(missing_2fa_entries)
        + len(stale_entries)
    )

    return {
        "total_entries": total,
        "score": int(health_score),
        "health_score": int(health_score),
        "stale_threshold_days": stale_days,
        "summary": {
            "total_entries": total,
            "total_issues": total_issues,
            "weak_count": len(weak_entries),
            "reused_group_count": len(reused_groups),
            "reused_entry_count": reused_entry_count,
            "missing_2fa_count": len(missing_2fa_entries),
            "unprotected_2fa_count": len(missing_2fa_entries),
            "stale_count": len(stale_entries),
        },
        "reused_groups": reused_groups,
        "weak_entries": weak_entries,
        "missing_2fa_entries": missing_2fa_entries,
        "unprotected_2fa_entries": missing_2fa_entries,
        "stale_entries": stale_entries,
    }
