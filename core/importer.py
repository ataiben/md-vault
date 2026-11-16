from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, Iterable, List, Set, Tuple
from urllib.parse import urlparse

from core.models import AccountEntry, generate_entry_id, now_timestamp
from core.totp import parse_totp_config

CSV_EXPORT_COLUMNS = [
    "category",
    "title",
    "platform",
    "username",
    "password",
    "totp_secret",
    "url",
    "phone",
    "recovery_email",
    "tags",
    "favorite",
    "two_fa_recovery",
    "notes",
    "updated_at",
]


def decode_csv_bytes(raw_bytes: bytes) -> str:
    """Decode CSV bytes supporting UTF-8 (with/without BOM) and GB18030/GBK."""
    for enc in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return raw_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def _pick_col(row_lower: Dict[str, str], candidates: Iterable[str]) -> str:
    for key in candidates:
        val = row_lower.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _infer_platform_from_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        host = (urlparse(raw).hostname or "").lower()
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host


def _detect_source_format(headers_lower: Set[str]) -> str:
    if {"login_uri", "login_username", "login_password"}.issubset(headers_lower):
        return "Bitwarden CSV"
    if {"title", "url", "username", "password", "otpauth"}.issubset(headers_lower):
        return "1Password CSV"
    if {"httpRealm".lower(), "formActionOrigin".lower()}.intersection(headers_lower):
        return "Firefox CSV"
    if {"name", "url", "username", "password"}.issubset(headers_lower):
        return "Chrome / Edge CSV"
    if {"category", "title", "username", "password"}.issubset(headers_lower):
        return "MD-Vault CSV"
    return "通用 CSV"


def parse_imported_csv(
    csv_text: str,
    existing_entries: Iterable[AccountEntry] = (),
    default_category: str = "外部导入",
    existing_plain_entries: Iterable[AccountEntry] = (),
) -> Dict[str, Any]:
    """
    Parse mainstream password manager / browser CSV exports into AccountEntry instances.
    Automatically skips blank rows and exact duplicate credentials.
    """
    cleaned = (csv_text or "").lstrip("\ufeff").strip()
    if not cleaned:
        raise ValueError("CSV 文件内容为空")

    reader = csv.DictReader(io.StringIO(cleaned))
    if not reader.fieldnames:
        raise ValueError("无法识别 CSV 表头，请确认文件为标准逗号分隔格式")

    headers_lower = {str(h).strip().lower() for h in reader.fieldnames if h}
    detected_format = _detect_source_format(headers_lower)

    recognized_any = headers_lower.intersection(
        {
            "name",
            "title",
            "account",
            "url",
            "login_uri",
            "username",
            "login_username",
            "login name",
            "password",
            "login_password",
            "标题",
            "账号",
            "登录账号",
            "密码",
            "登录密码",
        }
    )
    if not recognized_any:
        raise ValueError("未找到可识别的账号或密码列（支持 Chrome / Edge / Firefox / Bitwarden / 1Password / 通用 CSV）")

    seen_fingerprints: Set[Tuple[str, str, str, str]] = set()
    for ex in (*existing_entries, *existing_plain_entries):
        seen_fingerprints.add(
            (
                ex.title.strip().lower(),
                ex.username.strip().lower(),
                ex.password,
                ex.url.strip().lower(),
            )
        )

    imported: List[AccountEntry] = []
    skipped_duplicates = 0
    skipped_empty = 0
    fallback_cat = (default_category or "外部导入").strip() or "外部导入"

    for raw_row in reader:
        if not raw_row:
            skipped_empty += 1
            continue
        row_lower = {
            str(k).strip().lower(): (v if v is not None else "")
            for k, v in raw_row.items()
            if k is not None
        }

        # Skip non-login Bitwarden items unless they carry credentials
        bw_type = _pick_col(row_lower, ("type",))
        url = _pick_col(
            row_lower,
            ("url", "login_uri", "website", "web site", "uri", "origin", "网址", "网址/入口"),
        )
        username = _pick_col(
            row_lower,
            ("username", "login_username", "login name", "user", "email", "登录账号", "账号", "用户名"),
        )
        password = row_lower.get("password") or row_lower.get("login_password") or row_lower.get("登录密码") or row_lower.get("密码") or ""
        title_raw = _pick_col(
            row_lower, ("title", "name", "account", "service", "标题", "条目名称", "名称")
        )
        notes = (
            row_lower.get("notes")
            or row_lower.get("note")
            or row_lower.get("comments")
            or row_lower.get("extra")
            or row_lower.get("备注")
            or row_lower.get("备注说明")
            or ""
        ).strip()

        if bw_type and bw_type.lower() not in ("login", "1") and not password and not username:
            skipped_empty += 1
            continue

        if not any([title_raw, username, password, url, notes]):
            skipped_empty += 1
            continue

        inferred_host = _infer_platform_from_url(url)
        platform = _pick_col(row_lower, ("platform", "服务/平台", "平台")) or title_raw or inferred_host
        title = title_raw or inferred_host or username or "未命名导入账号"

        category = (
            _pick_col(row_lower, ("category", "folder", "group", "分类", "所属分类"))
            or fallback_cat
        )
        # Normalize nested folder paths like 'Work/Cloud' -> 'Work · Cloud' so H2 stays clean
        category = re.sub(r"\s*/\s*", " · ", category).strip() or fallback_cat

        raw_tags = _pick_col(row_lower, ("tags", "标签", "分区/标签"))
        tags = (
            [t.strip() for t in re.split(r"[,，;；]+", raw_tags) if t.strip()]
            if raw_tags
            else []
        )

        fav_raw = _pick_col(row_lower, ("favorite", "收藏", "星标")).lower()
        favorite = fav_raw in ("1", "true", "yes", "是", "y")

        totp_candidate = _pick_col(
            row_lower,
            ("totp_secret", "login_totp", "otpauth", "totp", "otp", "动态码密钥"),
        )
        valid_totp = ""
        two_fa_recovery = _pick_col(row_lower, ("two_fa_recovery", "2fa", "恢复码"))
        if totp_candidate:
            try:
                parse_totp_config(totp_candidate)
                valid_totp = totp_candidate
            except ValueError:
                # Preserve non-standard 2FA text inside encrypted two_fa_recovery so nothing is lost!
                two_fa_recovery = (
                    f"{two_fa_recovery}\n{totp_candidate}".strip()
                    if two_fa_recovery
                    else totp_candidate
                )

        fp = (
            title.strip().lower(),
            username.strip().lower(),
            password,
            url.strip().lower(),
        )
        if fp in seen_fingerprints:
            skipped_duplicates += 1
            continue
        seen_fingerprints.add(fp)

        imported.append(
            AccountEntry(
                id=generate_entry_id(),
                category=category,
                title=title,
                platform=platform,
                tags=tags,
                favorite=favorite,
                username=username,
                password=password,
                phone=_pick_col(row_lower, ("phone", "绑定手机", "手机号")),
                recovery_email=_pick_col(row_lower, ("recovery_email", "辅助邮箱")),
                url=url,
                totp_secret=valid_totp,
                two_fa_recovery=two_fa_recovery,
                notes=notes,
                updated_at=_pick_col(row_lower, ("updated_at", "更新日期")) or now_timestamp(),
            )
        )

    return {
        "entries": imported,
        "imported_count": len(imported),
        "skipped_duplicates": skipped_duplicates,
        "skipped_empty": skipped_empty,
        "detected_source": detected_format,
        "detected_format": detected_format,
    }


def _sanitize_csv_formula_cell(val: str) -> str:
    """Prevent spreadsheet formula injection (=, +, -, @) while preserving normal text."""
    if not val:
        return ""
    return val


def export_entries_to_csv(plain_entries: Iterable[AccountEntry]) -> str:
    """Serialize decrypted AccountEntry objects into a standard UTF-8 CSV string."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_EXPORT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for ent in plain_entries:
        writer.writerow(
            {
                "category": _sanitize_csv_formula_cell(ent.category),
                "title": _sanitize_csv_formula_cell(ent.title),
                "platform": _sanitize_csv_formula_cell(ent.platform),
                "username": _sanitize_csv_formula_cell(ent.username),
                "password": ent.password,
                "totp_secret": ent.totp_secret,
                "url": ent.url,
                "phone": ent.phone,
                "recovery_email": ent.recovery_email,
                "tags": ", ".join(ent.tags),
                "favorite": "1" if ent.favorite else "0",
                "two_fa_recovery": ent.two_fa_recovery,
                "notes": ent.notes,
                "updated_at": ent.updated_at,
            }
        )
    return buf.getvalue()
