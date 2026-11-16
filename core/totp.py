from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

BASE32_CLEAN_RE = re.compile(r"[\s\-]+")
OTPAUTH_URI_RE = re.compile(r"otpauth://totp/[^\s`'\"<>]+", re.IGNORECASE)
LABELED_TOTP_LINE_RE = re.compile(
    r"^(?:totp|otp|2fa\s*secret|2fa\s*密钥|动态码|动态口令|密钥种子|secret)\s*[:：=]\s*(.+)$",
    re.IGNORECASE,
)
STRICT_BASE32_RE = re.compile(r"^[A-Za-z2-7]+=*$")


def extract_totp_from_text(raw_text: str) -> Optional[str]:
    """
    Attempt to recognize a valid TOTP secret or otpauth:// URI from freeform 2FA text
    (such as legacy entries where users stored their TOTP seed inside two_fa_recovery).
    Returns the normalized TOTP config string if found, or None if the text looks like
    ordinary backup recovery codes.
    """
    text = (raw_text or "").strip()
    if not text:
        return None

    # 1. Explicit otpauth://totp/... URI anywhere in text
    uri_match = OTPAUTH_URI_RE.search(text)
    if uri_match:
        candidate_uri = uri_match.group(0)
        try:
            parse_totp_config(candidate_uri)
            return candidate_uri
        except ValueError:
            pass

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    # 2. Explicitly labeled line in multiline 2FA field (e.g. "TOTP: JBSWY3DPEHPK3PXP")
    for ln in lines:
        m = LABELED_TOTP_LINE_RE.match(ln)
        if m:
            val = m.group(1).strip().strip("`")
            cleaned = BASE32_CLEAN_RE.sub("", val)
            if len(cleaned) >= 10 and not cleaned.isdigit() and STRICT_BASE32_RE.match(cleaned):
                try:
                    parse_totp_config(val)
                    return val
                except ValueError:
                    pass

    # 3. Single-line raw Base32 seed (e.g. "JBSWY3DPEHPK3PXP" or "jbsw y3dp ehpk 3pxp")
    if len(lines) == 1 and "/" not in lines[0] and "," not in lines[0]:
        single = lines[0].strip("`")
        cleaned = BASE32_CLEAN_RE.sub("", single)
        if len(cleaned) >= 12 and not cleaned.isdigit() and STRICT_BASE32_RE.match(cleaned):
            try:
                parse_totp_config(single)
                return single
            except ValueError:
                pass

    # 4. Multiline unified 2FA field where one line is a >=16-char raw Base32 TOTP seed
    #    (without hyphens/slashes) alongside backup recovery codes on other lines
    for ln in lines:
        if "/" in ln or "," in ln or "-" in ln:
            continue
        cand = ln.strip("`")
        cleaned = re.sub(r"\s+", "", cand)
        if len(cleaned) >= 16 and not cleaned.isdigit() and STRICT_BASE32_RE.match(cleaned):
            try:
                parse_totp_config(cand)
                return cand
            except ValueError:
                pass

    return None


def has_extra_recovery_beyond_totp(raw_text: str) -> bool:
    """
    Return True if raw_text contains non-TOTP backup recovery info (either no TOTP seed was found,
    or multiple non-empty lines exist alongside the TOTP seed).
    """
    text = (raw_text or "").strip()
    if not text:
        return False
    extracted = extract_totp_from_text(text)
    if not extracted:
        return True
    non_empty_lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return len(non_empty_lines) > 1


def parse_totp_config(raw: str) -> Tuple[bytes, int, int, str]:
    """
    Parse a raw Base32 TOTP secret or an otpauth://totp/... URI.
    Returns (secret_bytes, digits, period, algorithm_name).
    Raises ValueError if invalid.
    """
    text = (raw or "").strip()
    if not text:
        raise ValueError("TOTP 密钥为空")

    digits = 6
    period = 30
    algo = "SHA1"
    secret_str = text

    if text.lower().startswith("otpauth://"):
        parsed = urlparse(text)
        if parsed.netloc.lower() != "totp":
            raise ValueError("仅支持 otpauth://totp/ 类型的动态验证码链接")
        qs = parse_qs(parsed.query)
        secret_list = qs.get("secret") or qs.get("SECRET")
        if not secret_list or not secret_list[0].strip():
            raise ValueError("otpauth:// 链接中缺少 secret 参数")
        secret_str = secret_list[0].strip()

        if "digits" in qs and qs["digits"]:
            try:
                digits = int(qs["digits"][0])
            except ValueError as exc:
                raise ValueError("otpauth:// 链接中的 digits 参数无效") from exc
            if digits not in (6, 7, 8):
                raise ValueError("TOTP 验证码位数仅支持 6–8 位")

        if "period" in qs and qs["period"]:
            try:
                period = int(qs["period"][0])
            except ValueError as exc:
                raise ValueError("otpauth:// 链接中的 period 参数无效") from exc
            if period < 10 or period > 120:
                raise ValueError("TOTP 刷新周期需在 10–120 秒之间")

        if "algorithm" in qs and qs["algorithm"]:
            algo = qs["algorithm"][0].strip().upper()
            if algo not in ("SHA1", "SHA256", "SHA512"):
                raise ValueError(f"不支持的 TOTP 哈希算法: {algo}")

    cleaned_b32 = BASE32_CLEAN_RE.sub("", secret_str).upper().rstrip("=")
    if not cleaned_b32:
        raise ValueError("TOTP Base32 密钥不能为空")

    # Pad to multiple of 8 for standard RFC 4648 Base32 decoding
    pad_len = (-len(cleaned_b32)) % 8
    padded = cleaned_b32 + ("=" * pad_len)
    try:
        secret_bytes = base64.b32decode(padded, casefold=True)
    except Exception as exc:
        raise ValueError("无效的 TOTP 密钥格式（请填写有效的 Base32 密钥或 otpauth:// 链接）") from exc

    if len(secret_bytes) == 0:
        raise ValueError("TOTP 解码密钥长度无效")

    return secret_bytes, digits, period, algo


def generate_totp_token(
    raw_secret: str, timestamp: Optional[float] = None
) -> Dict[str, Any]:
    """
    Compute current RFC 6238 TOTP code and countdown metadata.
    """
    secret_bytes, digits, period, algo = parse_totp_config(raw_secret)
    now_ts = time.time() if timestamp is None else float(timestamp)
    if now_ts < 0:
        raise ValueError("时间戳不能为负数")

    counter = int(now_ts) // period
    remaining = period - (int(now_ts) % period)

    digest_mod = {
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }[algo]

    msg = struct.pack(">Q", counter)
    mac = hmac.new(secret_bytes, msg, digest_mod).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    otp_int = binary % (10**digits)
    code = str(otp_int).zfill(digits)

    return {
        "code": code,
        "digits": digits,
        "period": period,
        "remaining": remaining,
        "algorithm": algo,
    }
