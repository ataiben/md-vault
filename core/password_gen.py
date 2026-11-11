from __future__ import annotations

import secrets
import string

AMBIGUOUS_CHARS = set("0O1lI|")
SYMBOLS_SET = "!@#$%^&*()-_=+[]{};:,.?"


def generate_password(
    length: int = 18,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = True,
) -> str:
    """
    Generate a cryptographically strong random password guaranteeing at least
    one character from each enabled character group.
    """
    length = max(6, min(128, int(length)))

    pools: list[str] = []
    if use_upper:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        pools.append(chars)
    if use_lower:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        pools.append(chars)
    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        pools.append(chars)
    if use_symbols:
        pools.append(SYMBOLS_SET)

    if not pools:
        # Fallback to lowercase + digits if all unchecked
        pools = [
            "".join(c for c in string.ascii_lowercase if c not in AMBIGUOUS_CHARS),
            "".join(c for c in string.digits if c not in AMBIGUOUS_CHARS),
        ]

    required_chars = [secrets.choice(pool) for pool in pools if pool]
    all_chars = "".join(pools)
    remaining_len = max(0, length - len(required_chars))
    result = required_chars + [secrets.choice(all_chars) for _ in range(remaining_len)]

    # Cryptographically shuffle using SystemRandom
    secrets.SystemRandom().shuffle(result)
    return "".join(result[:length])
