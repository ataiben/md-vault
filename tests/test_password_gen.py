import string

from core.password_gen import AMBIGUOUS_CHARS, SYMBOLS_SET, generate_password


def test_password_generator_character_sets_and_ambiguous_exclusion():
    for _ in range(30):
        pwd = generate_password(
            length=22,
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_symbols=True,
            exclude_ambiguous=True,
        )
        assert len(pwd) == 22
        assert any(c in string.ascii_uppercase for c in pwd)
        assert any(c in string.ascii_lowercase for c in pwd)
        assert any(c in string.digits for c in pwd)
        assert any(c in SYMBOLS_SET for c in pwd)
        assert not any(c in AMBIGUOUS_CHARS for c in pwd)


def test_password_generator_bounds():
    short_pwd = generate_password(length=2)
    assert len(short_pwd) == 6  # Minimum clamped to 6

    digits_only = generate_password(
        length=12,
        use_upper=False,
        use_lower=False,
        use_digits=True,
        use_symbols=False,
        exclude_ambiguous=False,
    )
    assert len(digits_only) == 12
    assert all(c in string.digits for c in digits_only)
