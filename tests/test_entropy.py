import math
import pytest
from keyhound.entropy import shannon_entropy, high_entropy_tokens


def test_entropy_zero_for_single_char():
    assert shannon_entropy("aaaa") == 0.0


def test_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_entropy_max_for_all_unique():
    s = "abcdefghijklmnop"  # 16 unique chars
    assert shannon_entropy(s) == pytest.approx(math.log2(16), abs=0.01)


def test_high_entropy_detects_random_token():
    # 31 unique chars → entropy ≈ 4.95, well above threshold
    # Use quote separator so the = sign doesn't merge prefix into the token
    token = "p8yKxH2mNqLvRs7TwBjAeF3dCzYo1Ug"
    result = high_entropy_tokens(f'TOKEN="{token}"')
    assert token in result


def test_high_entropy_ignores_low_entropy():
    assert high_entropy_tokens("a" * 25) == []


def test_high_entropy_ignores_short_tokens():
    assert high_entropy_tokens("aB3xKp") == []


def test_high_entropy_ignores_space_separated_words():
    # Short words can't reach the 20-char minimum as individual tokens
    assert high_entropy_tokens("the quick brown fox jumps over the lazy dog") == []


def test_high_entropy_detects_hex_secret():
    # Each hex digit appears exactly twice → entropy = log2(16) = 4.0 > HEX threshold 3.5
    # Use colon separator (not in token charset) so prefix doesn't merge
    hex_secret = "0123456789abcdef0123456789abcdef"
    result = high_entropy_tokens(f"hash:{hex_secret}")
    assert hex_secret in result


def test_high_entropy_no_duplicate_on_repeated_call():
    token = "p8yKxH2mNqLvRs7TwBjAeF3dCzYo1Ug"
    r1 = high_entropy_tokens(token)
    r2 = high_entropy_tokens(token)
    assert r1 == r2
