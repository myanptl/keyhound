import math
import re
from collections import Counter

_HEX_CHARS = set("0123456789abcdefABCDEF")
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")

B64_ENTROPY_THRESHOLD = 4.5
HEX_ENTROPY_THRESHOLD = 3.5


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def high_entropy_tokens(line: str) -> list[str]:
    """Return tokens from `line` that look like high-entropy secrets."""
    results = []
    for token in _TOKEN_RE.findall(line):
        charset = set(token)
        if charset <= _HEX_CHARS:
            if shannon_entropy(token) >= HEX_ENTROPY_THRESHOLD:
                results.append(token)
        elif shannon_entropy(token) >= B64_ENTROPY_THRESHOLD:
            results.append(token)
    return results
