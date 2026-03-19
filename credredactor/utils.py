"""
Utility functions: entropy calculation and file encoding detection.

Addresses: #16 (encoding detection), #28 (optimized entropy)
"""

import math
from collections import Counter


def entropy(s: str) -> float:
    """Shannon entropy in bits per character (optimized with Counter)."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in Counter(s).values())


def detect_encoding(filepath: str) -> str:
    """Detect the encoding of a file, falling back to utf-8.

    Tries charset_normalizer first, then chardet, then falls back to utf-8.
    """
    raw = b''
    try:
        with open(filepath, 'rb') as fh:
            raw = fh.read(8192)
    except (OSError, PermissionError):
        return 'utf-8'

    if not raw:
        return 'utf-8'

    # Try charset_normalizer (lighter, no C deps)
    try:
        import charset_normalizer
        result = charset_normalizer.from_bytes(raw).best()
        if result and result.encoding:
            return result.encoding
    except ImportError:
        pass

    # Try chardet
    try:
        import chardet
        det = chardet.detect(raw)
        if det and det.get('encoding') and det.get('confidence', 0) > 0.7:
            return det['encoding']
    except ImportError:
        pass

    # Heuristic: try to decode as utf-8
    try:
        raw.decode('utf-8')
        return 'utf-8'
    except UnicodeDecodeError:
        pass

    # Try latin-1 as a last resort (it never fails, but may be wrong)
    return 'latin-1'


def mask_secret(value: str, visible: int = 4) -> str:
    """Mask a secret value, showing only the first `visible` characters."""
    if len(value) <= visible:
        return '[REDACTED]'
    return value[:visible] + '[REDACTED]'
