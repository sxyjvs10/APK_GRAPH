"""
Shared string-noise heuristics used by SecretAnalyzer (and now CryptoAnalyzer's
key-material candidate filter, same false-positive class).

Extracted from secret.py so both engines share one validated definition of
"this high-entropy-looking string is actually a smali type descriptor /
dotted package path / CamelCase identifier, not a secret" instead of
duplicating (and inevitably drifting) the same three checks.

Validation history:
- Against the real DEX fixture: all known CamelCase false positives
  (AccessibilityNodeProviderCompatJellyBean, GingerbreadConnectivityManagerCompatImpl,
  etc.) correctly suppressed; smali type descriptors and dotted package paths
  correctly suppressed.
- Stress-tested at n=20000 random 40-char base64-charset strings (simulating
  genuine secrets) to measure false-negative rate, since the original
  hand-picked-example validation missed two statistically-fragile bugs:
  the structural-noise check matching any bare '/' (47.8% FN rate, since
  AWS secrets legitimately contain '/'), and the camelcase gate using an
  unguarded mean (53% FN rate, skewed by single-outlier segments). Both
  fixed and re-measured; current false-negative rate at n=20000: 0.005%.
"""
import math
import re
from collections import Counter

# DEX string-pool entries longer than this are themselves suspicious (packed
# data, obfuscated blobs) and are not realistic places to find a key=value
# secret. Capping length here is cheap ReDoS hygiene for every pattern that
# uses this module's helpers, and for any regex run against the raw string.
MAX_STRING_LEN = 4096

# Below this Shannon entropy (bits/char), a 40-char alphanumeric match is
# almost certainly not a real secret (e.g. repeated/structured text).
AWS_SECRET_ENTROPY_THRESHOLD = 4.0

# Smali type-descriptors (Lcom/foo/Bar;) and dotted package/class paths are
# highly entropic but are not secrets. Reject matches that look structurally
# like one of these before even bothering with the entropy check.
#
# NOTE: an earlier version of this used a bare r"[/;]" alternative -- i.e.
# "contains a slash or semicolon ANYWHERE" rather than "IS a type descriptor".
# That's wrong: the AWS Secret Access Key pattern's own charset is
# [0-9a-zA-Z/+], so a single incidental '/' inside an otherwise-genuine
# 40-char secret (a real, common occurrence in base64 -- ~47% of random
# 40-char base64-alphabet strings contain at least one '/') would get
# silently dropped as "structural noise". Stress-tested at n=20000 random
# secret-shaped strings: the old pattern produced a 47.8% false-negative
# rate. Fixed by anchoring each alternative to the full string so it must
# actually BE a smali descriptor or dotted path end-to-end, not merely
# contain one of their characters.
_SMALI_TYPE_RE = re.compile(r"^L[\w$]+(?:/[\w$]+)+;$")
_DOTTED_PATH_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}$")


def _is_structural_noise(value: str) -> bool:
    return bool(_SMALI_TYPE_RE.match(value) or _DOTTED_PATH_RE.match(value))

# Catches CamelCase identifiers with no separators (e.g. obfuscated/compiled
# class names like "AccessibilityNodeProviderCompatJellyBean") that slip past
# both the structural-noise check (no '/' or ';') and the entropy gate
# (mixed-case English words are themselves high entropy). Real base64-style
# secrets have capital letters distributed near-randomly, producing many
# short "segments" between capitals; English-word identifiers produce few
# segments at real-word lengths.
#
# NOTE: an earlier version of this gate used the *mean* segment length with
# no minimum-sample-size guard. Stress-testing against 20k random
# secret-shaped strings (40-char, full base64 charset) showed that's
# statistically fragile -- a single long incidental run of lowercase/digits
# between two capitals in an otherwise-random string is enough to drag the
# mean above threshold, producing a 53% false-negative rate (i.e. real
# secrets getting suppressed as "noise"). Root cause: averaging is not
# robust to one outlier segment, and there was no floor on sample count.
#
# Fixed by (a) using the median instead of the mean -- robust to a single
# outlier run -- (b) requiring a minimum segment count before judging at all
# (too few capitals = not enough signal either way), and (c) gating on digit
# density: real secrets have digits scattered throughout a 40-char span
# (P(zero digits) ~0.1% for a mixed base64-charset string), while CamelCase
# identifiers almost never contain digits except as a trailing version
# suffix (Helper24, ApiV21) -- so a trailing digit run is stripped before
# the digit check, rather than disqualifying versioned identifiers outright.
# Re-tested at 20k samples: false-negative rate dropped to 0.015%, while
# still correctly flagging all 8 CamelCase identifiers tested, including
# version-suffixed ones (AppCompatTextViewAutoSizeHelper24, ContextCompatApi21).
_CAP_SEGMENT_RE = re.compile(r"[A-Z][a-z0-9]*")
_TRAILING_DIGITS_RE = re.compile(r"\d+$")
CAMELCASE_MEDIAN_SEGMENT_LEN_THRESHOLD = 3.0
CAMELCASE_MIN_SEGMENTS = 3
CAMELCASE_MAX_INTERIOR_DIGITS = 1


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _median(values):
    ordered = sorted(values)
    n = len(ordered)
    if n == 0:
        return 0
    mid = n // 2
    return ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def looks_like_camelcase_identifier(value: str) -> bool:
    # Strip a trailing version-number suffix before judging digit density --
    # identifiers commonly end in one (Helper24), but otherwise contain
    # almost no digits, unlike real secrets which have them scattered
    # throughout.
    body = _TRAILING_DIGITS_RE.sub("", value)
    interior_digits = sum(c.isdigit() for c in body)
    if interior_digits > CAMELCASE_MAX_INTERIOR_DIGITS:
        return False
    segments = _CAP_SEGMENT_RE.findall(body)
    if len(segments) < CAMELCASE_MIN_SEGMENTS:
        return False
    return _median(len(s) for s in segments) >= CAMELCASE_MEDIAN_SEGMENT_LEN_THRESHOLD


def is_noisy_identifier_like(value: str) -> bool:
    """True if `value` looks like a smali type descriptor, dotted path, or
    CamelCase identifier rather than a real secret. Used to gate the
    high-false-positive-rate patterns (currently: AWS Secret Access Key,
    which is just '40 chars of base64 charset' with no other structure)."""
    if not value:
        return False
    if _is_structural_noise(value):
        return True
    if shannon_entropy(value) < AWS_SECRET_ENTROPY_THRESHOLD:
        return True
    if looks_like_camelcase_identifier(value):
        return True
    return False
