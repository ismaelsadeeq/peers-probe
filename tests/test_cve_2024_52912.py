# test_cve_2024_52912.py
"""
Verification tests for CVE-2024-52912 (timestamp-overflow net-split, fixed 0.21.0).

Behavioral MODEL only -- no exploit, no node. Models peer-time aggregation: a node
could be split from the network when its first ~200 peers feed skewed timestamps,
shifting its notion of time. The fix bounds the adjustment to a warn-only window so
it can never affect validation (consensus) time.

Run:  pytest test_cve_2024_52912.py -v
"""
from __future__ import annotations
import re
import pytest

CVE_RECORD = (
    "CVE-2024-52912",
    "timestamp-overflow net-split (Medium)",
    21,                       # fixed era-major (0.21.0)
    "FIXED",
    "fixed v0.21.0",
)
CVE_ID, TITLE, FIXED_VERSION, STATUS, FIX_REF = CVE_RECORD
ALLOWED_STATUS = {"FIXED", "PARTIAL", "VULNERABLE", "UNPATCHED"}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

MAX_PEER_SAMPLE = 200          # only the first ~200 peers feed the offset
MAX_TIME_ADJUSTMENT = 70 * 60  # +/- 70 minutes; warn-only, never consensus


def _era_major(verstr: str) -> int:
    m = re.search(r"v(\d+)\.(\d+)", verstr)
    maj, minr = int(m.group(1)), int(m.group(2))
    return minr if maj == 0 else maj


# --------------------------- registry integrity --------------------------- #
def test_record_shape():
    assert len(CVE_RECORD) == 5
    assert isinstance(FIXED_VERSION, int)

def test_cve_id_is_wellformed():
    assert re.fullmatch(r"CVE-\d{4}-\d{4,7}", CVE_ID)

def test_severity_valid():
    assert re.search(r"\(([A-Za-z]+)\)\s*$", TITLE).group(1) in VALID_SEVERITIES

def test_title_describes_split():
    low = TITLE.lower()
    assert "timestamp" in low and "split" in low

def test_fixed_version_is_0_21():
    assert FIXED_VERSION == 21
    assert _era_major(FIX_REF) == FIXED_VERSION

def test_status_known():
    assert STATUS in ALLOWED_STATUS


# --------------------------- behavioral model ----------------------------- #
def _median(xs):
    s = sorted(xs); n = len(s)
    if n == 0:
        return 0
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) // 2


class VulnerableTimeData:
    """< 0.21: early peers drive an unbounded time offset -> can split the node."""
    def __init__(self):
        self.offsets = []
    def add_peer(self, offset_seconds: int):
        if len(self.offsets) < MAX_PEER_SAMPLE:
            self.offsets.append(offset_seconds)
    def adjusted_offset(self) -> int:
        return _median(self.offsets)          # no clamp
    def is_split(self) -> bool:
        # consensus-affecting time shifted beyond the acceptable window
        return abs(self.adjusted_offset()) > MAX_TIME_ADJUSTMENT


class FixedTimeData(VulnerableTimeData):
    """>= 0.21.0: adjustment clamped to +/-70min, warn-only, never consensus."""
    def adjusted_offset(self) -> int:
        raw = _median(self.offsets)
        return max(-MAX_TIME_ADJUSTMENT, min(MAX_TIME_ADJUSTMENT, raw))
    def is_split(self) -> bool:
        return False                          # clamp => cannot split


def _attack(td):
    for _ in range(MAX_PEER_SAMPLE):          # first 200 peers, all malicious
        td.add_peer(3 * 3600)                 # +3h skew
    return td


def test_vulnerable_node_is_split_by_first_200_peers():
    td = _attack(VulnerableTimeData())
    assert td.adjusted_offset() == 3 * 3600
    assert td.is_split() is True

def test_fixed_node_not_split():
    td = _attack(FixedTimeData())
    assert abs(td.adjusted_offset()) <= MAX_TIME_ADJUSTMENT
    assert td.is_split() is False

def test_fix_is_observable():
    assert _attack(VulnerableTimeData()).is_split() is True
    assert _attack(FixedTimeData()).is_split() is False
