# test_cve_2024_52919.py
"""
Verification tests for CVE-2024-52919 (addrman 32-bit id overflow, Low, fixed v29.0).

Behavioral MODEL only -- no exploit, no node, no trigger payload. Models the
addrman nid counter: the vulnerable type is 32-bit and asserts at the boundary;
the v29.0 fix (PR #30568) uses a 64-bit id; and the v22 addr rate-limiting makes
reaching 2**32 impractical even without the type change.

Run:  pytest test_cve_2024_52919.py -v
"""
from __future__ import annotations
import re
import pytest

CVE_RECORD = (
    "CVE-2024-52919",
    "addrman 32-bit id overflow (Low)",
    29,                       # fixed era-major
    "FIXED",
    "PR #30568 (v29.0)",
)
CVE_ID, TITLE, FIXED_VERSION, STATUS, FIX_REF = CVE_RECORD
ALLOWED_STATUS = {"FIXED", "PARTIAL", "VULNERABLE", "UNPATCHED"}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
INT32_MAX = 2**31 - 1


def _era_major(verstr: str) -> int:
    m = re.search(r"v(\d+)\.(\d+)", verstr)
    maj, minr = int(m.group(1)), int(m.group(2))
    return minr if maj == 0 else maj


# --------------------------- registry integrity --------------------------- #
def test_record_shape():
    assert len(CVE_RECORD) == 5
    assert all(isinstance(x, str) for x in (CVE_ID, TITLE, STATUS, FIX_REF))
    assert isinstance(FIXED_VERSION, int)

def test_cve_id_is_wellformed():
    assert re.fullmatch(r"CVE-\d{4}-\d{4,7}", CVE_ID), CVE_ID

def test_severity_valid():
    sev = re.search(r"\(([A-Za-z]+)\)\s*$", TITLE).group(1)
    assert sev in VALID_SEVERITIES

def test_title_describes_overflow():
    low = TITLE.lower()
    assert "addrman" in low and "overflow" in low

def test_fixed_version_is_29():
    assert FIXED_VERSION == 29

def test_status_known():
    assert STATUS in ALLOWED_STATUS

def test_fix_reference_matches_version():
    assert FIX_REF.startswith("PR #")
    assert _era_major(FIX_REF) == FIXED_VERSION

def test_known_public_facts():
    assert CVE_ID == "CVE-2024-52919"
    assert "30568" in FIX_REF


# --------------------------- behavioral model ----------------------------- #
class VulnerableAddrMan:
    """< v29: nId is a 32-bit identifier; wraps/asserts past INT32_MAX."""
    def __init__(self, start: int = 0):
        self._next = start
    def new_id(self) -> int:
        assert self._next <= INT32_MAX, "assert(nId fits int32)"  # <-- overflow crash
        nid = self._next
        self._next += 1
        return nid


class FixedAddrMan:
    """>= v29.0 (PR #30568): 64-bit identifier, no practical overflow."""
    def __init__(self, start: int = 0):
        self._next = start
    def new_id(self) -> int:
        nid = self._next            # int is unbounded in python; models int64
        self._next += 1
        return nid


def years_to_overflow(peers: int, adds_per_peer_per_sec: float) -> float:
    """v22+ rate-limiting: time to push a 32-bit counter to overflow."""
    per_sec = max(peers * adds_per_peer_per_sec, 1e-9)
    return (2**32) / per_sec / (365 * 24 * 3600)


def test_vulnerable_asserts_at_32bit_boundary():
    am = VulnerableAddrMan(start=INT32_MAX)
    assert am.new_id() == INT32_MAX          # last valid id
    with pytest.raises(AssertionError):
        am.new_id()                          # overflow -> crash

def test_fixed_passes_the_boundary():
    am = FixedAddrMan(start=INT32_MAX)
    assert am.new_id() == INT32_MAX
    assert am.new_id() == INT32_MAX + 1      # no assert, 64-bit

def test_rate_limit_makes_overflow_impractical():
    # advisory: ~1000 peers attacking continuously would still take > 1 year
    assert years_to_overflow(peers=1000, adds_per_peer_per_sec=0.1) > 1.0

def test_fix_is_observable():
    with pytest.raises(AssertionError):
        VulnerableAddrMan(start=INT32_MAX + 1).new_id()
    assert FixedAddrMan(start=INT32_MAX + 1).new_id() == INT32_MAX + 1
