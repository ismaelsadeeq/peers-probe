# test_cve_2018_17144.py
"""
Verification tests for CVE-2018-17144 (duplicate-input block DoS/inflation,
Critical, fixed 0.16.3 / 0.17.0rc4, PR #14247).

Behavioral MODEL only -- no exploit, no node, no crafted block. Models block
validation: the vulnerable path skipped the duplicate-input check (an optimization),
so a block whose transaction spends the same input twice reached connect-time and
tripped an assertion (DoS); the fix always runs the check and rejects the block.

Run:  pytest test_cve_2018_17144.py -v
"""
from __future__ import annotations
import re
import pytest

CVE_RECORD = (
    "CVE-2018-17144",
    "duplicate-input block assert/inflation (Critical)",
    16,                       # fixed era-major (0.16.3)
    "FIXED",
    "PR #14247 (v0.16.3)",
)
CVE_ID, TITLE, FIXED_VERSION, STATUS, FIX_REF = CVE_RECORD
ALLOWED_STATUS = {"FIXED", "PARTIAL", "VULNERABLE", "UNPATCHED"}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


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

def test_severity_is_critical():
    assert re.search(r"\(([A-Za-z]+)\)\s*$", TITLE).group(1) == "Critical"

def test_title_describes_duplicate_input():
    low = TITLE.lower()
    assert "duplicate-input" in low or "duplicate" in low

def test_fixed_version_is_0_16():
    assert FIXED_VERSION == 16
    assert _era_major(FIX_REF) == FIXED_VERSION

def test_fix_reference_has_pr():
    assert "14247" in FIX_REF

def test_status_known():
    assert STATUS in ALLOWED_STATUS


# --------------------------- behavioral model ----------------------------- #
class Tx:
    def __init__(self, inputs, outputs):
        self.inputs = list(inputs)     # list of outpoint ids (str)
        self.outputs = list(outputs)


def _has_duplicate_inputs(tx: Tx) -> bool:
    return len(set(tx.inputs)) != len(tx.inputs)


class VulnerableValidator:
    """< 0.16.3: CheckBlock skipped the duplicate-input check (optimization).
    The malformed tx slips through and asserts at connect time."""
    def check_block(self, txs):
        # duplicate-input check intentionally NOT run here
        return "ok"
    def connect_block(self, txs):
        for tx in txs:
            if _has_duplicate_inputs(tx):
                assert False, "assert at UTXO disconnect (DoS / inflation)"  # crash
        return "connected"


class FixedValidator:
    """>= 0.16.3 (PR #14247): duplicate-input check always runs; block rejected."""
    def check_block(self, txs):
        for tx in txs:
            if _has_duplicate_inputs(tx):
                return "bad-txns-inputs-duplicate"   # rejected gracefully
        return "ok"
    def connect_block(self, txs):
        return "connected"


def _malicious_block():
    # a tx spending the same input ("A") twice -> would double-count value
    return [Tx(inputs=["A", "A"], outputs=["spend"])]


def test_vulnerable_crashes_on_duplicate_input_block():
    v = VulnerableValidator(); block = _malicious_block()
    assert v.check_block(block) == "ok"        # check passed (skipped)
    with pytest.raises(AssertionError):
        v.connect_block(block)                 # crash / inflation path

def test_fixed_rejects_duplicate_input_block():
    f = FixedValidator(); block = _malicious_block()
    assert f.check_block(block) == "bad-txns-inputs-duplicate"  # rejected, no crash

def test_fixed_still_accepts_honest_block():
    f = FixedValidator()
    assert f.check_block([Tx(inputs=["A", "B"], outputs=["spend"])]) == "ok"

def test_fix_is_observable():
    with pytest.raises(AssertionError):
        VulnerableValidator().connect_block(_malicious_block())
    assert FixedValidator().check_block(_malicious_block()) == "bad-txns-inputs-duplicate"
