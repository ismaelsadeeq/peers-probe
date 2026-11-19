# test_cve_2024_35202.py
"""
Verification tests for CVE-2024-35202 (blocktxn assertion crash, High, fixed v25.0).

Two layers:
  1. Registry/record tests - the CVE entry tuple is well-formed and self-consistent.
  2. Behavioural regression test - models PartiallyDownloadedBlock and asserts that a
     second FillBlock() on the same instance no longer trips the assert.

Run:  pytest test_cve_2024_35202.py -v
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Optional, Sequence

import pytest

CVE_RECORD = (
    "CVE-2024-35202",
    "blocktxn assertion crash (High)",
    25,
    "PARTIAL",
    "PR #26898 (v25.0)",
)

CVE_ID, TITLE, FIXED_VERSION, STATUS, FIX_REF = CVE_RECORD

ALLOWED_STATUS = {"FIXED", "PARTIAL", "VULNERABLE", "UNPATCHED"}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


def test_record_shape():
    assert isinstance(CVE_RECORD, tuple)
    assert len(CVE_RECORD) == 5
    assert all(isinstance(x, str) for x in (CVE_ID, TITLE, STATUS, FIX_REF))
    assert isinstance(FIXED_VERSION, int)


def test_cve_id_is_wellformed():
    assert re.fullmatch(r"CVE-\d{4}-\d{4,7}", CVE_ID), CVE_ID


def test_severity_is_valid_and_high():
    m = re.search(r"\(([A-Za-z]+)\)\s*$", TITLE)
    assert m, f"no severity tag in title: {TITLE!r}"
    severity = m.group(1)
    assert severity in VALID_SEVERITIES
    assert severity == "High"


def test_title_describes_blocktxn_assertion():
    low = TITLE.lower()
    assert "blocktxn" in low
    assert "assertion" in low


def test_fixed_version_is_the_v25_series():
    assert FIXED_VERSION == 25
    assert FIXED_VERSION >= 25


def test_status_is_known():
    assert STATUS in ALLOWED_STATUS


def test_fix_reference_format():
    m = re.fullmatch(r"PR #(\d+) \(v(\d+)\.(\d+)\)", FIX_REF)
    assert m, FIX_REF
    pr_number = int(m.group(1))
    ref_major = int(m.group(2))
    assert pr_number > 0
    assert ref_major == FIXED_VERSION


def test_high_severity_requires_a_fix_reference():
    severity = re.search(r"\(([A-Za-z]+)\)\s*$", TITLE).group(1)
    if severity == "High":
        assert FIX_REF.strip()
        assert FIX_REF.startswith("PR #")


def test_partial_status_is_consistent():
    if STATUS == "PARTIAL":
        assert FIX_REF, "PARTIAL entries must document the applied fix"
        assert re.search(r"\(v\d+\.\d+\)", FIX_REF)


def test_known_public_facts():
    assert CVE_ID == "CVE-2024-35202"
    assert FIXED_VERSION == 25
    assert "26898" in FIX_REF


class ReadStatus(Enum):
    OK = "ok"
    INVALID = "invalid"
    FAILED = "failed"


class _PdbBase:
    def __init__(self, header: Optional[str], txn_available: Sequence[Optional[str]]):
        self.header = header
        self.txn_available = list(txn_available)

    def _reconstruct_and_clear(self):
        self.header = None
        self.txn_available = []


class VulnerablePdb(_PdbBase):
    def fill_block(self, vtx_missing, *, merkle_valid: bool) -> ReadStatus:
        assert self.header is not None, "assert(!header.IsNull())"
        self._reconstruct_and_clear()
        return ReadStatus.OK if merkle_valid else ReadStatus.FAILED


class FixedPdb(_PdbBase):
    def fill_block(self, vtx_missing, *, merkle_valid: bool) -> ReadStatus:
        if self.header is None:
            return ReadStatus.INVALID
        self._reconstruct_and_clear()
        return ReadStatus.OK if merkle_valid else ReadStatus.FAILED


def _attack_sequence(pdb_cls):
    pdb = pdb_cls(header="block-header", txn_available=[None, None])
    first = pdb.fill_block(["tx-missing"], merkle_valid=False)
    second = pdb.fill_block(["tx-missing"], merkle_valid=False)
    return first, second


def test_vulnerable_impl_asserts_on_second_fillblock():
    pdb = VulnerablePdb(header="h", txn_available=[None])
    assert pdb.fill_block([], merkle_valid=False) == ReadStatus.FAILED
    with pytest.raises(AssertionError):
        pdb.fill_block([], merkle_valid=False)


def test_fixed_impl_returns_invalid_on_second_fillblock():
    first, second = _attack_sequence(FixedPdb)
    assert first == ReadStatus.FAILED
    assert second == ReadStatus.INVALID


def test_fix_is_actually_observable():
    with pytest.raises(AssertionError):
        _attack_sequence(VulnerablePdb)
    f_first, f_second = _attack_sequence(FixedPdb)
    assert f_first == ReadStatus.FAILED
    assert f_second == ReadStatus.INVALID
