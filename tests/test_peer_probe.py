"""Unit tests for peer_probe pure functions. No network required.

Run:  python3 -m unittest -v test_peer_probe
The integration test against a local node is in test_integration.py.
"""
import io, struct, unittest
import peer_probe as pp


class TestCompactSize(unittest.TestCase):
    def test_roundtrip_and_boundaries(self):
        for n in [0, 1, 0xFC, 0xFD, 0xFE, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000]:
            enc = pp.ser_compactsize(n)
            self.assertEqual(pp.deser_compactsize(io.BytesIO(enc)), n, f"n={n}")

    def test_encoding_widths(self):
        self.assertEqual(len(pp.ser_compactsize(0xFC)), 1)
        self.assertEqual(pp.ser_compactsize(0xFD)[:1], b"\xfd")
        self.assertEqual(len(pp.ser_compactsize(0xFD)), 3)
        self.assertEqual(pp.ser_compactsize(0x10000)[:1], b"\xfe")
        self.assertEqual(pp.ser_compactsize(0x100000000)[:1], b"\xff")


class TestHashing(unittest.TestCase):
    def test_sha256d_empty_known_vector(self):
        # double-SHA256 of empty input (well-known constant)
        self.assertEqual(
            pp.sha256d(b"").hex(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")


class TestFraming(unittest.TestCase):
    def test_make_and_parse_message(self):
        payload = b"hello world payload"
        raw = pp.make_message("version", payload)
        self.assertEqual(raw[:4], pp.MAINNET_MAGIC)
        self.assertEqual(raw[4:16], b"version".ljust(12, b"\x00"))
        self.assertEqual(struct.unpack("<I", raw[16:20])[0], len(payload))
        f = io.BytesIO(raw)
        cmd, pl = pp.parse_message(lambda n: f.read(n))
        self.assertEqual(cmd, "version")
        self.assertEqual(pl, payload)

    def test_empty_payload_message(self):
        raw = pp.make_message("verack", b"")
        f = io.BytesIO(raw)
        cmd, pl = pp.parse_message(lambda n: f.read(n))
        self.assertEqual((cmd, pl), ("verack", b""))

    def test_bad_checksum_rejected(self):
        raw = bytearray(pp.make_message("version", b"abc"))
        raw[20] ^= 0xFF  # corrupt checksum
        f = io.BytesIO(bytes(raw))
        with self.assertRaises(ValueError):
            pp.parse_message(lambda n: f.read(n))

    def test_bad_magic_rejected(self):
        raw = bytearray(pp.make_message("version", b"abc"))
        raw[0] ^= 0xFF
        f = io.BytesIO(bytes(raw))
        with self.assertRaises(ValueError):
            pp.parse_message(lambda n: f.read(n))


class TestVersion(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        payload = pp.build_version_payload(
            services=(1 << 0) | (1 << 3), user_agent="/test:1.0/",
            start_height=800000, relay=True, nonce=12345, timestamp=1700000000)
        v = pp.parse_version_payload(payload)
        self.assertEqual(v["user_agent"], "/test:1.0/")
        self.assertEqual(v["services"], 9)
        self.assertEqual(sorted(v["service_names"]), ["NETWORK", "WITNESS"])
        self.assertEqual(v["start_height"], 800000)
        self.assertEqual(v["nonce"], 12345)
        self.assertEqual(v["timestamp"], 1700000000)
        self.assertTrue(v["relay"])

    def test_missing_relay_byte_defaults_true(self):
        payload = pp.build_version_payload(user_agent="/x/")[:-1]  # drop relay
        v = pp.parse_version_payload(payload)
        self.assertTrue(v["relay"])


class TestServiceDecode(unittest.TestCase):
    def test_core_and_noncore(self):
        self.assertEqual(pp.decode_services(0), ["NONE"])
        self.assertIn("NETWORK", pp.decode_services(1 << 0))
        self.assertIn("UTREEXO", pp.decode_services(1 << 12))
        self.assertIn("LIBRE_RELAY", pp.decode_services(1 << 29))
        names = pp.decode_services((1 << 3) | (1 << 10) | (1 << 11))
        self.assertEqual(sorted(names), ["NETWORK_LIMITED", "P2P_V2", "WITNESS"])

    def test_unknown_bit_reported(self):
        self.assertIn("other(0x20)", pp.decode_services(1 << 5))


class TestGetData(unittest.TestCase):
    def test_getdata_payload_structure(self):
        h = bytes(range(32))
        p = pp.build_getdata_payload([(pp.MSG_WITNESS_BLOCK, h)])
        self.assertEqual(len(p), 1 + 4 + 32)          # count + type + hash
        self.assertEqual(p[0], 1)                      # one inv
        self.assertEqual(p[1:5], struct.pack("<I", pp.MSG_WITNESS_BLOCK))
        self.assertEqual(p[5:37], h)

    def test_witness_flag_value(self):
        self.assertEqual(pp.MSG_WITNESS_BLOCK, pp.MSG_BLOCK | 0x40000000)


class TestPing(unittest.TestCase):
    def test_ping_payload_is_8_byte_nonce(self):
        p = pp.build_ping_payload()
        self.assertEqual(len(p), 8)
        self.assertEqual(struct.unpack("<Q", p)[0], pp.PING_NONCE)

    def test_pong_nonce_roundtrips(self):
        self.assertEqual(pp.parse_pong_nonce(pp.build_ping_payload(1234)), 1234)
        self.assertIsNone(pp.parse_pong_nonce(b"\x00" * 4))   # short payload -> None


class TestNetAddr(unittest.TestCase):
    def test_ipv4_mapped(self):
        b = pp.ser_netaddr(0, "1.2.3.4", 8333)
        self.assertEqual(len(b), 26)
        self.assertEqual(b[8:18].hex(), "00000000000000000000")  # 10 zero bytes
        self.assertEqual(b[18:20], b"\xff\xff")
        self.assertEqual(b[20:24], bytes([1, 2, 3, 4]))
        self.assertEqual(b[24:26], struct.pack(">H", 8333))

    def test_none_is_zero(self):
        self.assertEqual(pp.ser_netaddr(0, None, 0)[8:24], b"\x00" * 16)


class TestCrossCheckCoreFramework(unittest.TestCase):
    """Cross-validate against Bitcoin Core's own test framework, if importable."""
    @classmethod
    def setUpClass(cls):
        import sys, os
        # point at a Bitcoin Core checkout's functional test framework via env:
        #   BITCOIN_FUNCTIONAL_TEST=/path/to/bitcoin/test/functional
        fdir = os.environ.get("BITCOIN_FUNCTIONAL_TEST")
        if not fdir:
            raise unittest.SkipTest("set BITCOIN_FUNCTIONAL_TEST to Core's test/functional")
        sys.path.insert(0, fdir)
        try:
            from test_framework import messages as m  # noqa
            cls.m = m
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"test_framework unavailable: {e}")

    def test_compactsize_matches_core(self):
        for n in [0, 1, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000]:
            self.assertEqual(pp.ser_compactsize(n), self.m.ser_compact_size(n),
                             f"n={n}")

    def test_sha256d_matches_core_hash256(self):
        for data in [b"", b"abc", b"\x00" * 32, bytes(range(50))]:
            self.assertEqual(pp.sha256d(data), self.m.hash256(data))


if __name__ == "__main__":
    unittest.main()
