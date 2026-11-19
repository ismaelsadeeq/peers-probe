"""Integration test: handshake the local running node as ground truth.

The patched node runs on 127.0.0.1:8333 and we KNOW its user agent
(/Satoshi:32.99.0.../), so a correct handshake must recover it.

Run:  python3 -m unittest -v test_integration
Skips automatically if no node is listening on 127.0.0.1:8333.
"""
import socket, unittest
import peer_probe as pp

HOST, PORT = "127.0.0.1", 8333


def _node_up():
    try:
        s = socket.create_connection((HOST, PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


@unittest.skipUnless(_node_up(), "no local node on 127.0.0.1:8333")
class TestLocalHandshake(unittest.TestCase):
    def test_handshake_recovers_our_user_agent(self):
        r = pp.handshake(HOST, PORT, timeout=5)
        self.assertIsNone(r["error"], r["error"])
        self.assertTrue(r["ok"])
        self.assertTrue(r["user_agent"].startswith("/Satoshi:"),
                        f"unexpected UA: {r['user_agent']}")
        self.assertGreater(r["version"], 70000)
        self.assertIn("service_names", r)

    def test_headers_speed_probe(self):
        r = pp.handshake(HOST, PORT, timeout=8, do_headers=True)
        self.assertIsNone(r["error"], r["error"])
        self.assertIn("headers_count", r)
        self.assertGreater(r["headers_count"], 0)
        self.assertIn("headers_ms", r)

    def test_ping_rtt_probe(self):
        r = pp.handshake(HOST, PORT, timeout=8, do_ping=True)
        self.assertIsNone(r["error"], r["error"])
        self.assertIn("ping_ms", r)          # pong echoed our nonce back
        self.assertGreaterEqual(r["ping_ms"], 0)
        self.assertLess(r["ping_ms"], 1000)  # loopback RTT is tiny


if __name__ == "__main__":
    unittest.main()
