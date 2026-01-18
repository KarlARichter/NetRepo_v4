import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import socket
import unittest
from protocol import send_json, recv_json

class TestProtocol(unittest.TestCase):
    def test_send_recv_roundtrip(self):
        a, b = socket.socketpair()
        try:
            send_json(a, {"cmd":"PING","args":[1,2,3]})
            msg = recv_json(b)
            self.assertEqual(msg["cmd"], "PING")
            self.assertEqual(msg["args"], [1,2,3])
        finally:
            a.close()
            b.close()

if __name__ == "__main__":
    unittest.main()
