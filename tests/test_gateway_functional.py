import importlib.util
import io
import json
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_gateway_module():
    spec = importlib.util.spec_from_file_location("gateway_app_test", ROOT / "gateway" / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeHeaders(dict):
    def get(self, key, default=None):
        return super().get(key, default)


class FakeGatewayHandler:
    def __init__(self, module, path: str):
        self.module = module
        self.path = path
        self.command = "GET"
        self.headers = FakeHeaders({"Host": "localhost", "User-Agent": "unit-test"})
        self.client_address = ("127.0.0.1", 0)
        self.response_code = None
        self.response_headers = {}
        self.wfile = io.BytesIO()

    def _client_ip(self):
        return self.client_address[0]

    def _event(self, event: str, decision: str, status: int):
        self.module.write_log(
            {
                "ts": self.module.now_iso(),
                "remote_addr": self._client_ip(),
                "method": self.command,
                "uri": self.path.split("?", 1)[0],
                "status": status,
                "event": event,
                "decision": decision,
                "step": str(self.module.STATE.get(self._client_ip(), {}).get("step", 0)),
                "user_agent": self.headers.get("User-Agent"),
            }
        )

    def _proxy(self, base: str, original_uri_header: bool = False):
        if "protected" in base:
            body = "Рабочая область администратора".encode("utf-8")
        else:
            body = "Административная консоль".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_response(self, code: int):
        self.response_code = code

    def send_header(self, key: str, value: str):
        self.response_headers[key] = value

    def end_headers(self):
        return


class GatewayFunctionalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gateway = load_gateway_module()

    def setUp(self):
        self.gateway.STATE.clear()
        self.tempdir = tempfile.TemporaryDirectory()
        self.gateway.LOG_FILE = str(Path(self.tempdir.name) / "gateway.jsonl")
        self.gateway.HONEYPOT_BASE = "http://honeypot:5000"
        self.gateway.PROTECTED_BASE = "http://protected-app:5001"
        self.gateway.KNOCK_TIMEOUT = 1
        self.gateway.ACCESS_WINDOW = 2

    def tearDown(self):
        self.tempdir.cleanup()

    def invoke(self, path: str):
        handler = FakeGatewayHandler(self.gateway, path)
        self.gateway.GatewayHandler.do_GET(handler)
        body = handler.wfile.getvalue().decode("utf-8")
        return handler, body

    def read_events(self):
        with open(self.gateway.LOG_FILE, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    def test_direct_admin_goes_to_honeypot(self):
        handler, body = self.invoke("/admin")
        self.assertEqual(handler.response_code, 200)
        self.assertIn("Административная консоль", body)
        self.assertEqual(self.read_events()[-1]["event"], "protected_denied")

    def test_knock_sequence_unlocks_protected_admin(self):
        for step in ("/start", "/verify", "/grant"):
            handler, body = self.invoke(step)
            self.assertEqual(handler.response_code, 204)
            self.assertEqual(body, "")

        handler, body = self.invoke("/admin")
        self.assertEqual(handler.response_code, 200)
        self.assertIn("Рабочая область администратора", body)
        self.assertEqual(self.read_events()[-1]["event"], "protected_allowed")

    def test_timeout_resets_sequence(self):
        handler, _ = self.invoke("/start")
        self.assertEqual(handler.response_code, 204)
        time.sleep(1.2)
        handler, body = self.invoke("/verify")
        self.assertEqual(handler.response_code, 200)
        self.assertIn("Административная консоль", body)
        self.assertEqual(self.read_events()[-1]["decision"], "honeypot")
