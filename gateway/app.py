import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/neh/nginx-events.jsonl")
PROTECTED_BASE = os.environ.get("PROTECTED_BASE", "http://protected-app:5001")
HONEYPOT_BASE = os.environ.get("HONEYPOT_BASE", "http://honeypot:5000")
KNOCK_TIMEOUT = int(os.environ.get("KNOCK_TIMEOUT", "30"))
ACCESS_WINDOW = int(os.environ.get("ACCESS_WINDOW", "60"))
SEQUENCE = ["/start", "/verify", "/grant"]
PROTECTED_URI = "/admin"

STATE = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_log(payload: dict) -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=True) + "\n")


def get_client_state(ip: str) -> dict:
    state = STATE.setdefault(ip, {"step": 0, "last_seen": 0, "grant_until": 0, "failures": 0})
    if state["last_seen"] and time.time() - state["last_seen"] > KNOCK_TIMEOUT:
        state["step"] = 0
    state["last_seen"] = time.time()
    return state


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "NEHGateway/1.0"

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _event(self, event: str, decision: str, status: int) -> None:
        write_log(
            {
                "ts": now_iso(),
                "remote_addr": self._client_ip(),
                "method": self.command,
                "uri": self.path.split("?", 1)[0],
                "status": status,
                "event": event,
                "decision": decision,
                "step": str(STATE.get(self._client_ip(), {}).get("step", 0)),
                "user_agent": self.headers.get("User-Agent"),
            }
        )

    def _proxy(self, base: str, original_uri_header: bool = False) -> None:
        target = f"{base}{self.path}"
        req = urllib.request.Request(target, method=self.command)
        req.add_header("Host", self.headers.get("Host", "localhost"))
        req.add_header("X-Real-IP", self._client_ip())
        if original_uri_header:
            req.add_header("X-Original-URI", self.path)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read()
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() in {"transfer-encoding", "connection", "server", "date"}:
                        continue
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as exc:
            body = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_GET(self) -> None:
        ip = self._client_ip()
        path = self.path.split("?", 1)[0]
        state = get_client_state(ip)

        if path in SEQUENCE:
            matched = SEQUENCE.index(path)
            if matched == state["step"]:
                state["step"] += 1
                if state["step"] == len(SEQUENCE):
                    state["grant_until"] = time.time() + ACCESS_WINDOW
                    state["step"] = 0
                    self._event("knock_success", "grant_window", 204)
                else:
                    self._event("knock_progress", "await_next", 204)
                self.send_response(204)
                self.end_headers()
                return

            state["failures"] += 1
            if matched == 0:
                state["step"] = 1
                self._event("knock_restart", "restart_sequence", 204)
                self.send_response(204)
                self.end_headers()
                return

            state["step"] = 0
            self._event("redirect_honeypot", "honeypot", 200)
            self._proxy(HONEYPOT_BASE, original_uri_header=True)
            return

        if path == PROTECTED_URI:
            if state["grant_until"] >= time.time():
                self._event("protected_allowed", "pass", 200)
                self._proxy(PROTECTED_BASE)
                return

            state["failures"] += 1
            self._event("protected_denied", "honeypot", 200)
            self._proxy(HONEYPOT_BASE, original_uri_header=True)
            return

        if path == "/":
            body = b"\xd0\x94\xd0\xb5\xd0\xbc\xd0\xbe-\xd1\x88\xd0\xbb\xd1\x8e\xd0\xb7 NEH\n"
            self._event("none", "pass", 200)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self._event("redirect_honeypot", "honeypot", 200)
        self._proxy(HONEYPOT_BASE, original_uri_header=True)

    def log_message(self, format: str, *args) -> None:
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), GatewayHandler)
    server.serve_forever()
