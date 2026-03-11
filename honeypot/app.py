import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

LOG_FILE = os.environ.get("LOG_FILE", "/var/log/neh/honeypot.jsonl")
PORT = int(os.environ.get("PORT", "5000"))


def write_event(payload: dict) -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=True) + "\n")


class HoneypotHandler(BaseHTTPRequestHandler):
    server_version = "NEHHoneypot/1.0"

    def _render_page(self, path: str) -> bytes:
        title = "Операционная консоль"
        heading = "Административная консоль"
        subtitle = "Ограниченная зона. Требуются аутентификация и подтверждение оператора."
        if path == "/":
            title = "Панель управления"
            heading = "Панель управления инфраструктурой"
            subtitle = "Поступление телеметрии задерживается. Перед продолжением проверьте ожидающие алерты."

        html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <style>
      :root {{
        color-scheme: dark;
        --bg: #07111a;
        --panel: rgba(8, 23, 35, 0.92);
        --panel-strong: rgba(16, 40, 58, 0.96);
        --line: rgba(122, 161, 191, 0.25);
        --text: #d7e5ef;
        --muted: #8ca3b5;
        --accent: #f3b65c;
        --danger: #ff7b72;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        min-height: 100vh;
        font-family: "Segoe UI", Tahoma, sans-serif;
        background:
          radial-gradient(circle at top, rgba(40, 88, 129, 0.32), transparent 40%),
          linear-gradient(160deg, #05090e, var(--bg));
        color: var(--text);
      }}
      main {{
        width: min(980px, calc(100% - 32px));
        margin: 32px auto;
        padding: 28px;
        border: 1px solid var(--line);
        border-radius: 24px;
        background: var(--panel);
        box-shadow: 0 24px 70px rgba(0, 0, 0, 0.35);
      }}
      .eyebrow {{
        display: inline-block;
        margin-bottom: 14px;
        padding: 6px 10px;
        border-radius: 999px;
        background: rgba(243, 182, 92, 0.14);
        color: var(--accent);
        font-size: 12px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
      }}
      h1 {{
        margin: 0 0 8px;
        font-size: clamp(32px, 6vw, 52px);
        line-height: 0.96;
      }}
      p {{
        margin: 0;
        color: var(--muted);
        max-width: 720px;
      }}
      .grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
        margin-top: 26px;
      }}
      .card {{
        padding: 18px;
        border: 1px solid var(--line);
        border-radius: 18px;
        background: var(--panel-strong);
      }}
      .metric {{
        font-size: 30px;
        font-weight: 700;
        color: var(--accent);
      }}
      .danger {{
        color: var(--danger);
      }}
      .table {{
        margin-top: 22px;
        border: 1px solid var(--line);
        border-radius: 18px;
        overflow: hidden;
      }}
      .row {{
        display: grid;
        grid-template-columns: 1.2fr 0.8fr 1fr;
        gap: 12px;
        padding: 14px 18px;
        border-top: 1px solid var(--line);
      }}
      .row:first-child {{ border-top: 0; background: rgba(255, 255, 255, 0.03); }}
      .muted {{ color: var(--muted); }}
    </style>
  </head>
  <body>
    <main>
      <div class="eyebrow">Ограниченный доступ</div>
      <h1>{heading}</h1>
      <p>{subtitle}</p>
      <div class="grid">
        <section class="card">
          <div class="muted">Среда</div>
          <div class="metric">prod-eu-1</div>
        </section>
        <section class="card">
          <div class="muted">Задачи в очереди</div>
          <div class="metric">148</div>
        </section>
        <section class="card">
          <div class="muted">Эскалации</div>
          <div class="metric danger">7 ожидают</div>
        </section>
      </div>
      <div class="table">
        <div class="row">
          <strong>Сервис</strong>
          <strong>Статус</strong>
          <strong>Обновлено</strong>
        </div>
        <div class="row">
          <span>identity-admin</span>
          <span class="danger">деградирован</span>
          <span>{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</span>
        </div>
        <div class="row">
          <span>vault-sync</span>
          <span>требуется проверка</span>
          <span>ручное подтверждение</span>
        </div>
        <div class="row">
          <span>edge-telemetry</span>
          <span>буферизация</span>
          <span>отставание 12 мин</span>
        </div>
      </div>
    </main>
  </body>
</html>
"""
        return html.encode("utf-8")

    def _handle(self) -> None:
        parts = urlsplit(self.path)
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "remote_addr": self.headers.get("X-Real-IP", self.client_address[0]),
            "method": self.command,
            "path": parts.path,
            "query": parts.query,
            "original_uri": self.headers.get("X-Original-URI"),
            "user_agent": self.headers.get("User-Agent"),
            "headers": {
                "host": self.headers.get("Host"),
                "content_type": self.headers.get("Content-Type"),
            },
        }
        write_event(payload)

        body = self._render_page(parts.path)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self._handle()

    def log_message(self, format: str, *args) -> None:
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), HoneypotHandler)
    server.serve_forever()
