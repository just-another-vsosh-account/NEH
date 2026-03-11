import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "5001"))


class ProtectedHandler(BaseHTTPRequestHandler):
    server_version = "NEHProtected/1.0"

    def _render_page(self, path: str) -> bytes:
        if path == "/":
            html = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Защищённый сервис</title>
    <style>
      :root {
        --bg: #f3f7f2;
        --panel: #ffffff;
        --line: #d4ded1;
        --text: #123123;
        --muted: #58725f;
        --accent: #276749;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: Georgia, "Times New Roman", serif;
        background:
          linear-gradient(180deg, rgba(226, 238, 225, 0.85), rgba(243, 247, 242, 0.98)),
          var(--bg);
        color: var(--text);
      }
      main {
        width: min(860px, calc(100% - 32px));
        margin: 40px auto;
        padding: 28px;
        border: 1px solid var(--line);
        border-radius: 24px;
        background: var(--panel);
        box-shadow: 0 18px 48px rgba(34, 64, 46, 0.12);
      }
      h1 { margin: 0 0 10px; font-size: clamp(32px, 6vw, 54px); }
      p { color: var(--muted); line-height: 1.55; }
      .cta {
        display: inline-block;
        margin-top: 18px;
        padding: 12px 18px;
        border-radius: 999px;
        background: var(--accent);
        color: #fff;
        text-decoration: none;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Защищённый операционный сервис</h1>
      <p>Это легитимное внутреннее приложение, скрытое за последовательностью NEH. Авторизованные операторы могут перейти в защищённую административную рабочую область.</p>
      <a class="cta" href="/admin">Открыть защищённую админку</a>
    </main>
  </body>
</html>
"""
        else:
            html = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Рабочая область администратора</title>
    <style>
      :root {
        --bg: #fbf8f0;
        --panel: #fffdf8;
        --line: #ded6c6;
        --text: #2f2619;
        --muted: #6d614e;
        --accent: #8b5e34;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: Georgia, "Times New Roman", serif;
        background: radial-gradient(circle at top, rgba(190, 153, 108, 0.18), transparent 32%), var(--bg);
        color: var(--text);
      }
      main {
        width: min(980px, calc(100% - 32px));
        margin: 32px auto;
        padding: 28px;
        border: 1px solid var(--line);
        border-radius: 24px;
        background: var(--panel);
        box-shadow: 0 22px 64px rgba(81, 58, 31, 0.12);
      }
      h1 { margin: 0 0 8px; font-size: clamp(34px, 6vw, 56px); }
      p { margin: 0; color: var(--muted); }
      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
        margin-top: 24px;
      }
      .card {
        padding: 18px;
        border: 1px solid var(--line);
        border-radius: 18px;
        background: rgba(255, 255, 255, 0.72);
      }
      .value {
        margin-top: 10px;
        font-size: 28px;
        color: var(--accent);
        font-weight: 700;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Рабочая область администратора</h1>
      <p>Доступ предоставлен после knock-последовательности NEH. Эта страница представляет легитимную внутреннюю цель.</p>
      <div class="grid">
        <section class="card">
          <div>Канал релиза</div>
          <div class="value">стабильный</div>
        </section>
        <section class="card">
          <div>Ожидающие подтверждения</div>
          <div class="value">3</div>
        </section>
        <section class="card">
          <div>Окно обслуживания</div>
          <div class="value">23:00 UTC</div>
        </section>
      </div>
    </main>
  </body>
</html>
"""
        return html.encode("utf-8")

    def do_GET(self) -> None:
        if self.path not in {"/", "/admin"}:
            self.send_response(404)
            self.end_headers()
            return

        body = self._render_page(self.path)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), ProtectedHandler)
    server.serve_forever()
