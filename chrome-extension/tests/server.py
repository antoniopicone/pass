"""Tiny local HTTP server for the test fixtures. Serves the static pages in
fixtures/ normally, plus /trusted-types/email and /trusted-types/password
which serve a strict `Content-Security-Policy: require-trusted-types-for
'script'` header (matching sites like accounts.google.com) — regression
coverage for the "content.js never uses innerHTML" requirement."""

import http.server
import os
import socketserver
import threading

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

TT_EMAIL_HTML = b"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>TT Email Step</title></head>
<body>
<h1>Strict Trusted-Types page (email step, like Google/Apple sign-in)</h1>
<form id="f">
  <input type="email" id="identifier" name="identifier" autocomplete="username" placeholder="Email or phone">
  <button type="submit">Next</button>
</form>
</body></html>
"""

TT_PASSWORD_HTML = b"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>TT Password Step</title></head>
<body>
<h1>Strict Trusted-Types page (password step)</h1>
<form id="f">
  <input type="email" id="identifier" name="identifier" autocomplete="username" value="bob@example.com" readonly>
  <input type="password" id="pw" name="pw" autocomplete="current-password" placeholder="Password">
  <button type="submit">Sign in</button>
</form>
</body></html>
"""


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FIXTURES_DIR, **kwargs)

    def do_GET(self):
        if self.path.startswith("/trusted-types/email"):
            return self._send(TT_EMAIL_HTML, trusted_types=True)
        if self.path.startswith("/trusted-types/password"):
            return self._send(TT_PASSWORD_HTML, trusted_types=True)
        return super().do_GET()

    def _send(self, body, trusted_types=False):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if trusted_types:
            self.send_header("Content-Security-Policy", "require-trusted-types-for 'script'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # keep test output quiet


def start(port=8899):
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd
