"""Serveur HTTP volontairement mal configuré, utilisé uniquement par les tests.

Il permet de vérifier la détection sans jamais toucher à un site réel.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX_HTML = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Site de test VulnLens</title>
  <meta name="generator" content="WordPress 6.2.1">
  <script src="http://cdn.insecure.test/app.js"></script>
</head>
<body>
  <!-- TODO: retirer le mot de passe de debug avant la prod -->
  <form action="http://test.local/login" method="post">
    <input type="text" name="user">
    <input type="password" name="password">
    <button type="submit">Connexion</button>
  </form>
  <iframe src="https://video.test/embed"></iframe>
  <a href="/about">À propos</a>
  <a href="/contact">Contact</a>
  <a href="/logout">Déconnexion</a>
  <a href="https://example.org" target="_blank">partenaire</a>
</body>
</html>
"""


class BadSiteHandler(BaseHTTPRequestHandler):
    server_version = "FixtureServer/0.9.1"
    sys_version = ""

    def _send(self, status: int, body: str = "", content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        self.send_header("Set-Cookie", "__Host-insecure=1; Path=/; Domain=test.local")
        self.send_header(
            "Content-Security-Policy", "default-src *; script-src 'unsafe-inline' http: *"
        )
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]

        if path == "/":
            self._send(200, INDEX_HTML)
        elif path == "/about":
            self._send(200, "<html><head><title>À propos</title></head><body><a href='/'>retour</a></body></html>")
        elif path == "/contact":
            self._send(
                200,
                """<html><head><title>Contact</title></head><body>
                <script src="http://cdn.example.test/form.js"></script>
                <form action="http://test.local/send" method="post">
                  <input type="text" name="email">
                  <input type="password" name="secret">
                </form></body></html>""",
            )
        elif path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", "text/plain")
        elif path == "/.env":
            self._send(200, "DB_PASSWORD=hunter2\nSECRET_KEY=abc\n", "text/plain")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n", "text/plain")
        elif path in ("/admin/", "/uploads/"):
            self._send(200, "<html><head><title>Index of /admin/</title></head><body></body></html>")
        else:
            self._send(
                404,
                "<html><body>Traceback (most recent call last):\n  File app.py, line 12</body></html>",
            )

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, PUT")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


class FixtureServer:
    """Serveur de test démarrable en contexte."""

    def __init__(self) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), BadSiteHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def __enter__(self) -> FixtureServer:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":  # pragma: no cover - usage manuel
    with FixtureServer() as server:
        print(f"Serveur de test : {server.url}")
        threading.Event().wait()
