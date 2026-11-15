"""Local fake of a GitHub repository's release URLs, for test/install/run.sh.

Usage: server.py ROOT PORTFILE

ROOT holds releases/download/<tag>/<files> and a latest.txt with the tag that
/releases/latest redirects to (read on every request, so a test can change it).
Binds 127.0.0.1 on a free port and writes the port number to PORTFILE.
"""

import http.server
import os
import sys

ROOT = os.path.abspath(sys.argv[1])
PORTFILE = sys.argv[2]


def latest():
    with open(os.path.join(ROOT, "latest.txt")) as f:
        return f.read().strip()


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/releases/latest":
            self.send_response(302)
            self.send_header("Location", "/releases/tag/" + latest())
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path.startswith("/releases/tag/"):
            body = b"release page\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        prefix = "/releases/latest/download/"
        if path.startswith(prefix):
            self.path = "/releases/download/" + latest() + "/" + path[len(prefix):]
        super().do_GET()

    def log_message(self, fmt, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(PORTFILE, "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
