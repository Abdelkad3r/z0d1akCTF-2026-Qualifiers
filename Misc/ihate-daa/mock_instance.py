#!/usr/bin/env python3
"""
Local reimplementation of the ihateDAA service, for verifying solve.py after
the real instance is gone.

It reproduces the properties that matter to the solver:

  * `/?path=<token>` addresses a node; the landing page lists the roots
  * out-degrees drawn from {0, 2, 3, 4, 5}; base36 tokens of length 8-15
  * the graph is CYCLIC, including edges back into the root set
  * exactly one node renders "Flag Found"; sinks render "Dead End"
  * unknown tokens return the 404 "Missing Path" page

Usage:
    python3 mock_instance.py --port 8000 --nodes 5000 --seed 1
    python3 solve.py http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import random
import string
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ALPHABET = string.digits + string.ascii_lowercase
FLAG = "zdk{i_l0Ve_GRaPH_7RAvER5AL_4nd_dyN4mIc_inSTanc35}"

SHELL = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ font-family: monospace; max-width: 860px; margin: 40px auto; padding: 0 16px; }}
    a {{ color: #ff5a5a; }}
    .card {{ border: 1px solid #444; border-radius: 10px; padding: 16px; }}
    .muted {{ opacity: 0.8; }}
  </style>
</head>
<body>
  <div class="card">
    {body}
  </div>
</body>
</html>"""


def build_graph(n_nodes: int, seed: int):
    rng = random.Random(seed)
    tokens = set()
    while len(tokens) < n_nodes:
        length = rng.randint(8, 15)
        tokens.add("".join(rng.choice(ALPHABET) for _ in range(length)))
    tokens = sorted(tokens)

    roots = tokens[:6]
    graph: dict[str, list[str]] = {}
    for tok in tokens:
        deg = rng.choice([0, 2, 3, 4, 5])
        # Edges point anywhere, including backwards and into the roots, so the
        # graph is genuinely cyclic -- this is what breaks a naive DFS.
        graph[tok] = rng.sample(tokens, deg) if deg else []

    # Guarantee the flag node is reachable and has in-degree 1, as observed.
    flag_token = tokens[-1]
    graph[flag_token] = []
    for tok in tokens:
        if flag_token in graph[tok]:
            graph[tok] = [t for t in graph[tok] if t != flag_token]
    parent = rng.choice([t for t in tokens if graph[t] and t != flag_token])
    graph[parent][rng.randrange(len(graph[parent]))] = flag_token
    return roots, graph, flag_token


class Handler(BaseHTTPRequestHandler):
    roots: list[str] = []
    graph: dict[str, list[str]] = {}
    flag_token = ""

    def log_message(self, *a):  # keep the test output quiet
        pass

    def _send(self, status: int, title: str, body: str) -> None:
        payload = SHELL.format(title=title, body=body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    @staticmethod
    def _links(tokens):
        items = "\n".join(f'<li><a href="/?path={t}">{t}</a></li>' for t in tokens)
        return f"<h1>Which way did the flag go?</h1>\n   <p>Choose a path:</p>\n   <ul>{items}</ul>"

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        if parts.path != "/":
            self._send(404, "Error", "<h1>Cannot GET</h1>")
            return
        token = parse_qs(parts.query).get("path", [None])[0]
        if token is None:
            self._send(200, "Which way did the flag go?", self._links(self.roots))
        elif token == self.flag_token:
            self._send(200, "Flag Found", f"<h1>flag:</h1><p><strong>{FLAG}</strong></p>")
        elif token not in self.graph:
            self._send(404, "Missing Path",
                       '<h1>Unknown path</h1><p class="muted">This token is not part of the graph.</p>')
        elif not self.graph[token]:
            self._send(200, "Dead End",
                       '<h1>Which way did the flag go?</h1><p>nope :(</p>'
                       '<p class="muted">Try a different route.</p>')
        else:
            self._send(200, "Which way did the flag go?", self._links(self.graph[token]))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--nodes", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    roots, graph, flag_token = build_graph(args.nodes, args.seed)
    Handler.roots, Handler.graph, Handler.flag_token = roots, graph, flag_token
    edges = sum(len(v) for v in graph.values())
    print(f"[mock] {len(graph)} nodes, {edges} edges, flag at {flag_token}")
    print(f"[mock] listening on http://127.0.0.1:{args.port}")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
