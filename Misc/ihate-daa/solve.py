#!/usr/bin/env python3
"""
z0d1akCTF 2026 Qualifiers -- Miscellaneous -- ihateDAA

The challenge exposes a directed graph over HTTP. Every node is addressed by
`/?path=<token>` and renders its out-edges as further `?path=` links. Three
page kinds exist, distinguished by <title>:

    "Which way did the flag go?"  interior node, 2-5 out-edges
    "Dead End"                    sink, renders "nope :("
    "Flag Found"                  the single goal node
    "Missing Path"                token not in the graph (HTTP 404)

The graph is cyclic, so a depth-first walk without a visited set never
terminates. This solver runs a breadth-first search with a global visited set
over a pool of keep-alive connections, then reconstructs the shortest root-to-
flag path from the BFS tree.

Standard library only.

Usage:
    python3 solve.py https://ihate-daa-<id>.chals.z0d1ak.org
    python3 solve.py https://ihate-daa-<id>.chals.z0d1ak.org -t 32 -o graph.json
"""

from __future__ import annotations

import argparse
import collections
import http.client
import json
import re
import ssl
import sys
import threading
import time
from queue import Empty, Queue
from urllib.parse import urlsplit

LINK_RE = re.compile(r'href="/\?path=([^"]+)"')
TITLE_RE = re.compile(r"<title>([^<]*)</title>")
FLAG_RE = re.compile(r"zdk\{[^}]*\}")

INTERIOR_TITLE = "Which way did the flag go?"


class Fetcher:
    """One keep-alive HTTP(S) connection per worker thread, with retries."""

    def __init__(self, base_url: str, timeout: float = 25.0):
        parts = urlsplit(base_url)
        self.https = parts.scheme != "http"
        self.host = parts.netloc
        self.timeout = timeout
        self.ctx = ssl.create_default_context() if self.https else None
        self._local = threading.local()

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if self.https:
                conn = http.client.HTTPSConnection(
                    self.host, context=self.ctx, timeout=self.timeout
                )
            else:
                conn = http.client.HTTPConnection(self.host, timeout=self.timeout)
            self._local.conn = conn
        return conn

    def _drop(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        self._local.conn = None

    def get(self, token: str, attempts: int = 5) -> tuple[int | None, str]:
        target = f"/?path={token}" if token else "/"
        for attempt in range(attempts):
            try:
                conn = self._conn()
                conn.request("GET", target, headers={"Connection": "keep-alive"})
                resp = conn.getresponse()
                return resp.status, resp.read().decode("utf-8", "replace")
            except Exception:
                self._drop()
                time.sleep(0.2 * (attempt + 1))
        return None, ""


class Crawler:
    def __init__(self, fetcher: Fetcher, threads: int = 32):
        self.fetcher = fetcher
        self.threads = threads
        self.graph: dict[str, list[str]] = {}
        self.seen: set[str] = set()
        self.queue: Queue = Queue()
        self.lock = threading.Lock()
        self.flag: str | None = None
        self.flag_token: str | None = None
        self.flag_body: str | None = None
        self.stop_on_flag = True
        self.stop = threading.Event()

    def _worker(self) -> None:
        while not self.stop.is_set():
            try:
                token = self.queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                status, body = self.fetcher.get(token)
                out = LINK_RE.findall(body)
                title_match = TITLE_RE.search(body)
                title = title_match.group(1) if title_match else ""

                if title not in (INTERIOR_TITLE, "Dead End"):
                    flag_match = FLAG_RE.search(body)
                    if flag_match:
                        with self.lock:
                            if self.flag is None:
                                self.flag = flag_match.group(0)
                                self.flag_token = token
                                self.flag_body = body

                with self.lock:
                    self.graph[token] = out
                    fresh = [t for t in out if t not in self.seen]
                    self.seen.update(fresh)
                for t in fresh:
                    self.queue.put(t)
            finally:
                self.queue.task_done()

    def run(self, progress_every: float = 10.0) -> None:
        status, body = self.fetcher.get("")
        roots = LINK_RE.findall(body)
        if not roots:
            raise SystemExit(f"no roots found on landing page (HTTP {status})")
        self.roots = roots
        print(f"[*] roots: {roots}")

        with self.lock:
            self.seen.update(roots)
        for r in roots:
            self.queue.put(r)

        workers = [
            threading.Thread(target=self._worker, daemon=True)
            for _ in range(self.threads)
        ]
        for w in workers:
            w.start()

        started = time.time()
        last = 0.0
        while True:
            time.sleep(0.5)
            with self.lock:
                done, pending, flag = len(self.graph), self.queue.qsize(), self.flag
            now = time.time() - started
            if now - last >= progress_every:
                last = now
                print(f"[*] {now:7.1f}s  nodes={done:6d}  queue={pending:6d}")
            exhausted = pending == 0 and done > 0 and self.queue.unfinished_tasks == 0
            if exhausted or (flag is not None and self.stop_on_flag):
                break
        self.stop.set()
        print(f"[*] finished in {time.time() - started:.1f}s, {len(self.graph)} nodes")

    def shortest_path(self, target: str) -> list[str]:
        prev: dict[str, str | None] = {}
        dq = collections.deque()
        for r in self.roots:
            prev[r] = None
            dq.append(r)
        while dq:
            node = dq.popleft()
            if node == target:
                break
            for nxt in self.graph.get(node, []):
                if nxt not in prev:
                    prev[nxt] = node
                    dq.append(nxt)
        if target not in prev:
            return []
        path, node = [], target
        while node is not None:
            path.append(node)
            node = prev[node]
        return path[::-1]


def main() -> int:
    ap = argparse.ArgumentParser(description="ihateDAA solver (BFS over the HTTP graph)")
    ap.add_argument("url", help="instance base URL, e.g. https://ihate-daa-<id>.chals.z0d1ak.org")
    ap.add_argument("-t", "--threads", type=int, default=32, help="worker threads (default 32)")
    ap.add_argument("-o", "--out", help="write the captured adjacency list to this JSON file")
    ap.add_argument("--full", action="store_true",
                    help="keep crawling after the flag is found (maps the whole graph)")
    args = ap.parse_args()

    crawler = Crawler(Fetcher(args.url), threads=args.threads)
    crawler.stop_on_flag = not args.full
    crawler.run()

    if crawler.flag is None:
        print("[-] no flag node reached")
        return 1

    print(f"\n[+] flag node : {crawler.flag_token}")
    path = crawler.shortest_path(crawler.flag_token)
    if path:
        print(f"[+] depth     : {len(path) - 1} hops from a root")
        print("[+] path      : " + " -> ".join(path))
    print(f"\n[+] {crawler.flag}")

    if args.out:
        with open(args.out, "w") as fh:
            json.dump({"roots": crawler.roots, "graph": crawler.graph}, fh)
        print(f"[*] graph written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
