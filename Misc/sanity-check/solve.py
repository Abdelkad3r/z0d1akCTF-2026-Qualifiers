#!/usr/bin/env python3
"""
Sanity Check (z0d1akCTF 2026 Qualifiers) -- solver.

Every HTML response from the marketing site injects a server-side (Cloudflare
Snippet) marker that is NOT rendered but visible in the page source:

    <style id="sanity-check-fragment">:root{--sanity-fragment:"...."}</style>

The value is constant across every path on a given host, but the Snippet keys it
off the *hostname*, so the apex and the www host serve two different fragments:

    z0d1ak.org        -> 26cPm361Zq4WTj89j2HhnestsgA
    www.z0d1ak.org    -> U9aCPzuwzja87fh1RiE83aGLBR7

Those two strings are the two halves of a single Base58 number. Concatenating
apex||www and Base58-decoding yields the flag text.

    base58("26cPm361Zq4WTj89j2HhnestsgA" + "U9aCPzuwzja87fh1RiE83aGLBR7")
      == b"all the best, we hope you enjoy the ctf"

    flag = zdk{all the best, we hope you enjoy the ctf}

Usage:  python3 solve.py
"""

import re
import subprocess

HOSTS = ["https://z0d1ak.org/", "https://www.z0d1ak.org/"]  # order matters: apex first, then www
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
FRAG_RE = re.compile(r'--sanity-fragment:"([^"]*)"')

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58_ALPHABET.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))        # leading '1' -> leading 0x00
    return b"\x00" * pad + body


def fetch_fragment(url: str) -> str:
    # Cloudflare blocks the default urllib UA, so shell out to curl with a browser UA.
    html = subprocess.run(
        ["curl", "-s", "--max-time", "20", "-A", UA, url],
        capture_output=True, text=True, timeout=25,
    ).stdout
    m = FRAG_RE.search(html)
    if not m:
        raise SystemExit(f"no --sanity-fragment found at {url}")
    return m.group(1)


def main():
    fragments = []
    for url in HOSTS:
        frag = fetch_fragment(url)
        print(f"{url:28s} -> {frag}")
        fragments.append(frag)

    combined = "".join(fragments)
    message = b58decode(combined).decode()
    print(f"\nbase58({' + '.join(fragments)})")
    print(f"  = {message!r}")
    print(f"\nFLAG: zdk{{{message}}}")


if __name__ == "__main__":
    main()
