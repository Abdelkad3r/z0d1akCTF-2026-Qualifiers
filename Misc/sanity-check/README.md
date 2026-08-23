# Sanity Check

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Miscellaneous |
| Author | ludicrouslytrue |
| Points | 199 |
| Solves at time of solving | 31 |
| Flag | `zdk{all the best, we hope you enjoy the ctf}` |

> z0d1ak.org

## Executive Summary

The whole challenge is the event's own marketing site, `https://z0d1ak.org/`.
Every HTML response carries a **server-side-injected marker** that never renders
but is plainly visible in the page source:

```html
<style id="sanity-check-fragment">:root{--sanity-fragment:"26cPm361Zq4WTj89j2HhnestsgA"}</style>
```

The `id` says *fragment* — and the value is keyed on the **hostname**. The apex
and the `www` host each serve a different piece. The two pieces are the two halves
of one **Base58** number; concatenate them (apex first) and decode:

```python
base58("26cPm361Zq4WTj89j2HhnestsgA" + "U9aCPzuwzja87fh1RiE83aGLBR7")
  == b"all the best, we hope you enjoy the ctf"
```

```
zdk{all the best, we hope you enjoy the ctf}
```

## Step 1 — Read the page source

`z0d1ak.org` is a Vite/React single-page app. It serves the same `index.html`
for essentially every path (client-side routing), so `robots.txt`, `sitemap.xml`,
`/flag`, etc. all just return the SPA shell — nothing obvious there. The JS bundle
is 195 KB of minified React (the "flag"/"hidden" hits inside it are React fiber
internals, not the CTF flag), and the OpenGraph image and favicon are clean.

The tell is in the raw HTML `<head>`. A path that returns a slightly different
byte length — `curl -s https://z0d1ak.org/flag.txt | wc -c` gives 2170 vs 2465
for the SPA shell — makes it easy to spot the odd element:

```html
<style id="sanity-check-fragment">:root{--sanity-fragment:"26cPm361Zq4WTj89j2HhnestsgA"}</style>
```

This is injected by a Cloudflare Snippet/Worker in front of the origin (there is
no such tag in the deployed React build), which is why it appears on *every* HTML
response regardless of path.

## Step 2 — Notice it's a *fragment*, and find the second one

The element id is `sanity-check-fragment` (singular), and the CSS custom property
is `--sanity-fragment`. "Fragment" implies more than one. Probing shows the value
is **constant across every path** on a host — but different **per hostname**:

```
z0d1ak.org      -> 26cPm361Zq4WTj89j2HhnestsgA
www.z0d1ak.org  -> U9aCPzuwzja87fh1RiE83aGLBR7
```

I confirmed these are the only two fragment-bearing hosts three independent ways
(details in [`artifacts/enumeration.md`](artifacts/enumeration.md)):

* **DNS brute** of SecLists' top-5000 subdomains via DNS-over-HTTPS — only `www`
  (and `geoint`, which serves no fragment) resolve.
* **Certificate transparency** (certspotter) — the only zone hosts are
  `z0d1ak.org`, `www`, `ctf`, `geoint`, `glasshouse.ctf`, `sekai-end-probe`;
  the CTF-infra hosts inject nothing.
* **Wildcard-cert / SNI probing** — a `*.z0d1ak.org` cert exists, so any hostname
  completes a TLS handshake; forcing SNI with `curl --resolve` shows every
  non-configured host returns Cloudflare **error 1016 (530)**. Only the apex and
  `www` answer with `200` + a fragment.

No path, query-string, header, cookie, or method changes the value — the axis is
purely the hostname, and there are exactly two.

## Step 3 — Recognise Base58 and assemble

Each fragment is 27 characters from the Base58 alphabet (no `0 O I l`, mixed
case + digits). Decoding either fragment *alone* gives garbage; decoding the
**concatenation** is the trick, because Base58 is a positional (big-number)
encoding — the whole message is one number, split across two strings.

```python
ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + ALPHA.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

apex = "26cPm361Zq4WTj89j2HhnestsgA"
www  = "U9aCPzuwzja87fh1RiE83aGLBR7"
b58decode(apex + www)   # b'all the best, we hope you enjoy the ctf'
b58decode(www + apex)   # garbage  -> apex is the high-order half (comes first)
```

The decode is a complete, grammatical sentence — and because Base58 is
positional, a clean decode of `apex ‖ www` means those two strings *are* the
entire number: there is no third fragment to chase.

## Flag

```
zdk{all the best, we hope you enjoy the ctf}
```

The flag is the decoded message verbatim — spaces and comma included, wrapped in
the `zdk{...}` format.

## Reproduce

```bash
python3 solve.py
```

`solve.py` fetches both hosts, extracts each `--sanity-fragment`, concatenates
apex‖www, Base58-decodes, and prints the flag. (Cloudflare blocks the default
`urllib` User-Agent, so the solver shells out to `curl` with a browser UA.)

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | Fetches both fragments and Base58-decodes them into the flag |
| [`artifacts/evidence.txt`](artifacts/evidence.txt) | Captured markers, per-path constancy, and the Base58 assembly |
| [`artifacts/enumeration.md`](artifacts/enumeration.md) | How apex + www were confirmed to be the only two fragment hosts (DNS brute, CT logs, wildcard-SNI probing) |

## Why 199 points / 31 solves

Nothing here is a single well-known path — it's a chain of small realisations:
the flag lives in an injected, non-rendered CSS variable (view-source only), the
value is *host*-keyed rather than path-keyed (so you have to notice `www` differs
from the apex and confirm nothing else does), and the two pieces only mean
anything when concatenated and read as one Base58 number. Miss any link and the
"sanity check" quietly stays unsolved.
