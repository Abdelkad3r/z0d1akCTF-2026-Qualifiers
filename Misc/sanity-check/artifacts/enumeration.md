# Sanity Check — host / fragment enumeration notes

The `--sanity-fragment` value is keyed on the **hostname**. Confirming that only
the apex and `www` carry fragments (and that no path/header/method axis produces
more) is what makes the two-piece Base58 assembly the intended, complete answer.

## What varies the fragment

| Axis tested | Result |
| --- | --- |
| Path (`/`, `/flag.txt`, `/about`, `/rules`, `/register`, `/404.html`, `.txt` files, …) | constant per host |
| Query string (`?fragment=N`, `?f=N`, `?i=N`, `/fragment/N`, …) | no change |
| HTTP method (POST/PUT) | no marker (Snippet only injects on GET HTML) |
| `Accept` / `Accept-Language` / bot User-Agents / `CF-IPCountry` | no change |
| **Hostname** | **changes the fragment** |

## Hostname enumeration

* `z0d1ak.org` → `26cPm361Zq4WTj89j2HhnestsgA`
* `www.z0d1ak.org` → `U9aCPzuwzja87fh1RiE83aGLBR7`
* `ctf`, `geoint`, `sekai-end-probe`, `glasshouse.ctf` → resolve but inject **no** fragment

Enumeration methods, all agreeing that apex + www are the only two fragment hosts:

* **DNS brute** — SecLists `subdomains-top1million-5000.txt` resolved via DNS-over-HTTPS
  (`cloudflare-dns.com/dns-query`): only `www` (and `geoint`, no fragment) resolve.
* **Certificate transparency** (certspotter `api.certspotter.com`):
  `z0d1ak.org`, `www`, `ctf`, `geoint`, `glasshouse.ctf`, `sekai-end-probe`,
  plus wildcards `*.z0d1ak.org`, `*.chals`, `*.geoint`, `*.sekai-end-probe`.
* **Wildcard-cert / SNI probing** — because a `*.z0d1ak.org` cert exists, arbitrary
  hostnames complete a TLS handshake. Forcing SNI with `curl --resolve <host>:443:<cf-ip>`
  shows that any non-configured host returns Cloudflare **error 1016 (HTTP 530)**;
  only `z0d1ak.org` and `www.z0d1ak.org` return HTTP 200 with a fragment.

## Assembly

```
base58("26cPm361Zq4WTj89j2HhnestsgA" + "U9aCPzuwzja87fh1RiE83aGLBR7")
  = b"all the best, we hope you enjoy the ctf"       # complete, clean sentence
base58("U9aCPzuwzja87fh1RiE83aGLBR7" + "26cPm361Zq4WTj89j2HhnestsgA")
  = <garbage>                                         # => apex is the high-order half
```

Base58 is a positional (big-number) encoding, so a clean, grammatical decode of
`apex ‖ www` means those two strings are the whole number — there is no third
fragment to find.

```
FLAG = zdk{all the best, we hope you enjoy the ctf}
```
