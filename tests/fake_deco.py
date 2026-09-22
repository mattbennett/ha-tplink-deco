"""Minimal fake Deco HTTP API for testing the integration's API client."""

import asyncio
import base64
import json
import re
from urllib.parse import parse_qs

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import aiohttp
from aiohttp import web

from custom_components.tplink_deco.api import TplinkDecoApi
from custom_components.tplink_deco.api import aes_decrypt
from custom_components.tplink_deco.api import aes_encrypt

RSA_KEY = RSA.generate(1024)
SEQ = 452678
STOK = "0123456789abcdef0123456789abcdef"
SYSAUTH = "1234567890abcdef1234567890abcdef"

SIGN_PATTERN = re.compile(r"k=(\d+)&i=(\d+)&h=([0-9a-f]+)&s=(\d+)")
ERROR_RESPONSES = {
    401: web.HTTPUnauthorized,
    403: web.HTTPForbidden,
    500: web.HTTPInternalServerError,
}


def rsa_decrypt(ciphertext_hex: str) -> bytes:
    """Reverse api.rsa_encrypt, which hex concatenates PKCS#1 v1.5 blocks."""
    cipher = PKCS1_v1_5.new(RSA_KEY)
    block_size = RSA_KEY.size_in_bytes()
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = b""
    for index in range(0, len(ciphertext), block_size):
        plaintext += cipher.decrypt(ciphertext[index : index + block_size], b"")
    return plaintext


class FakeDeco:
    """Fake Deco that speaks enough of the API to exercise the client.

    Tests can inject the failures that real Decos produce by adding a form name to
    `errors` (HTTP status) or `hangs` (seconds to stall before responding).
    """

    def __init__(self) -> None:
        self.app = web.Application()
        self.app.router.add_post("/cgi-bin/luci/;stok=/login", self._async_login)
        self.app.router.add_post(
            "/cgi-bin/luci/;stok={stok}/admin/{endpoint}", self._async_admin
        )

        # Set by the test fixture once the server is listening.
        self.session: aiohttp.ClientSession = None
        self.base_url: str = None

        self.errors: dict[str, int] = {}
        self.hangs: dict[str, float] = {}
        self.requests: list[str] = []
        self.request_cookies: list[str] = []
        self.logins = 0

    def create_api(
        self, timeout_error_retries: int = 1, timeout_seconds: int = 1
    ) -> TplinkDecoApi:
        return TplinkDecoApi(
            self.session,
            self.base_url,
            "admin",
            "password",
            True,
            timeout_error_retries,
            timeout_seconds,
        )

    def _record(self, request: web.Request) -> str:
        form = request.query.get("form", "")
        self.requests.append(form)
        self.request_cookies.append(request.headers.get("Cookie", ""))
        return form

    async def _async_maybe_fail(self, form: str) -> None:
        hang = self.hangs.get(form)
        if hang is not None:
            await asyncio.sleep(hang)
        status = self.errors.get(form)
        if status is not None:
            raise ERROR_RESPONSES[status]

    async def _async_login(self, request: web.Request) -> web.Response:
        form = self._record(request)
        await self._async_maybe_fail(form)

        key = [f"{RSA_KEY.n:x}", f"{RSA_KEY.e:x}"]
        if form == "keys":
            return web.json_response({"error_code": 0, "result": {"password": key}})
        if form == "auth":
            return web.json_response(
                {"error_code": 0, "result": {"key": key, "seq": SEQ}}
            )
        if form != "login":
            raise web.HTTPNotFound

        self.logins += 1
        aes_key, aes_iv = await self._async_read_aes_key(request)
        response = self._json_response(
            aes_key, aes_iv, {"error_code": 0, "result": {"stok": STOK}}
        )
        response.headers["Set-Cookie"] = f"sysauth={SYSAUTH}; path=/"
        return response

    async def _async_admin(self, request: web.Request) -> web.Response:
        form = self._record(request)
        await self._async_maybe_fail(form)

        if request.match_info["stok"] != STOK:
            raise web.HTTPForbidden
        if f"sysauth={SYSAUTH}" not in request.headers.get("Cookie", ""):
            raise web.HTTPForbidden

        aes_key, aes_iv = await self._async_read_aes_key(request)
        if form == "device_list":
            result = {"device_list": [{"mac": "AA-BB-CC-DD-EE-FF", "role": "master"}]}
        elif form == "client_list":
            result = {"client_list": []}
        elif form == "performance":
            result = {"cpu_usage": 0.5, "mem_usage": 0.25}
        else:
            raise web.HTTPNotFound
        return self._json_response(aes_key, aes_iv, {"error_code": 0, "result": result})

    async def _async_read_aes_key(self, request: web.Request) -> tuple[bytes, bytes]:
        payload = parse_qs(await request.text())
        sign = rsa_decrypt(payload["sign"][0]).decode()
        match = SIGN_PATTERN.fullmatch(sign)
        assert match is not None, f"Unexpected sign {sign}"
        aes_key = match.group(1).encode()
        aes_iv = match.group(2).encode()

        # Confirm the request body decrypts with the key from the sign.
        data = base64.b64decode(payload["data"][0])
        decrypted = aes_decrypt(aes_key, aes_iv, data)
        json.loads(decrypted[: -int(decrypted[-1])].decode())

        return aes_key, aes_iv

    def _json_response(self, aes_key: bytes, aes_iv: bytes, data: dict) -> web.Response:
        encrypted = aes_encrypt(aes_key, aes_iv, json.dumps(data).encode())
        return web.json_response({"data": base64.b64encode(encrypted).decode()})
