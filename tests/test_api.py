"""Tests for the TP-Link Deco API client."""

import asyncio
from unittest.mock import patch

import aiohttp
from aiohttp.test_utils import TestServer
import pytest

from custom_components.tplink_deco import api as api_module
from custom_components.tplink_deco.exceptions import ForbiddenException
from custom_components.tplink_deco.exceptions import LoginForbiddenException
from custom_components.tplink_deco.exceptions import LoginTemporarilyForbiddenException
from custom_components.tplink_deco.exceptions import TimeoutException
from tests.fake_deco import FakeDeco
from tests.fake_deco import SYSAUTH

HANG_SECONDS = 5


@pytest.fixture
async def deco():
    """Run a fake Deco and yield it."""
    fake = FakeDeco()
    server = TestServer(fake.app)
    await server.start_server()
    fake.session = aiohttp.ClientSession()
    fake.base_url = f"http://127.0.0.1:{server.port}"
    try:
        yield fake
    finally:
        await fake.session.close()
        await server.close()


async def test_list_devices_sends_session_cookie(deco: FakeDeco) -> None:
    """The session cookie must reach a Deco that is addressed by IP address."""
    api = deco.create_api()

    devices = await api.async_list_devices()

    assert devices == [{"mac": "AA-BB-CC-DD-EE-FF", "role": "master"}]
    assert deco.requests == ["keys", "auth", "login", "device_list"]
    assert f"sysauth={SYSAUTH}" in deco.request_cookies[-1]


async def test_timeout_retries_can_be_disabled_per_call(deco: FakeDeco) -> None:
    """A disabled retry budget must cost a single request.

    The first coordinator refresh runs inside async_setup_entry, which Home Assistant
    does not time out, so every retry there keeps the config entry in
    setup_in_progress for another timeout_seconds.
    """
    deco.hangs["keys"] = HANG_SECONDS
    api = deco.create_api(timeout_error_retries=2)

    with pytest.raises(TimeoutException):
        await api.async_list_devices(timeout_error_retries=0)

    assert deco.requests == ["keys"]


async def test_timeout_retries_are_honored_when_configured(deco: FakeDeco) -> None:
    """The configured retry count is used for regular polling."""
    deco.hangs["keys"] = HANG_SECONDS
    api = deco.create_api(timeout_error_retries=2)

    with pytest.raises(TimeoutException):
        await api.async_list_devices()

    assert deco.requests == ["keys", "keys", "keys"]


async def test_single_login_forbidden_does_not_require_reauth(deco: FakeDeco) -> None:
    """A 403 on login is not a credentials problem, so it must stay retryable."""
    deco.errors["login"] = 403
    api = deco.create_api()

    with pytest.raises(LoginTemporarilyForbiddenException):
        await api.async_list_devices()


async def test_repeated_login_forbidden_requires_reauth(deco: FakeDeco) -> None:
    """Persistent 403s on login do ask the user to reauthenticate."""
    deco.errors["login"] = 403
    api = deco.create_api()

    for _ in range(api_module.MAX_LOGIN_FORBIDDEN_ERRORS - 1):
        with pytest.raises(LoginTemporarilyForbiddenException):
            await api.async_list_devices()

    with pytest.raises(LoginForbiddenException):
        await api.async_list_devices()


async def test_login_forbidden_count_resets_after_success(deco: FakeDeco) -> None:
    """A successful login clears the forbidden counter."""
    api = deco.create_api()
    forbidden_errors_before_reauth = api_module.MAX_LOGIN_FORBIDDEN_ERRORS - 1

    deco.errors["login"] = 403
    for _ in range(forbidden_errors_before_reauth):
        with pytest.raises(LoginTemporarilyForbiddenException):
            await api.async_list_devices()

    del deco.errors["login"]
    await api.async_list_devices()

    # Without the reset these would have asked the user to reauthenticate.
    deco.errors["login"] = 403
    for _ in range(forbidden_errors_before_reauth):
        api.clear_auth()
        with pytest.raises(LoginTemporarilyForbiddenException):
            await api.async_list_devices()


async def test_relogin_after_forbidden_request_is_delayed(deco: FakeDeco) -> None:
    """Re-authenticating must not immediately follow a rejected request."""
    api = deco.create_api()
    await api.async_list_devices()
    assert deco.logins == 1

    deco.errors["device_list"] = 403
    delays = []
    real_sleep = asyncio.sleep

    async def fake_sleep(delay, *args, **kwargs):
        delays.append(delay)
        await real_sleep(0)

    with patch.object(asyncio, "sleep", fake_sleep):
        with pytest.raises(ForbiddenException):
            await api.async_list_devices()

    assert api_module.RELOGIN_RETRY_DELAY_SECONDS in delays
    assert deco.logins == 2
